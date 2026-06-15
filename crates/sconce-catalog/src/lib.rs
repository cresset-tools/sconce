//! Postgres-backed catalog: packages, their versions, and the blob index.
//!
//! Design choices, deliberately:
//! - **Postgres only.** No database abstraction; we use Postgres features freely.
//! - **Runtime queries only.** No `sqlx::query!` / `migrate!` macros and no
//!   `macros` feature — nothing here needs a database at *compile* time. Rows
//!   are mapped by hand. SQL migrations are plain files applied at runtime.
//!
//! The catalog maps content (a [`sconce_cas`]-style sha256 blob) to meaning:
//! "package X version Y has this `composer.json` and this dist blob". It's the
//! layer the mirror worker writes and the Composer serving reads.
//!
//! [`sconce_cas`]: https://docs.rs/sconce-cas

#![forbid(unsafe_code)]

pub mod secret;

use serde_json::Value;
use sqlx::{PgPool, Row};
use uuid::Uuid;

/// The error type returned by catalog operations (re-exported so consumers can
/// handle it without depending on `sqlx` directly).
pub use sqlx::Error as SqlxError;

/// Migrations, embedded as plain SQL and applied in order at runtime. Adding a
/// migration = append a `(name, include_str!(...))` entry; names are recorded in
/// `_sconce_migrations` so each runs once.
const MIGRATIONS: &[(&str, &str)] = &[
    ("0001_init", include_str!("../migrations/0001_init.sql")),
    (
        "0002_dist_shasum",
        include_str!("../migrations/0002_dist_shasum.sql"),
    ),
    ("0003_tokens", include_str!("../migrations/0003_tokens.sql")),
    (
        "0004_update_policy",
        include_str!("../migrations/0004_update_policy.sql"),
    ),
    (
        "0005_multitenancy",
        include_str!("../migrations/0005_multitenancy.sql"),
    ),
    ("0006_grants", include_str!("../migrations/0006_grants.sql")),
    (
        "0007_licenses",
        include_str!("../migrations/0007_licenses.sql"),
    ),
    (
        "0008_accounts",
        include_str!("../migrations/0008_accounts.sql"),
    ),
    (
        "0009_token_expiry",
        include_str!("../migrations/0009_token_expiry.sql"),
    ),
    (
        "0010_org_settings",
        include_str!("../migrations/0010_org_settings.sql"),
    ),
    (
        "0011_token_origin",
        include_str!("../migrations/0011_token_origin.sql"),
    ),
    (
        "0012_repo_token_policy",
        include_str!("../migrations/0012_repo_token_policy.sql"),
    ),
    (
        "0013_repo_disallow_private",
        include_str!("../migrations/0013_repo_disallow_private.sql"),
    ),
    (
        "0014_upstreams",
        include_str!("../migrations/0014_upstreams.sql"),
    ),
    (
        "0015_mirror_jobs",
        include_str!("../migrations/0015_mirror_jobs.sql"),
    ),
    (
        "0016_upstream_credential_type",
        include_str!("../migrations/0016_upstream_credential_type.sql"),
    ),
    (
        "0017_upstream_package_filter",
        include_str!("../migrations/0017_upstream_package_filter.sql"),
    ),
    (
        "0018_generalize_jobs",
        include_str!("../migrations/0018_generalize_jobs.sql"),
    ),
    (
        "0019_dependency_plan",
        include_str!("../migrations/0019_dependency_plan.sql"),
    ),
    ("0020_oidc", include_str!("../migrations/0020_oidc.sql")),
    (
        "0021_oidc_per_org",
        include_str!("../migrations/0021_oidc_per_org.sql"),
    ),
    (
        "0022_org_roles",
        include_str!("../migrations/0022_org_roles.sql"),
    ),
    ("0023_scim", include_str!("../migrations/0023_scim.sql")),
    ("0024_ci_oidc", include_str!("../migrations/0024_ci_oidc.sql")),
    (
        "0025_package_lifecycle",
        include_str!("../migrations/0025_package_lifecycle.sql"),
    ),
    (
        "0026_credential_policy",
        include_str!("../migrations/0026_credential_policy.sql"),
    ),
];

/// Arbitrary fixed key for the migration advisory lock (so all sconce instances
/// agree on the same lock).
const MIGRATE_LOCK: i64 = 6_927_654_321;

/// The catalog handle: a Postgres connection pool plus the query methods.
#[derive(Debug, Clone)]
pub struct Catalog {
    pool: PgPool,
}

/// An organization (tenant) in the admin listing.
#[derive(Debug, Clone)]
pub struct OrgSummary {
    pub id: Uuid,
    pub slug: String,
    pub name: Option<String>,
}

/// Org-wide policy. Defaults are permissive (a fresh org behaves as before).
#[derive(Debug, Clone, Copy)]
pub struct OrgSettings {
    /// When false, manually-created raw repo tokens are refused org-wide.
    pub allow_raw_tokens: bool,
    /// When `Some(n)`, a created token must expire within `n` days (and may not
    /// be non-expiring). `None` = no cap.
    pub max_token_ttl_days: Option<i64>,
}

impl Default for OrgSettings {
    fn default() -> Self {
        Self {
            allow_raw_tokens: true,
            max_token_ttl_days: None,
        }
    }
}

/// A package's visibility, derived from the upstream it was mirrored from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    /// Operator-controlled / paid source — only this catalog can serve it.
    Private,
    /// Mirrored from a public registry (Packagist, …).
    Public,
}

impl Visibility {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Visibility::Private => "private",
            Visibility::Public => "public",
        }
    }

    /// Parse `"public"`/`"private"`; anything else is `None`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "public" => Some(Visibility::Public),
            "private" => Some(Visibility::Private),
            _ => None,
        }
    }
}

/// An upstream in the admin listing — no secret material, just whether one
/// exists (`has_credential`).
#[derive(Debug, Clone)]
pub struct UpstreamSummary {
    pub id: Uuid,
    pub kind: String,
    pub base: String,
    pub visibility: String,
    pub label: Option<String>,
    pub has_credential: bool,
    /// Composer-only: regex scoping which packages a sync mirrors (`None` = all).
    pub package_filter: Option<String>,
    /// Status of the most recent mirror job, if any (`pending`/`running`/
    /// `ready`/`failed`).
    pub job_status: Option<String>,
    /// Error from the most recent job, if it failed.
    pub job_error: Option<String>,
}

/// A package with its lifecycle state, for the operator view. `sync_health` is
/// `ok`/`broken`; `archived_at` non-null means the operator froze it (which masks
/// a broken flag). `broken`/`stale` are *not* serving states — every mirrored
/// version keeps serving from the CAS regardless.
#[derive(Debug, Clone)]
pub struct PackageStatus {
    pub name: String,
    pub visibility: String,
    pub sync_health: String,
    pub broken_reason: Option<String>,
    pub broken_at: Option<String>,
    pub last_success_at: Option<String>,
    pub archived: bool,
}

/// A claimed job handed to the worker. `kind` selects which fields are set:
/// `mirror_upstream`→`upstream_id`; `mirror_package`→`upstream_id`+`package`;
/// `resolve_closure`→`repo_id`.
#[derive(Debug, Clone)]
pub struct MirrorJob {
    pub id: Uuid,
    pub kind: String,
    pub upstream_id: Option<Uuid>,
    pub package: Option<String>,
    pub repo_id: Option<Uuid>,
    /// Attempt number (already incremented by the claim).
    pub attempts: i32,
}

/// A CI OIDC exchange policy: a workflow whose JWT validates against
/// `issuer`/`audience` and matches `claims` gets a token for `repo_id`.
#[derive(Debug, Clone)]
pub struct CiPolicy {
    pub id: Uuid,
    pub repo_id: Uuid,
    pub provider: String,
    pub issuer: String,
    pub audience: String,
    /// Claim matchers (every key must equal the JWT's claim).
    pub claims: Value,
    pub token_ttl_secs: i64,
}

/// An OIDC connection (identity-provider config). `client_secret` is encrypted.
#[derive(Debug, Clone)]
pub struct OidcConnection {
    /// Set on rows returned from the catalog; ignored when creating one.
    pub id: Uuid,
    /// `None` = the instance-default connection; `Some` = scoped to that org
    /// (users authenticating via it get membership in that org).
    pub org_slug: Option<String>,
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: Option<Vec<u8>>,
    pub redirect_url: String,
    pub scopes: String,
    pub allowed_domains: Option<Vec<String>>,
    pub admin_domains: Option<Vec<String>>,
}

/// A row of a repo's computed dependency closure (a proposal to review).
#[derive(Debug, Clone)]
pub struct DependencyPlanEntry {
    pub name: String,
    /// `present` | `resolvable-private` | `resolvable-public` | `missing`.
    pub status: String,
    pub resolver_upstream_id: Option<Uuid>,
    pub required_by: Option<String>,
}

/// An upstream loaded for mirroring — includes the encrypted credential blob.
#[derive(Debug, Clone)]
pub struct UpstreamRow {
    pub id: Uuid,
    pub repo_id: Uuid,
    pub kind: String,
    pub base: String,
    pub visibility: Visibility,
    /// Encrypted (`nonce||ciphertext`) credential, decrypt via [`secret::SecretKey`].
    pub credential: Option<Vec<u8>>,
    /// How to present the credential when cloning: `basic`|`github`|`gitlab`|`bearer`.
    pub credential_type: String,
    /// Composer-only: regex scoping which packages a sync mirrors (`None` = all).
    pub package_filter: Option<String>,
}

/// Repo-level settings. Token fields are tighten-only *overrides* (`None` =
/// inherit the org); `allow_private_packages` is a plain repo policy.
#[derive(Debug, Clone, Copy)]
pub struct RepoSettings {
    /// `Some(false)` forces raw tokens off for this repo even if the org allows
    /// them. `Some(true)` cannot re-enable them when the org forbids them.
    pub allow_raw_tokens: Option<bool>,
    /// `Some(n)` caps token expiry for this repo; combined with the org cap, the
    /// smaller wins. `None` = inherit the org cap.
    pub max_token_ttl_days: Option<i64>,
    /// When false, the repo is public-only: private packages can't be added and
    /// any already present aren't served.
    pub allow_private_packages: bool,
}

impl Default for RepoSettings {
    fn default() -> Self {
        Self {
            allow_raw_tokens: None,
            max_token_ttl_days: None,
            allow_private_packages: true,
        }
    }
}

/// Why upserting a package failed — a database error, or a repo policy that
/// forbids it (a private package in a public-only repo).
#[derive(Debug, thiserror::Error)]
pub enum UpsertPackageError {
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    #[error("{0}")]
    Policy(String),
}

/// Why creating a token failed — a database error, or an org policy that forbids
/// it (so callers can show the user a clear reason instead of a 500).
#[derive(Debug, thiserror::Error)]
pub enum CreateTokenError {
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    /// The org's policy rejects this token (raw tokens disabled, or expiry
    /// missing/too long). The string is a user-facing explanation.
    #[error("{0}")]
    Policy(String),
}

/// A repository in the admin listing.
#[derive(Debug, Clone)]
pub struct RepoSummary {
    pub org: String,
    pub org_id: Uuid,
    pub repo: String,
    pub id: Uuid,
    pub update_mode: String,
    pub cooldown_days: i32,
}

/// An authenticated admin user (from a session or login).
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub id: Uuid,
    pub is_superadmin: bool,
    /// Org (tenant) ids this user is a member of (empty for a superadmin, who
    /// sees all).
    pub tenant_org_ids: Vec<Uuid>,
    /// The subset of `tenant_org_ids` where the user has the `admin` role.
    pub admin_org_ids: Vec<Uuid>,
}

/// A user in the superadmin listing.
#[derive(Debug, Clone)]
pub struct UserSummary {
    pub email: String,
    pub is_superadmin: bool,
    pub tenants: Vec<String>,
}

/// A version row for the admin UI, with its control state.
#[derive(Debug, Clone)]
pub struct AdminVersion {
    pub package: String,
    pub version: String,
    pub normalized_version: String,
    pub stability: String,
    pub held: bool,
    pub approved: bool,
    pub yanked: bool,
    /// Release time as text (`null` if unknown).
    pub released_at: Option<String>,
    /// Whole days until this version clears the repo's cooldown (`0` once past,
    /// `None` when it has no release date). Lets the operator view show a
    /// countdown that matches what serving hides.
    pub cooldown_days_left: Option<i64>,
}

/// A credential's optional supply-chain policy override (`None` = inherit the
/// repo). It can only **tighten** the repo default at serve time.
#[derive(Debug, Clone, Default)]
pub struct PolicyOverride {
    pub update_mode: Option<String>,
    pub cooldown_days: Option<i32>,
}

impl PolicyOverride {
    /// The effective `(update_mode, cooldown_days)` for serving a request under
    /// this credential, given the repo default. **Tighten-only**: a credential
    /// can make the policy *more* restrictive (later cooldown, manual over auto),
    /// never weaken it. A bare cooldown override implies `delayed` (a cooldown is
    /// meaningless under `auto`).
    #[must_use]
    pub fn effective(&self, repo_mode: &str, repo_cooldown: i32) -> (String, i32) {
        let rank = |m: &str| match m {
            "manual" => 2,
            "delayed" => 1,
            _ => 0,
        };
        let ovr_cooldown = self.cooldown_days.unwrap_or(0);
        let ovr_mode = self
            .update_mode
            .as_deref()
            .or(if ovr_cooldown > 0 { Some("delayed") } else { None });
        let mode = match ovr_mode {
            Some(m) if rank(m) > rank(repo_mode) => m.to_owned(),
            _ => repo_mode.to_owned(),
        };
        (mode, ovr_cooldown.max(repo_cooldown))
    }

    /// Whether any override is set (for compact display).
    #[must_use]
    pub fn is_some(&self) -> bool {
        self.update_mode.is_some() || self.cooldown_days.is_some()
    }
}

/// A license key in the admin listing (the key itself is never recoverable).
#[derive(Debug, Clone)]
pub struct LicenseSummary {
    pub id: Uuid,
    pub buyer: Option<String>,
    pub status: String,
    pub packages: Vec<String>,
}

/// A read token in the admin listing (the token itself is never recoverable).
#[derive(Debug, Clone)]
pub struct TokenSummary {
    pub id: Uuid,
    pub label: Option<String>,
    /// How it was minted: `manual` | `session` | `ci`.
    pub origin: String,
    /// Creation date as text (`YYYY-MM-DD`).
    pub created: String,
    /// Last-use date as text, `null` if never used.
    pub last_used: Option<String>,
    /// Expiry date as text, `null` if it never expires.
    pub expires: Option<String>,
    /// Whether the token is already past its expiry.
    pub expired: bool,
}

/// A grant shown in the admin UI: a package owned elsewhere, exposed here.
#[derive(Debug, Clone)]
pub struct GrantSummary {
    pub package: String,
    pub source_org: String,
    pub source_repo: String,
}

/// A package version as stored in the catalog.
#[derive(Debug, Clone)]
pub struct PackageVersion {
    pub version: String,
    pub normalized_version: String,
    pub stability: String,
    pub composer_json: Value,
    /// sha256 of the dist archive in the CAS, if one is attached.
    pub dist_blob_sha256: Option<[u8; 32]>,
    /// sha1 hex of the dist archive — Composer's `dist.shasum`.
    pub dist_shasum: Option<String>,
    pub source_reference: Option<String>,
}

impl Catalog {
    /// Connect to Postgres at `database_url` (e.g.
    /// `postgres://user:pass@host:5432/db`).
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPool::connect(database_url).await?;
        Ok(Self { pool })
    }

    /// Build from an existing pool.
    #[must_use]
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create an organization (idempotent on slug), returning its id.
    pub async fn create_org(&self, slug: &str, name: Option<&str>) -> Result<Uuid, sqlx::Error> {
        sqlx::query_scalar(
            "insert into organizations (slug, name) values ($1, $2) \
             on conflict (slug) do update set name = coalesce(excluded.name, organizations.name) \
             returning id",
        )
        .bind(slug)
        .bind(name)
        .fetch_one(&self.pool)
        .await
    }

    /// Create a repository under the org with slug `org_slug` (idempotent on the
    /// `(org, repo)` slug pair), returning its id. Errors if the org is unknown.
    pub async fn create_repo(&self, org_slug: &str, repo_slug: &str) -> Result<Uuid, sqlx::Error> {
        sqlx::query_scalar(
            "insert into repositories (org_id, slug) \
             select o.id, $2 from organizations o where o.slug = $1 \
             on conflict (org_id, slug) do update set slug = excluded.slug \
             returning id",
        )
        .bind(org_slug)
        .bind(repo_slug)
        .fetch_one(&self.pool)
        .await
    }

    /// Resolve `(org slug, repo slug)` to a repository id.
    pub async fn resolve_repo(
        &self,
        org_slug: &str,
        repo_slug: &str,
    ) -> Result<Option<Uuid>, sqlx::Error> {
        sqlx::query_scalar(
            "select r.id from repositories r \
             join organizations o on o.id = r.org_id \
             where o.slug = $1 and r.slug = $2",
        )
        .bind(org_slug)
        .bind(repo_slug)
        .fetch_optional(&self.pool)
        .await
    }

    /// All organizations (tenants), sorted — so a freshly created org is visible
    /// in the dashboard even before it has any repositories.
    pub async fn list_organizations(&self) -> Result<Vec<OrgSummary>, sqlx::Error> {
        let rows = sqlx::query("select id, slug, name from organizations order by slug")
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|r| {
                Ok(OrgSummary {
                    id: r.try_get("id")?,
                    slug: r.try_get("slug")?,
                    name: r.try_get("name")?,
                })
            })
            .collect()
    }

    /// All repositories, for the admin dashboard.
    pub async fn list_repositories(&self) -> Result<Vec<RepoSummary>, sqlx::Error> {
        let rows = sqlx::query(
            "select o.slug as org, o.id as org_id, r.slug as repo, r.id as id, \
                    r.update_mode as update_mode, r.cooldown_days as cooldown_days \
             from repositories r join organizations o on o.id = r.org_id \
             order by o.slug, r.slug",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                Ok(RepoSummary {
                    org: row.try_get("org")?,
                    org_id: row.try_get("org_id")?,
                    repo: row.try_get("repo")?,
                    id: row.try_get("id")?,
                    update_mode: row.try_get("update_mode")?,
                    cooldown_days: row.try_get("cooldown_days")?,
                })
            })
            .collect()
    }

    /// Every version of every package **owned** by a repo, with control state —
    /// the admin view (unlike `visible_versions`, it ignores policy/holds so the
    /// operator can see and act on everything).
    pub async fn admin_package_versions(
        &self,
        repo_id: Uuid,
    ) -> Result<Vec<AdminVersion>, sqlx::Error> {
        let rows = sqlx::query(
            "select p.name as package, pv.version, pv.normalized_version, pv.stability, \
                    (pv.held_at is not null) as held, (pv.approved_at is not null) as approved, \
                    (pv.yanked_at is not null) as yanked, \
                    pv.released_at::text as released_at, \
                    case when pv.released_at is null then null else \
                        greatest(0, ceil(extract(epoch from \
                            (pv.released_at + make_interval(days => r.cooldown_days) - now())) / 86400))::bigint \
                    end as cooldown_days_left \
             from package_versions pv \
             join packages p on p.id = pv.package_id \
             join repositories r on r.id = $1 \
             where p.repo_id = $1 \
             order by p.name, pv.normalized_version",
        )
        .bind(repo_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                Ok(AdminVersion {
                    package: row.try_get("package")?,
                    version: row.try_get("version")?,
                    normalized_version: row.try_get("normalized_version")?,
                    stability: row.try_get("stability")?,
                    held: row.try_get("held")?,
                    approved: row.try_get("approved")?,
                    yanked: row.try_get("yanked")?,
                    released_at: row.try_get("released_at")?,
                    cooldown_days_left: row.try_get("cooldown_days_left")?,
                })
            })
            .collect()
    }

    /// Number of read tokens for a repository.
    pub async fn repo_token_count(&self, repo_id: Uuid) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar("select count(*) from tokens where repo_id = $1")
            .bind(repo_id)
            .fetch_one(&self.pool)
            .await
    }

    /// License keys for a repository, each with its entitled package names.
    pub async fn list_licenses(&self, repo_id: Uuid) -> Result<Vec<LicenseSummary>, sqlx::Error> {
        let rows = sqlx::query(
            "select l.id as id, l.buyer_ref as buyer, l.status as status, \
                    coalesce(array_agg(p.name) filter (where p.name is not null), '{}') as packages \
             from license_keys l \
             left join entitlements e on e.license_key_id = l.id \
             left join packages p on p.id = e.package_id \
             where l.repo_id = $1 \
             group by l.id, l.buyer_ref, l.status, l.created_at \
             order by l.created_at",
        )
        .bind(repo_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                Ok(LicenseSummary {
                    id: row.try_get("id")?,
                    buyer: row.try_get("buyer")?,
                    status: row.try_get("status")?,
                    packages: row.try_get("packages")?,
                })
            })
            .collect()
    }

    /// Packages granted into a repository (with where they're owned).
    pub async fn list_grants(&self, repo_id: Uuid) -> Result<Vec<GrantSummary>, sqlx::Error> {
        let rows = sqlx::query(
            "select p.name as package, o.slug as source_org, r.slug as source_repo \
             from repository_grants g \
             join packages p on p.id = g.package_id \
             join repositories r on r.id = p.repo_id \
             join organizations o on o.id = r.org_id \
             where g.repo_id = $1 order by p.name",
        )
        .bind(repo_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                Ok(GrantSummary {
                    package: row.try_get("package")?,
                    source_org: row.try_get("source_org")?,
                    source_repo: row.try_get("source_repo")?,
                })
            })
            .collect()
    }

    // ----- accounts (admin UI) -----

    /// Create a user with an argon2-hashed password (idempotent on email:
    /// updates the password + superadmin flag). Returns the user id.
    pub async fn create_user(
        &self,
        email: &str,
        password: &str,
        is_superadmin: bool,
    ) -> Result<Uuid, sqlx::Error> {
        let hash = hash_password(password);
        sqlx::query_scalar(
            "insert into users (email, password_hash, is_superadmin) values ($1, $2, $3) \
             on conflict (email) do update set password_hash = excluded.password_hash, \
                 is_superadmin = excluded.is_superadmin \
             returning id",
        )
        .bind(email)
        .bind(hash)
        .bind(is_superadmin)
        .fetch_one(&self.pool)
        .await
    }

    /// Give a user access to a tenant (organization, by slug) with `role`
    /// (`member`|`admin`). Upserts the role for an existing membership. Returns
    /// `false` if the user or org is unknown.
    pub async fn add_user_to_tenant(
        &self,
        email: &str,
        org_slug: &str,
        role: &str,
    ) -> Result<bool, sqlx::Error> {
        let done = sqlx::query(
            "insert into user_tenants (user_id, org_id, role, active) \
             select u.id, o.id, $3, true from users u, organizations o \
             where u.email = $1 and o.slug = $2 \
             on conflict (user_id, org_id) do update set role = excluded.role, active = true",
        )
        .bind(email)
        .bind(org_slug)
        .bind(role)
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() > 0)
    }

    /// Verify an email/password and, on success, return the user's id.
    pub async fn verify_credentials(
        &self,
        email: &str,
        password: &str,
    ) -> Result<Option<Uuid>, sqlx::Error> {
        let row: Option<(Uuid, String)> =
            sqlx::query_as("select id, password_hash from users where email = $1")
                .bind(email)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row
            .filter(|(_, hash)| verify_password(password, hash))
            .map(|(id, _)| id))
    }

    /// Open a login session for a user, returning the (plaintext) session token.
    pub async fn create_session(
        &self,
        user_id: Uuid,
        ttl_days: i64,
    ) -> Result<String, sqlx::Error> {
        let token = generate_secret("scses_");
        sqlx::query(
            "insert into sessions (token_hash, user_id, expires_at) \
             values ($1, $2, now() + make_interval(days => $3))",
        )
        .bind(token_hash(&token))
        .bind(user_id)
        .bind(i32::try_from(ttl_days).unwrap_or(i32::MAX))
        .execute(&self.pool)
        .await?;
        Ok(token)
    }

    /// Resolve a session token to the authenticated user (with tenant access),
    /// or `None` if missing/expired.
    pub async fn resolve_session(&self, token: &str) -> Result<Option<AuthUser>, sqlx::Error> {
        let row: Option<(Uuid, bool)> = sqlx::query_as(
            "select u.id, u.is_superadmin from sessions s join users u on u.id = s.user_id \
             where s.token_hash = $1 and s.expires_at > now()",
        )
        .bind(token_hash(token))
        .fetch_optional(&self.pool)
        .await?;
        let Some((id, is_superadmin)) = row else {
            return Ok(None);
        };
        // Only *active* memberships grant access (SCIM deactivation flips this).
        let rows: Vec<(Uuid, String)> =
            sqlx::query_as("select org_id, role from user_tenants where user_id = $1 and active")
                .bind(id)
                .fetch_all(&self.pool)
                .await?;
        let tenant_org_ids = rows.iter().map(|(o, _)| *o).collect();
        let admin_org_ids = rows
            .iter()
            .filter(|(_, r)| r == "admin")
            .map(|(o, _)| *o)
            .collect();
        Ok(Some(AuthUser {
            id,
            is_superadmin,
            tenant_org_ids,
            admin_org_ids,
        }))
    }

    /// Delete a session (logout).
    pub async fn delete_session(&self, token: &str) -> Result<(), sqlx::Error> {
        sqlx::query("delete from sessions where token_hash = $1")
            .bind(token_hash(token))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// All users with their tenant slugs — for the superadmin user list.
    pub async fn list_users(&self) -> Result<Vec<UserSummary>, sqlx::Error> {
        let rows = sqlx::query(
            "select u.email as email, u.is_superadmin as is_superadmin, \
                    coalesce(array_agg(o.slug) filter (where o.slug is not null), '{}') as tenants \
             from users u \
             left join user_tenants ut on ut.user_id = u.id \
             left join organizations o on o.id = ut.org_id \
             group by u.id, u.email, u.is_superadmin order by u.email",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                Ok(UserSummary {
                    email: row.try_get("email")?,
                    is_superadmin: row.try_get("is_superadmin")?,
                    tenants: row.try_get("tenants")?,
                })
            })
            .collect()
    }

    /// Number of users (a fresh install has none → bootstrap a superadmin).
    pub async fn user_count(&self) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar("select count(*) from users")
            .fetch_one(&self.pool)
            .await
    }

    // ----- OIDC (dashboard SSO) -----

    /// Set an OIDC connection, scoped to `org_slug` (`None` = instance default).
    /// Replaces any existing connection at that scope. `client_secret` is the
    /// already-encrypted blob (NULL for a public client).
    pub async fn set_oidc_connection(
        &self,
        org_slug: Option<&str>,
        c: &OidcConnection,
    ) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        // Resolve the org (if any) up front so an unknown slug is a clean error.
        let org_id: Option<Uuid> = match org_slug {
            None => None,
            Some(slug) => Some(
                sqlx::query_scalar("select id from organizations where slug = $1")
                    .bind(slug)
                    .fetch_one(&mut *tx)
                    .await?,
            ),
        };
        match org_id {
            None => {
                sqlx::query("delete from oidc_connections where org_id is null")
                    .execute(&mut *tx)
                    .await?;
            }
            Some(id) => {
                sqlx::query("delete from oidc_connections where org_id = $1")
                    .bind(id)
                    .execute(&mut *tx)
                    .await?;
            }
        }
        sqlx::query(
            "insert into oidc_connections \
                 (org_id, issuer_url, client_id, client_secret, redirect_url, scopes, allowed_domains, admin_domains) \
             values ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(org_id)
        .bind(&c.issuer_url)
        .bind(&c.client_id)
        .bind(c.client_secret.as_deref())
        .bind(&c.redirect_url)
        .bind(&c.scopes)
        .bind(c.allowed_domains.as_deref())
        .bind(c.admin_domains.as_deref())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    const OIDC_SELECT: &'static str =
        "select c.id, o.slug as org_slug, c.issuer_url, c.client_id, c.client_secret, \
                c.redirect_url, c.scopes, c.allowed_domains, c.admin_domains \
         from oidc_connections c left join organizations o on o.id = c.org_id";

    fn oidc_from_row(r: &sqlx::postgres::PgRow) -> Result<OidcConnection, sqlx::Error> {
        Ok(OidcConnection {
            id: r.try_get("id")?,
            org_slug: r.try_get("org_slug")?,
            issuer_url: r.try_get("issuer_url")?,
            client_id: r.try_get("client_id")?,
            client_secret: r.try_get("client_secret")?,
            redirect_url: r.try_get("redirect_url")?,
            scopes: r.try_get("scopes")?,
            allowed_domains: r.try_get("allowed_domains")?,
            admin_domains: r.try_get("admin_domains")?,
        })
    }

    /// The instance-default OIDC connection (`org_id IS NULL`), if configured.
    pub async fn oidc_connection(&self) -> Result<Option<OidcConnection>, sqlx::Error> {
        let row = sqlx::query(&format!("{} where c.org_id is null", Self::OIDC_SELECT))
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(Self::oidc_from_row).transpose()
    }

    /// An OIDC connection by id.
    pub async fn oidc_connection_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<OidcConnection>, sqlx::Error> {
        let row = sqlx::query(&format!("{} where c.id = $1", Self::OIDC_SELECT))
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(Self::oidc_from_row).transpose()
    }

    /// Route an email to a connection by domain: an org connection whose
    /// `allowed_domains` matches wins; else the instance default (if any).
    /// Returns the connection id to begin a login with.
    pub async fn oidc_connection_for_email(
        &self,
        email: &str,
    ) -> Result<Option<Uuid>, sqlx::Error> {
        let domain = email.rsplit('@').next().unwrap_or("");
        // Prefer an org-scoped connection that lists this domain.
        let scoped: Option<Uuid> = sqlx::query_scalar(
            "select id from oidc_connections \
             where org_id is not null and allowed_domains is not null \
               and exists (select 1 from unnest(allowed_domains) d where lower(d) = lower($1)) \
             limit 1",
        )
        .bind(domain)
        .fetch_optional(&self.pool)
        .await?;
        if scoped.is_some() {
            return Ok(scoped);
        }
        sqlx::query_scalar("select id from oidc_connections where org_id is null")
            .fetch_optional(&self.pool)
            .await
    }

    /// Whether any OIDC connection exists (to decide whether to offer SSO).
    pub async fn oidc_configured(&self) -> Result<bool, sqlx::Error> {
        sqlx::query_scalar("select exists (select 1 from oidc_connections)")
            .fetch_one(&self.pool)
            .await
    }

    /// Store a login flow's transaction state (TTL in seconds). `conn_id` is the
    /// connection it began with (`None` = instance default).
    pub async fn create_oidc_flow(
        &self,
        state: &str,
        conn_id: Option<Uuid>,
        nonce: &str,
        pkce_verifier: &str,
        redirect_to: &str,
        ttl_secs: i64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "insert into oidc_flows (state, conn_id, nonce, pkce_verifier, redirect_to, expires_at) \
             values ($1, $2, $3, $4, $5, now() + make_interval(secs => $6::double precision))",
        )
        .bind(state)
        .bind(conn_id)
        .bind(nonce)
        .bind(pkce_verifier)
        .bind(redirect_to)
        .bind(ttl_secs)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Consume a login flow: atomically fetch + delete it, returning
    /// `(conn_id, nonce, pkce_verifier, redirect_to)`. `None` if unknown/expired.
    pub async fn consume_oidc_flow(
        &self,
        state: &str,
    ) -> Result<Option<(Option<Uuid>, String, String, String)>, sqlx::Error> {
        let row = sqlx::query(
            "delete from oidc_flows where state = $1 and expires_at > now() \
             returning conn_id, nonce, pkce_verifier, redirect_to",
        )
        .bind(state)
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            Some(r) => Some((
                r.try_get("conn_id")?,
                r.try_get("nonce")?,
                r.try_get("pkce_verifier")?,
                r.try_get("redirect_to")?,
            )),
            None => None,
        })
    }

    /// JIT-provision (or fetch) an SSO user by email, setting superadmin. Keeps
    /// any existing password (SSO users normally have none). Returns the id.
    pub async fn find_or_create_sso_user(
        &self,
        email: &str,
        is_superadmin: bool,
    ) -> Result<Uuid, sqlx::Error> {
        // A random, unusable password hash for new SSO users (no password login).
        let hash = hash_password(&generate_secret("sso_"));
        sqlx::query_scalar(
            "insert into users (email, password_hash, is_superadmin) values ($1, $2, $3) \
             on conflict (email) do update set is_superadmin = excluded.is_superadmin \
             returning id",
        )
        .bind(email)
        .bind(hash)
        .bind(is_superadmin)
        .fetch_one(&self.pool)
        .await
    }

    // ----- SCIM provisioning (offboarding) -----

    /// Create (replace) an org's SCIM bearer token; returns the plaintext once.
    /// `None` if the org is unknown.
    pub async fn create_scim_token(&self, org_slug: &str) -> Result<Option<String>, sqlx::Error> {
        let Some(org_id): Option<Uuid> =
            sqlx::query_scalar("select id from organizations where slug = $1")
                .bind(org_slug)
                .fetch_optional(&self.pool)
                .await?
        else {
            return Ok(None);
        };
        let token = generate_secret("scim_");
        sqlx::query(
            "insert into scim_tokens (org_id, token_hash) values ($1, $2) \
             on conflict (org_id) do update set token_hash = excluded.token_hash",
        )
        .bind(org_id)
        .bind(token_hash(&token))
        .execute(&self.pool)
        .await?;
        Ok(Some(token))
    }

    /// Resolve a SCIM bearer token to the org it provisions into.
    pub async fn resolve_scim_token(&self, token: &str) -> Result<Option<Uuid>, sqlx::Error> {
        sqlx::query_scalar("select org_id from scim_tokens where token_hash = $1")
            .bind(token_hash(token))
            .fetch_optional(&self.pool)
            .await
    }

    /// Provision a user into an org as an active `member` (idempotent by email).
    /// Returns the user id (the SCIM resource id).
    pub async fn scim_provision(&self, org_id: Uuid, email: &str) -> Result<Uuid, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let hash = hash_password(&generate_secret("scim_"));
        let user_id: Uuid = sqlx::query_scalar(
            "insert into users (email, password_hash, is_superadmin) values ($1, $2, false) \
             on conflict (email) do update set email = excluded.email returning id",
        )
        .bind(email)
        .bind(hash)
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query(
            "insert into user_tenants (user_id, org_id, role, active) values ($1, $2, 'member', true) \
             on conflict (user_id, org_id) do update set active = true",
        )
        .bind(user_id)
        .bind(org_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(user_id)
    }

    /// Set a user's membership active flag in an org. Returns whether the
    /// membership existed.
    pub async fn scim_set_active(
        &self,
        org_id: Uuid,
        user_id: Uuid,
        active: bool,
    ) -> Result<bool, sqlx::Error> {
        let done = sqlx::query("update user_tenants set active = $3 where org_id = $1 and user_id = $2")
            .bind(org_id)
            .bind(user_id)
            .bind(active)
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() > 0)
    }

    /// Revoke all of a user's login sessions (used on deactivation → instant
    /// logout). Returns the number revoked.
    pub async fn delete_user_sessions(&self, user_id: Uuid) -> Result<u64, sqlx::Error> {
        let done = sqlx::query("delete from sessions where user_id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected())
    }

    /// A SCIM member's `(email, active)` by id within an org.
    pub async fn scim_member(
        &self,
        org_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<(String, bool)>, sqlx::Error> {
        sqlx::query_as(
            "select u.email, ut.active from user_tenants ut join users u on u.id = ut.user_id \
             where ut.org_id = $1 and ut.user_id = $2",
        )
        .bind(org_id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
    }

    /// A SCIM member's `(user_id, active)` by email (for `userName` filters).
    pub async fn scim_member_by_email(
        &self,
        org_id: Uuid,
        email: &str,
    ) -> Result<Option<(Uuid, bool)>, sqlx::Error> {
        sqlx::query_as(
            "select ut.user_id, ut.active from user_tenants ut join users u on u.id = ut.user_id \
             where ut.org_id = $1 and lower(u.email) = lower($2)",
        )
        .bind(org_id)
        .bind(email)
        .fetch_optional(&self.pool)
        .await
    }

    // ----- CI OIDC token exchange -----

    /// Add a CI OIDC policy to a repo. Returns the new policy id.
    pub async fn add_ci_policy(
        &self,
        repo_id: Uuid,
        provider: &str,
        issuer: &str,
        audience: &str,
        claims: &Value,
        token_ttl_secs: i64,
    ) -> Result<Uuid, sqlx::Error> {
        sqlx::query_scalar(
            "insert into ci_oidc_policies (repo_id, provider, issuer, audience, claims, token_ttl_secs) \
             values ($1, $2, $3, $4, $5, $6) returning id",
        )
        .bind(repo_id)
        .bind(provider)
        .bind(issuer)
        .bind(audience)
        .bind(claims)
        .bind(token_ttl_secs)
        .fetch_one(&self.pool)
        .await
    }

    /// A repo's CI OIDC policies.
    pub async fn ci_policies(&self, repo_id: Uuid) -> Result<Vec<CiPolicy>, sqlx::Error> {
        let rows = sqlx::query(
            "select id, repo_id, provider, issuer, audience, claims, token_ttl_secs \
             from ci_oidc_policies where repo_id = $1 order by created_at",
        )
        .bind(repo_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok(CiPolicy {
                    id: r.try_get("id")?,
                    repo_id: r.try_get("repo_id")?,
                    provider: r.try_get("provider")?,
                    issuer: r.try_get("issuer")?,
                    audience: r.try_get("audience")?,
                    claims: r.try_get("claims")?,
                    token_ttl_secs: r.try_get("token_ttl_secs")?,
                })
            })
            .collect()
    }

    /// Mint a short-lived **CI** token (`origin = 'ci'`). Bypasses the
    /// `allow_raw_tokens` org policy by design — a CI token carries a
    /// deprovisionable workload identity, not a raw operator secret.
    pub async fn create_ci_token(
        &self,
        repo_id: Uuid,
        label: &str,
        ttl_secs: i64,
    ) -> Result<String, sqlx::Error> {
        let token = generate_token();
        sqlx::query(
            "insert into tokens (repo_id, token_hash, label, expires_at, origin) values \
             ($1, $2, $3, now() + make_interval(secs => $4::double precision), 'ci')",
        )
        .bind(repo_id)
        .bind(token_hash(&token))
        .bind(label)
        .bind(ttl_secs)
        .execute(&self.pool)
        .await?;
        Ok(token)
    }

    /// Apply any pending migrations. Idempotent; safe to call on every startup.
    ///
    /// Concurrent migrators (multiple app instances starting at once, or
    /// parallel tests) are serialized with a session-level Postgres advisory
    /// lock: the first holder applies migrations, the rest block and then see
    /// them already applied. No races, no duplicate application.
    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        let mut conn = self.pool.acquire().await?;
        sqlx::query("select pg_advisory_lock($1)")
            .bind(MIGRATE_LOCK)
            .execute(&mut *conn)
            .await?;
        let result = run_migrations(&mut conn).await;
        // Always release the lock, even if a migration failed.
        let _ = sqlx::query("select pg_advisory_unlock($1)")
            .bind(MIGRATE_LOCK)
            .execute(&mut *conn)
            .await;
        result
    }

    /// Record a blob's presence + size (idempotent — the sha256 is the key).
    pub async fn upsert_blob(&self, sha256: &[u8; 32], size_bytes: i64) -> Result<(), sqlx::Error> {
        sqlx::query(
            "insert into blobs (sha256, size_bytes) values ($1, $2) \
             on conflict (sha256) do nothing",
        )
        .bind(&sha256[..])
        .bind(size_bytes)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Upsert a package by name **within a repository**, returning its id.
    ///
    /// Enforces the repo's `allow_private_packages` policy: a [`Visibility::Private`]
    /// package can't be added to a public-only repo (returns
    /// [`UpsertPackageError::Policy`]).
    pub async fn upsert_package(
        &self,
        repo_id: Uuid,
        name: &str,
        kind: &str,
        source: Option<&Value>,
        visibility: Visibility,
    ) -> Result<Uuid, UpsertPackageError> {
        if visibility == Visibility::Private {
            let allows: bool =
                sqlx::query_scalar("select allow_private_packages from repositories where id = $1")
                    .bind(repo_id)
                    .fetch_one(&self.pool)
                    .await?;
            if !allows {
                return Err(UpsertPackageError::Policy(
                    "this repository is public-only and does not allow private packages".to_owned(),
                ));
            }
        }
        let id = sqlx::query_scalar(
            "insert into packages (repo_id, name, kind, source, visibility) values ($1, $2, $3, $4, $5) \
             on conflict (repo_id, name) do update set \
                 kind = excluded.kind, source = excluded.source, visibility = excluded.visibility \
             returning id",
        )
        .bind(repo_id)
        .bind(name)
        .bind(kind)
        .bind(source)
        .bind(visibility.as_str())
        .fetch_one(&self.pool)
        .await?;
        Ok(id)
    }

    /// Packages in a repo with their lifecycle state, newest-broken first then by
    /// name. The operator view (not the serving read path — serving ignores
    /// lifecycle).
    pub async fn list_packages(&self, repo_id: Uuid) -> Result<Vec<PackageStatus>, sqlx::Error> {
        let rows = sqlx::query(
            "select name, visibility, sync_health, broken_reason, \
                    to_char(broken_at,       'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') as broken_at, \
                    to_char(last_success_at, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') as last_success_at, \
                    archived_at is not null as archived \
             from packages where repo_id = $1 \
             order by (sync_health = 'broken' and archived_at is null) desc, name",
        )
        .bind(repo_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok(PackageStatus {
                    name: r.try_get("name")?,
                    visibility: r.try_get("visibility")?,
                    sync_health: r.try_get("sync_health")?,
                    broken_reason: r.try_get("broken_reason")?,
                    broken_at: r.try_get("broken_at")?,
                    last_success_at: r.try_get("last_success_at")?,
                    archived: r.try_get("archived")?,
                })
            })
            .collect()
    }

    /// Record a successful sync of a package: stamp `last_success_at` and **clear
    /// any broken flag** (a package that synced is healthy again). No-op if the
    /// package doesn't exist.
    pub async fn mark_package_synced(&self, repo_id: Uuid, name: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            "update packages set last_success_at = now(), \
                 sync_health = 'ok', broken_reason = null, broken_at = null \
             where repo_id = $1 and name = $2",
        )
        .bind(repo_id)
        .bind(name)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Flag an **existing** package broken after a *terminal* sync failure (the
    /// caller has already classified it). Preserves an earlier `broken_at`.
    /// Returns whether a row was flagged (only existing packages are flagged —
    /// we never create one here). Archived packages are skipped (the operator
    /// already acknowledged them).
    pub async fn mark_package_broken(
        &self,
        repo_id: Uuid,
        name: &str,
        reason: &str,
    ) -> Result<bool, sqlx::Error> {
        let n = sqlx::query(
            "update packages set sync_health = 'broken', broken_reason = $3, \
                 broken_at = coalesce(broken_at, now()) \
             where repo_id = $1 and name = $2 and archived_at is null",
        )
        .bind(repo_id)
        .bind(name)
        .bind(reason)
        .execute(&self.pool)
        .await?;
        Ok(n.rows_affected() > 0)
    }

    /// Archive a package: freeze it (stop scheduling syncs) and mask any broken
    /// flag. Also cancels its pending per-package mirror jobs. Idempotent.
    pub async fn archive_package(&self, repo_id: Uuid, name: &str) -> Result<bool, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let n = sqlx::query(
            "update packages set archived_at = coalesce(archived_at, now()) \
             where repo_id = $1 and name = $2",
        )
        .bind(repo_id)
        .bind(name)
        .execute(&mut *tx)
        .await?;
        // Cancel any pending sync for this package so it stops failing.
        // mirror_package jobs carry (upstream_id, package), not repo_id, so scope
        // by the package's upstream belonging to this repo.
        sqlx::query(
            "delete from mirror_jobs mj using upstreams u \
             where mj.kind = 'mirror_package' and mj.status = 'pending' \
               and mj.package = $2 and mj.upstream_id = u.id and u.repo_id = $1",
        )
        .bind(repo_id)
        .bind(name)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(n.rows_affected() > 0)
    }

    /// Un-archive a package: resume syncing (health is re-detected on next sync).
    pub async fn unarchive_package(&self, repo_id: Uuid, name: &str) -> Result<bool, sqlx::Error> {
        let n = sqlx::query(
            "update packages set archived_at = null where repo_id = $1 and name = $2",
        )
        .bind(repo_id)
        .bind(name)
        .execute(&self.pool)
        .await?;
        Ok(n.rows_affected() > 0)
    }

    /// Names of packages in a repo bound to `upstream_id` that are **not**
    /// archived — used by the registry mirror to skip frozen packages and to
    /// reconcile removals.
    pub async fn upstream_package_names(
        &self,
        upstream_id: Uuid,
    ) -> Result<Vec<String>, sqlx::Error> {
        let rows = sqlx::query(
            "select name from packages where upstream_id = $1 and archived_at is null order by name",
        )
        .bind(upstream_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(|r| r.try_get("name")).collect()
    }

    /// Upsert a version of a package, returning its id.
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_package_version(
        &self,
        package_id: Uuid,
        version: &str,
        normalized_version: &str,
        stability: &str,
        composer_json: &Value,
        dist_blob_sha256: Option<&[u8; 32]>,
        dist_shasum: Option<&str>,
        source_reference: Option<&str>,
        released_at_unix: Option<i64>,
    ) -> Result<Uuid, sqlx::Error> {
        let dist = dist_blob_sha256.map(|b| &b[..]);
        // released_at is the upstream release time that drives cooldown; the
        // cast-to-double + to_timestamp happen in SQL (null stays null).
        // held_at/approved_at are deliberately NOT touched here, so re-mirroring
        // preserves operator decisions.
        sqlx::query_scalar(
            "insert into package_versions \
                 (package_id, version, normalized_version, stability, composer_json, \
                  dist_blob_sha256, dist_shasum, source_reference, released_at) \
             values ($1, $2, $3, $4, $5, $6, $7, $8, to_timestamp($9::double precision)) \
             on conflict (package_id, normalized_version) do update set \
                 version = excluded.version, \
                 stability = excluded.stability, \
                 composer_json = excluded.composer_json, \
                 dist_blob_sha256 = excluded.dist_blob_sha256, \
                 dist_shasum = excluded.dist_shasum, \
                 source_reference = excluded.source_reference, \
                 released_at = excluded.released_at \
             returning id",
        )
        .bind(package_id)
        .bind(version)
        .bind(normalized_version)
        .bind(stability)
        .bind(composer_json)
        .bind(dist)
        .bind(dist_shasum)
        .bind(source_reference)
        .bind(released_at_unix)
        .fetch_one(&self.pool)
        .await
    }

    /// Create a new read token for a repository: generate a high-entropy secret,
    /// store only its sha256, and return the plaintext **once** (never
    /// recoverable after).
    /// `expires_in_days = Some(n)` makes the token expire `n` days from now;
    /// `None` means it never expires.
    ///
    /// This is the **manual** (`origin = 'manual'`) token path — a raw token an
    /// operator/user creates. It enforces the owning org's [`OrgSettings`]
    /// (raw-token toggle, max TTL) here, the single authoritative path, so neither
    /// the UI nor the CLI can bypass it. Returns [`CreateTokenError::Policy`] with
    /// a user-facing reason when the org forbids the token.
    ///
    /// SSO/CI-derived tokens (`origin = 'session' | 'ci'`) are **exempt** from the
    /// `allow_raw_tokens` gate and will be minted by separate, ungated methods —
    /// they carry a deprovisionable identity, which is exactly why disabling raw
    /// tokens is safe.
    pub async fn create_token(
        &self,
        repo_id: Uuid,
        label: Option<&str>,
        expires_in_days: Option<i64>,
    ) -> Result<String, CreateTokenError> {
        let settings = self.effective_token_policy(repo_id).await?;
        if !settings.allow_raw_tokens {
            return Err(CreateTokenError::Policy(
                "raw tokens are disabled for this repository".to_owned(),
            ));
        }
        if let Some(max) = settings.max_token_ttl_days {
            match expires_in_days {
                None => {
                    return Err(CreateTokenError::Policy(format!(
                        "this organization requires an expiry of at most {max} day(s)"
                    )));
                }
                Some(d) if d > max => {
                    return Err(CreateTokenError::Policy(format!(
                        "expiry {d} day(s) exceeds the organization limit of {max} day(s)"
                    )));
                }
                Some(_) => {}
            }
        }
        let token = generate_token();
        sqlx::query(
            "insert into tokens (repo_id, token_hash, label, expires_at, origin) values \
             ($1, $2, $3, case when $4::bigint is null then null \
                               else now() + make_interval(days => $4::int) end, 'manual')",
        )
        .bind(repo_id)
        .bind(token_hash(&token))
        .bind(label)
        .bind(expires_in_days)
        .execute(&self.pool)
        .await?;
        Ok(token)
    }

    /// Org-wide settings for an organization (defaults if none stored).
    pub async fn org_settings(&self, org_id: Uuid) -> Result<OrgSettings, sqlx::Error> {
        let row = sqlx::query(
            "select allow_raw_tokens, max_token_ttl_days from org_settings where org_id = $1",
        )
        .bind(org_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            Some(r) => OrgSettings {
                allow_raw_tokens: r.try_get("allow_raw_tokens")?,
                max_token_ttl_days: r.try_get("max_token_ttl_days")?,
            },
            None => OrgSettings::default(),
        })
    }

    /// The **effective** token policy for a repo: the org baseline combined with
    /// the repo's overrides, where the repo can only *tighten*. Raw tokens are
    /// allowed only if both levels allow; the max TTL is the smaller of the two
    /// caps (treating "no cap" as infinity). Errors if the repo does not exist.
    pub async fn effective_token_policy(&self, repo_id: Uuid) -> Result<OrgSettings, sqlx::Error> {
        let row = sqlx::query(
            "select coalesce(s.allow_raw_tokens, true) as org_allow, \
                    s.max_token_ttl_days as org_max, \
                    r.allow_raw_tokens as repo_allow, \
                    r.max_token_ttl_days as repo_max \
             from repositories r \
             left join org_settings s on s.org_id = r.org_id \
             where r.id = $1",
        )
        .bind(repo_id)
        .fetch_optional(&self.pool)
        .await?;
        let Some(r) = row else {
            return Err(sqlx::Error::RowNotFound);
        };
        let org_allow: bool = r.try_get("org_allow")?;
        let org_max: Option<i64> = r.try_get("org_max")?;
        let repo_allow: Option<bool> = r.try_get("repo_allow")?;
        let repo_max: Option<i64> = r.try_get("repo_max")?;
        Ok(OrgSettings {
            // Repo can turn off, never on.
            allow_raw_tokens: org_allow && repo_allow.unwrap_or(true),
            // Smaller cap wins; None = no cap = infinity.
            max_token_ttl_days: min_cap(org_max, repo_max),
        })
    }

    /// A repo's raw token-policy overrides (NULL fields = inherit). Errors if the
    /// repo does not exist.
    pub async fn repo_settings(&self, repo_id: Uuid) -> Result<RepoSettings, sqlx::Error> {
        let row = sqlx::query(
            "select allow_raw_tokens, max_token_ttl_days, allow_private_packages \
             from repositories where id = $1",
        )
        .bind(repo_id)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some(r) => Ok(RepoSettings {
                allow_raw_tokens: r.try_get("allow_raw_tokens")?,
                max_token_ttl_days: r.try_get("max_token_ttl_days")?,
                allow_private_packages: r.try_get("allow_private_packages")?,
            }),
            None => Err(sqlx::Error::RowNotFound),
        }
    }

    /// Set a repo's settings (token overrides + private-package policy).
    pub async fn set_repo_settings(
        &self,
        repo_id: Uuid,
        settings: RepoSettings,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "update repositories set allow_raw_tokens = $2, max_token_ttl_days = $3, \
                 allow_private_packages = $4 where id = $1",
        )
        .bind(repo_id)
        .bind(settings.allow_raw_tokens)
        .bind(settings.max_token_ttl_days)
        .bind(settings.allow_private_packages)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Register an upstream for a repo. `credential` is the already-encrypted
    /// blob (see [`secret::SecretKey`]); pass `None` for a public/unauthed one.
    /// Returns the new upstream id.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_upstream(
        &self,
        repo_id: Uuid,
        kind: &str,
        base: &str,
        visibility: Visibility,
        label: Option<&str>,
        credential: Option<&[u8]>,
        credential_type: &str,
    ) -> Result<Uuid, sqlx::Error> {
        // Public upstreams are unauthenticated by definition — never store a
        // credential for one, whatever the caller passed.
        let credential = match visibility {
            Visibility::Public => None,
            Visibility::Private => credential,
        };
        sqlx::query_scalar(
            "insert into upstreams (repo_id, kind, base, visibility, label, credential, credential_type) \
             values ($1, $2, $3, $4, $5, $6, $7) returning id",
        )
        .bind(repo_id)
        .bind(kind)
        .bind(base)
        .bind(visibility.as_str())
        .bind(label)
        .bind(credential)
        .bind(credential_type)
        .fetch_one(&self.pool)
        .await
    }

    /// A repo's upstreams for the admin listing (no secret material).
    pub async fn list_upstreams(&self, repo_id: Uuid) -> Result<Vec<UpstreamSummary>, sqlx::Error> {
        let rows = sqlx::query(
            "select u.id, u.kind, u.base, u.visibility, u.label, \
                    (u.credential is not null) as has_credential, u.package_filter, \
                    j.status as job_status, j.last_error as job_error \
             from upstreams u \
             left join lateral ( \
                 select status, last_error from mirror_jobs m \
                 where m.upstream_id = u.id order by m.created_at desc limit 1 \
             ) j on true \
             where u.repo_id = $1 order by u.created_at",
        )
        .bind(repo_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok(UpstreamSummary {
                    id: r.try_get("id")?,
                    kind: r.try_get("kind")?,
                    base: r.try_get("base")?,
                    visibility: r.try_get("visibility")?,
                    label: r.try_get("label")?,
                    has_credential: r.try_get("has_credential")?,
                    package_filter: r.try_get("package_filter")?,
                    job_status: r.try_get("job_status")?,
                    job_error: r.try_get("job_error")?,
                })
            })
            .collect()
    }

    /// Load one upstream (with its encrypted credential) for mirroring.
    pub async fn get_upstream(&self, upstream_id: Uuid) -> Result<Option<UpstreamRow>, sqlx::Error> {
        let row = sqlx::query(
            "select id, repo_id, kind, base, visibility, credential, credential_type, package_filter \
             from upstreams where id = $1",
        )
        .bind(upstream_id)
        .fetch_optional(&self.pool)
        .await?;
        let Some(r) = row else { return Ok(None) };
        let visibility = Visibility::parse(r.try_get("visibility")?)
            .unwrap_or(Visibility::Private);
        Ok(Some(UpstreamRow {
            id: r.try_get("id")?,
            repo_id: r.try_get("repo_id")?,
            kind: r.try_get("kind")?,
            base: r.try_get("base")?,
            visibility,
            credential: r.try_get("credential")?,
            credential_type: r.try_get("credential_type")?,
            package_filter: r.try_get("package_filter")?,
        }))
    }

    /// Remove an upstream, scoped to its repo. Returns whether one was removed.
    /// Packages keep their rows but their `upstream_id` is set NULL (FK).
    pub async fn delete_upstream(
        &self,
        repo_id: Uuid,
        upstream_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let done = sqlx::query("delete from upstreams where repo_id = $1 and id = $2")
            .bind(repo_id)
            .bind(upstream_id)
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() > 0)
    }

    /// Set (or clear) a composer upstream's package-filter regex, repo-scoped.
    pub async fn set_upstream_filter(
        &self,
        repo_id: Uuid,
        upstream_id: Uuid,
        filter: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("update upstreams set package_filter = $3 where repo_id = $1 and id = $2")
            .bind(repo_id)
            .bind(upstream_id)
            .bind(filter)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Bind a package to the upstream it was mirrored from.
    pub async fn set_package_upstream(
        &self,
        package_id: Uuid,
        upstream_id: Uuid,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("update packages set upstream_id = $2 where id = $1")
            .bind(package_id)
            .bind(upstream_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ----- mirror job queue -----

    /// Enqueue a `mirror_upstream` job (sync a whole upstream).
    pub async fn enqueue_mirror_job(&self, upstream_id: Uuid) -> Result<bool, sqlx::Error> {
        self.enqueue_job("mirror_upstream", Some(upstream_id), None, None)
            .await
    }

    /// Enqueue a `mirror_package` job (mirror one package from an upstream).
    pub async fn enqueue_mirror_package_job(
        &self,
        upstream_id: Uuid,
        package: &str,
    ) -> Result<bool, sqlx::Error> {
        self.enqueue_job("mirror_package", Some(upstream_id), Some(package), None)
            .await
    }

    /// Enqueue a `resolve_closure` job (recompute a repo's dependency plan).
    pub async fn enqueue_resolve_closure_job(&self, repo_id: Uuid) -> Result<bool, sqlx::Error> {
        self.enqueue_job("resolve_closure", None, None, Some(repo_id))
            .await
    }

    /// Insert a job (deduped against an identical pending one) and wake the
    /// worker. Returns whether a new job was created.
    async fn enqueue_job(
        &self,
        kind: &str,
        upstream_id: Option<Uuid>,
        package: Option<&str>,
        repo_id: Option<Uuid>,
    ) -> Result<bool, sqlx::Error> {
        let done = sqlx::query(
            "insert into mirror_jobs (kind, upstream_id, package, repo_id) values ($1, $2, $3, $4) \
             on conflict (kind, coalesce(upstream_id::text, ''), coalesce(package, ''), \
                          coalesce(repo_id::text, '')) where status = 'pending' do nothing",
        )
        .bind(kind)
        .bind(upstream_id)
        .bind(package)
        .bind(repo_id)
        .execute(&self.pool)
        .await?;
        // Wake the worker regardless — if we deduped, the existing job still runs.
        sqlx::query("select pg_notify('mirror_jobs', '')")
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() > 0)
    }

    /// Atomically claim the next eligible pending job (oldest `run_after` first),
    /// marking it `running`. Uses `FOR UPDATE SKIP LOCKED` so concurrent workers
    /// never grab the same job. Returns `None` when nothing is ready.
    pub async fn claim_mirror_job(&self) -> Result<Option<MirrorJob>, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            "select id, kind, upstream_id, package, repo_id, attempts from mirror_jobs \
             where status = 'pending' and run_after <= now() \
             order by run_after for update skip locked limit 1",
        )
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Ok(None);
        };
        let id: Uuid = row.try_get("id")?;
        let attempts: i32 = row.try_get::<i32, _>("attempts")? + 1;
        let job = MirrorJob {
            id,
            kind: row.try_get("kind")?,
            upstream_id: row.try_get("upstream_id")?,
            package: row.try_get("package")?,
            repo_id: row.try_get("repo_id")?,
            attempts,
        };
        sqlx::query(
            "update mirror_jobs set status = 'running', attempts = $2, \
                 claimed_at = now(), updated_at = now() where id = $1",
        )
        .bind(id)
        .bind(attempts)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Some(job))
    }

    /// Mark a job finished successfully.
    pub async fn complete_mirror_job(&self, job_id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query(
            "update mirror_jobs set status = 'ready', last_error = null, updated_at = now() \
             where id = $1",
        )
        .bind(job_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Reschedule a failed job to retry after `backoff_secs`, recording the error.
    pub async fn retry_mirror_job(
        &self,
        job_id: Uuid,
        backoff_secs: f64,
        error: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "update mirror_jobs set status = 'pending', \
                 run_after = now() + make_interval(secs => $2), \
                 last_error = $3, updated_at = now() where id = $1",
        )
        .bind(job_id)
        .bind(backoff_secs)
        .bind(error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Mark a job permanently failed (retries exhausted).
    pub async fn fail_mirror_job(&self, job_id: Uuid, error: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            "update mirror_jobs set status = 'failed', last_error = $2, updated_at = now() \
             where id = $1",
        )
        .bind(job_id)
        .bind(error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ----- dependency plan -----

    /// Direct `require` edges of a repo's **own** packages: `(requiring package,
    /// dependency name)` across all stored versions (deduped by the caller).
    /// These seed the closure; transitive expansion happens via the upstreams.
    pub async fn repo_direct_requires(
        &self,
        repo_id: Uuid,
    ) -> Result<Vec<(String, String)>, sqlx::Error> {
        let rows = sqlx::query(
            "select distinct p.name as pkg, dep \
             from packages p \
             join package_versions pv on pv.package_id = p.id \
             cross join lateral jsonb_object_keys(coalesce(pv.composer_json->'require', '{}'::jsonb)) as dep \
             where p.repo_id = $1",
        )
        .bind(repo_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| Ok((r.try_get("pkg")?, r.try_get("dep")?)))
            .collect()
    }

    /// Replace a repo's stored dependency plan with `entries` (transactional).
    pub async fn replace_dependency_plan(
        &self,
        repo_id: Uuid,
        entries: &[DependencyPlanEntry],
    ) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("delete from dependency_plan where repo_id = $1")
            .bind(repo_id)
            .execute(&mut *tx)
            .await?;
        for e in entries {
            sqlx::query(
                "insert into dependency_plan (repo_id, name, status, resolver_upstream_id, required_by) \
                 values ($1, $2, $3, $4, $5)",
            )
            .bind(repo_id)
            .bind(&e.name)
            .bind(&e.status)
            .bind(e.resolver_upstream_id)
            .bind(&e.required_by)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// A repo's stored dependency plan, sorted by status then name.
    pub async fn list_dependency_plan(
        &self,
        repo_id: Uuid,
    ) -> Result<Vec<DependencyPlanEntry>, sqlx::Error> {
        let rows = sqlx::query(
            "select name, status, resolver_upstream_id, required_by \
             from dependency_plan where repo_id = $1 order by status, name",
        )
        .bind(repo_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok(DependencyPlanEntry {
                    name: r.try_get("name")?,
                    status: r.try_get("status")?,
                    resolver_upstream_id: r.try_get("resolver_upstream_id")?,
                    required_by: r.try_get("required_by")?,
                })
            })
            .collect()
    }

    /// One plan entry by name (used when adding a dep — to find its resolver).
    pub async fn dependency_plan_entry(
        &self,
        repo_id: Uuid,
        name: &str,
    ) -> Result<Option<DependencyPlanEntry>, sqlx::Error> {
        let row = sqlx::query(
            "select name, status, resolver_upstream_id, required_by \
             from dependency_plan where repo_id = $1 and name = $2",
        )
        .bind(repo_id)
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            Some(r) => Some(DependencyPlanEntry {
                name: r.try_get("name")?,
                status: r.try_get("status")?,
                resolver_upstream_id: r.try_get("resolver_upstream_id")?,
                required_by: r.try_get("required_by")?,
            }),
            None => None,
        })
    }

    /// Upsert an org's settings.
    pub async fn set_org_settings(
        &self,
        org_id: Uuid,
        settings: OrgSettings,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "insert into org_settings (org_id, allow_raw_tokens, max_token_ttl_days, updated_at) \
             values ($1, $2, $3, now()) \
             on conflict (org_id) do update set \
                 allow_raw_tokens = excluded.allow_raw_tokens, \
                 max_token_ttl_days = excluded.max_token_ttl_days, \
                 updated_at = now()",
        )
        .bind(org_id)
        .bind(settings.allow_raw_tokens)
        .bind(settings.max_token_ttl_days)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Whether `token` is valid **for this repository** (and not expired). Bumps
    /// `last_used_at`.
    pub async fn token_valid(&self, repo_id: Uuid, token: &str) -> Result<bool, sqlx::Error> {
        let updated = sqlx::query(
            "update tokens set last_used_at = now() where repo_id = $1 and token_hash = $2 \
             and (expires_at is null or expires_at > now())",
        )
        .bind(repo_id)
        .bind(token_hash(token))
        .execute(&self.pool)
        .await?;
        Ok(updated.rows_affected() > 0)
    }

    /// Tokens for a repository, for the admin listing (newest first). The
    /// plaintext is never recoverable; only metadata is returned.
    pub async fn list_tokens(&self, repo_id: Uuid) -> Result<Vec<TokenSummary>, sqlx::Error> {
        let rows = sqlx::query(
            "select id, label, origin, \
                    to_char(created_at, 'YYYY-MM-DD') as created, \
                    to_char(last_used_at, 'YYYY-MM-DD') as last_used, \
                    to_char(expires_at, 'YYYY-MM-DD') as expires, \
                    coalesce(expires_at <= now(), false) as expired \
             from tokens where repo_id = $1 order by created_at desc",
        )
        .bind(repo_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                Ok(TokenSummary {
                    id: row.try_get("id")?,
                    label: row.try_get("label")?,
                    origin: row.try_get("origin")?,
                    created: row.try_get("created")?,
                    last_used: row.try_get("last_used")?,
                    expires: row.try_get("expires")?,
                    expired: row.try_get("expired")?,
                })
            })
            .collect()
    }

    /// Revoke (delete) a token by id, scoped to its repository. Returns whether a
    /// token was actually removed.
    pub async fn revoke_token(&self, repo_id: Uuid, token_id: Uuid) -> Result<bool, sqlx::Error> {
        let deleted = sqlx::query("delete from tokens where repo_id = $1 and id = $2")
            .bind(repo_id)
            .bind(token_id)
            .execute(&self.pool)
            .await?;
        Ok(deleted.rows_affected() > 0)
    }

    /// Issue a license key for a repository (seller mode). Stores only the
    /// sha256; returns `(plaintext key, license id)` — the key is shown once.
    pub async fn create_license_key(
        &self,
        repo_id: Uuid,
        buyer_ref: Option<&str>,
    ) -> Result<(String, Uuid), sqlx::Error> {
        let key = generate_secret("sclk_");
        let id: Uuid = sqlx::query_scalar(
            "insert into license_keys (repo_id, key_hash, buyer_ref) values ($1, $2, $3) \
             returning id",
        )
        .bind(repo_id)
        .bind(token_hash(&key))
        .bind(buyer_ref)
        .fetch_one(&self.pool)
        .await?;
        Ok((key, id))
    }

    /// Issue a license entitled to `packages` (all owned by `repo_id`) in one
    /// transaction. Returns `Ok(None)` — and changes nothing — if any package is
    /// not found in the repo, so there are never orphan keys with missing
    /// entitlements. On success returns the plaintext key (shown once).
    pub async fn issue_license(
        &self,
        repo_id: Uuid,
        buyer: Option<&str>,
        packages: &[&str],
    ) -> Result<Option<String>, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let mut ids = Vec::with_capacity(packages.len());
        for &pkg in packages {
            let id: Option<Uuid> =
                sqlx::query_scalar("select id from packages where repo_id = $1 and name = $2")
                    .bind(repo_id)
                    .bind(pkg)
                    .fetch_optional(&mut *tx)
                    .await?;
            let Some(id) = id else {
                tx.rollback().await?;
                return Ok(None);
            };
            ids.push(id);
        }
        let key = generate_secret("sclk_");
        let license_id: Uuid = sqlx::query_scalar(
            "insert into license_keys (repo_id, key_hash, buyer_ref) values ($1, $2, $3) returning id",
        )
        .bind(repo_id)
        .bind(token_hash(&key))
        .bind(buyer)
        .fetch_one(&mut *tx)
        .await?;
        for id in ids {
            sqlx::query(
                "insert into entitlements (license_key_id, package_id) values ($1, $2) \
                 on conflict do nothing",
            )
            .bind(license_id)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(Some(key))
    }

    /// Entitle a license to a package owned by its repository. Returns `false`
    /// if no such package exists in the repo.
    pub async fn entitle_package(
        &self,
        license_id: Uuid,
        repo_id: Uuid,
        package: &str,
    ) -> Result<bool, sqlx::Error> {
        let Some(package_id): Option<Uuid> =
            sqlx::query_scalar("select id from packages where repo_id = $1 and name = $2")
                .bind(repo_id)
                .bind(package)
                .fetch_optional(&self.pool)
                .await?
        else {
            return Ok(false);
        };
        sqlx::query(
            "insert into entitlements (license_key_id, package_id) values ($1, $2) \
             on conflict do nothing",
        )
        .bind(license_id)
        .bind(package_id)
        .execute(&self.pool)
        .await?;
        Ok(true)
    }

    /// Validate a license key for a repository: active and unexpired. Returns the
    /// license id on success.
    pub async fn resolve_license(
        &self,
        repo_id: Uuid,
        key: &str,
    ) -> Result<Option<Uuid>, sqlx::Error> {
        sqlx::query_scalar(
            "select id from license_keys \
             where repo_id = $1 and key_hash = $2 and status = 'active' \
               and (expires_at is null or expires_at > now())",
        )
        .bind(repo_id)
        .bind(token_hash(key))
        .fetch_optional(&self.pool)
        .await
    }

    /// Validate a repo read token **and** return its policy override (a valid
    /// token with no override yields an empty [`PolicyOverride`]; an invalid /
    /// expired token yields `None`). Stamps `last_used_at`. Use this in the
    /// serving auth path so the credential's policy is resolved in one round-trip.
    pub async fn resolve_token_policy(
        &self,
        repo_id: Uuid,
        token: &str,
    ) -> Result<Option<PolicyOverride>, sqlx::Error> {
        let row = sqlx::query(
            "update tokens set last_used_at = now() \
             where repo_id = $1 and token_hash = $2 \
               and (expires_at is null or expires_at > now()) \
             returning update_mode, cooldown_days",
        )
        .bind(repo_id)
        .bind(token_hash(token))
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| PolicyOverride {
            update_mode: r.try_get("update_mode").ok().flatten(),
            cooldown_days: r.try_get("cooldown_days").ok().flatten(),
        }))
    }

    /// A license key's policy override (empty if none set).
    pub async fn license_policy(&self, license_id: Uuid) -> Result<PolicyOverride, sqlx::Error> {
        let row = sqlx::query("select update_mode, cooldown_days from license_keys where id = $1")
            .bind(license_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(PolicyOverride {
            update_mode: row.try_get("update_mode").ok().flatten(),
            cooldown_days: row.try_get("cooldown_days").ok().flatten(),
        })
    }

    /// Set (or clear, with `None`s) a token's policy override, by repo + label.
    /// Returns whether a token matched.
    pub async fn set_token_policy(
        &self,
        repo_id: Uuid,
        label: &str,
        policy: &PolicyOverride,
    ) -> Result<bool, sqlx::Error> {
        let n = sqlx::query(
            "update tokens set update_mode = $3, cooldown_days = $4 \
             where repo_id = $1 and label = $2",
        )
        .bind(repo_id)
        .bind(label)
        .bind(policy.update_mode.as_deref())
        .bind(policy.cooldown_days)
        .execute(&self.pool)
        .await?;
        Ok(n.rows_affected() > 0)
    }

    /// Set (or clear) a license key's policy override, by id.
    pub async fn set_license_policy(
        &self,
        repo_id: Uuid,
        license_id: Uuid,
        policy: &PolicyOverride,
    ) -> Result<bool, sqlx::Error> {
        let n = sqlx::query(
            "update license_keys set update_mode = $3, cooldown_days = $4 \
             where id = $1 and repo_id = $2",
        )
        .bind(license_id)
        .bind(repo_id)
        .bind(policy.update_mode.as_deref())
        .bind(policy.cooldown_days)
        .execute(&self.pool)
        .await?;
        Ok(n.rows_affected() > 0)
    }

    /// The package names a license is entitled to, sorted.
    pub async fn entitled_package_names(
        &self,
        license_id: Uuid,
    ) -> Result<Vec<String>, sqlx::Error> {
        let rows = sqlx::query(
            "select p.name from entitlements e \
             join packages p on p.id = e.package_id \
             where e.license_key_id = $1 order by p.name",
        )
        .bind(license_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(|r| r.try_get("name")).collect()
    }

    /// Grant `package` (owned by `source_repo`) into `target_repo`, so the target
    /// exposes it without owning it. Returns `false` if no such package exists in
    /// the source.
    pub async fn grant_package(
        &self,
        target_repo: Uuid,
        source_repo: Uuid,
        package: &str,
    ) -> Result<bool, sqlx::Error> {
        let Some(package_id): Option<Uuid> =
            sqlx::query_scalar("select id from packages where repo_id = $1 and name = $2")
                .bind(source_repo)
                .bind(package)
                .fetch_optional(&self.pool)
                .await?
        else {
            return Ok(false);
        };
        sqlx::query(
            "insert into repository_grants (repo_id, package_id) values ($1, $2) \
             on conflict do nothing",
        )
        .bind(target_repo)
        .bind(package_id)
        .execute(&self.pool)
        .await?;
        Ok(true)
    }

    /// All package names visible in a repository (owned ∪ granted), sorted — for
    /// `available-packages`.
    pub async fn all_package_names(&self, repo_id: Uuid) -> Result<Vec<String>, sqlx::Error> {
        // A public-only repo (allow_private_packages = false) hides private
        // packages — both its own and granted ones.
        let rows = sqlx::query(
            "select p.name from packages p \
             join repositories r on r.id = $1 \
             where p.repo_id = $1 \
               and (r.allow_private_packages or p.visibility = 'public') \
             union \
             select p.name from packages p \
             join repository_grants g on g.package_id = p.id \
             join repositories r on r.id = $1 \
             where g.repo_id = $1 \
               and (r.allow_private_packages or p.visibility = 'public') \
             order by name",
        )
        .bind(repo_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(|r| r.try_get("name")).collect()
    }

    /// All non-yanked versions of a package in a repository — the raw catalog
    /// view (ignores holds and update policy). Use [`Self::visible_versions`]
    /// for the serving read path.
    pub async fn package_versions(
        &self,
        repo_id: Uuid,
        name: &str,
    ) -> Result<Vec<PackageVersion>, sqlx::Error> {
        let rows = sqlx::query(
            "select pv.version, pv.normalized_version, pv.stability, pv.composer_json, \
                    pv.dist_blob_sha256, pv.dist_shasum, pv.source_reference \
             from package_versions pv \
             join packages p on p.id = pv.package_id \
             where p.repo_id = $1 and p.name = $2 and pv.yanked_at is null \
             order by pv.normalized_version",
        )
        .bind(repo_id)
        .bind(name)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(row_to_version).collect()
    }

    /// The versions of a package **visible** under an explicit update policy —
    /// the read path Composer serving builds on (the server passes its global
    /// policy in). A version is hidden if yanked or held; otherwise: `auto` →
    /// all visible; `manual` → only approved; `delayed` → visible once
    /// `released_at + cooldown_days` has passed (or it was approved early).
    ///
    /// Taking the policy as parameters (rather than reading the singleton here)
    /// keeps this pure and testable without mutating shared global state.
    pub async fn visible_versions(
        &self,
        repo_id: Uuid,
        name: &str,
        mode: &str,
        cooldown_days: i32,
    ) -> Result<Vec<PackageVersion>, sqlx::Error> {
        let rows = sqlx::query(
            "select pv.version, pv.normalized_version, pv.stability, pv.composer_json, \
                    pv.dist_blob_sha256, pv.dist_shasum, pv.source_reference \
             from package_versions pv \
             join packages p on p.id = pv.package_id \
             join repositories r on r.id = $1 \
             where p.name = $2 \
               and ( p.repo_id = $1 \
                     or exists (select 1 from repository_grants g \
                                where g.repo_id = $1 and g.package_id = p.id) ) \
               and (r.allow_private_packages or p.visibility = 'public') \
               and pv.yanked_at is null \
               and pv.held_at is null \
               and ( $3 = 'auto' \
                     or pv.approved_at is not null \
                     or ( $3 = 'delayed' \
                          and pv.released_at is not null \
                          and pv.released_at + make_interval(days => $4) <= now() ) ) \
             order by pv.normalized_version",
        )
        .bind(repo_id)
        .bind(name)
        .bind(mode)
        .bind(cooldown_days)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(row_to_version).collect()
    }

    /// A repository's update policy: `(update_mode, cooldown_days)`.
    pub async fn update_policy(&self, repo_id: Uuid) -> Result<(String, i32), sqlx::Error> {
        let row = sqlx::query("select update_mode, cooldown_days from repositories where id = $1")
            .bind(repo_id)
            .fetch_one(&self.pool)
            .await?;
        Ok((row.try_get("update_mode")?, row.try_get("cooldown_days")?))
    }

    /// Set a repository's update policy. `mode` must be `auto`/`manual`/`delayed`
    /// (enforced by a check constraint).
    pub async fn set_update_policy(
        &self,
        repo_id: Uuid,
        mode: &str,
        cooldown_days: i32,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("update repositories set update_mode = $1, cooldown_days = $2 where id = $3")
            .bind(mode)
            .bind(cooldown_days)
            .bind(repo_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Place a security hold on a version (hides it immediately). Returns whether
    /// a matching version was found in the repository.
    pub async fn hold_version(
        &self,
        repo_id: Uuid,
        package: &str,
        normalized_version: &str,
    ) -> Result<bool, sqlx::Error> {
        self.set_version_timestamp("held_at", "now()", repo_id, package, normalized_version)
            .await
    }

    /// Release a hold.
    pub async fn unhold_version(
        &self,
        repo_id: Uuid,
        package: &str,
        normalized_version: &str,
    ) -> Result<bool, sqlx::Error> {
        self.set_version_timestamp("held_at", "null", repo_id, package, normalized_version)
            .await
    }

    /// Yank a version: withdraw a bad/compromised release permanently (hides it
    /// like a hold, but signals "this version is withdrawn", not "pending
    /// review"). Reversible via [`Self::unyank_version`].
    pub async fn yank_version(
        &self,
        repo_id: Uuid,
        package: &str,
        normalized_version: &str,
    ) -> Result<bool, sqlx::Error> {
        self.set_version_timestamp("yanked_at", "now()", repo_id, package, normalized_version)
            .await
    }

    /// Reinstate a yanked version.
    pub async fn unyank_version(
        &self,
        repo_id: Uuid,
        package: &str,
        normalized_version: &str,
    ) -> Result<bool, sqlx::Error> {
        self.set_version_timestamp("yanked_at", "null", repo_id, package, normalized_version)
            .await
    }

    /// Approve a version (makes it visible under `manual`, or early under
    /// `delayed`).
    pub async fn approve_version(
        &self,
        repo_id: Uuid,
        package: &str,
        normalized_version: &str,
    ) -> Result<bool, sqlx::Error> {
        self.set_version_timestamp("approved_at", "now()", repo_id, package, normalized_version)
            .await
    }

    /// Set `held_at`/`approved_at` to `now()`/`null` for one version in a repo.
    /// `column` and `value` are fixed literals chosen by the callers above —
    /// never user input — so interpolating them is safe.
    async fn set_version_timestamp(
        &self,
        column: &str,
        value: &str,
        repo_id: Uuid,
        package: &str,
        normalized_version: &str,
    ) -> Result<bool, sqlx::Error> {
        let sql = format!(
            "update package_versions pv set {column} = {value} \
             from packages p \
             where p.id = pv.package_id and p.repo_id = $1 and p.name = $2 \
               and pv.normalized_version = $3"
        );
        let done = sqlx::query(&sql)
            .bind(repo_id)
            .bind(package)
            .bind(normalized_version)
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() > 0)
    }
}

/// Combine two optional TTL caps into the tighter one: `None` means "no cap"
/// (infinity), so the result is the smaller of any present values.
fn min_cap(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (only, None) | (None, only) => only,
    }
}

/// A fresh, high-entropy read token (`sconce_` prefix).
fn generate_token() -> String {
    generate_secret("sconce_")
}

/// A fresh, high-entropy secret with the given prefix for recognizability.
/// Randomness comes from two v4 UUIDs (CSPRNG-backed) — 32 bytes, hex-encoded.
fn generate_secret(prefix: &str) -> String {
    use std::fmt::Write as _;
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    let mut s = String::with_capacity(prefix.len() + 64);
    s.push_str(prefix);
    for byte in a.as_bytes().iter().chain(b.as_bytes()) {
        let _ = write!(s, "{byte:02x}");
    }
    s
}

/// sha256 of a token — what we store and compare against.
fn token_hash(token: &str) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(token.as_bytes()).to_vec()
}

/// Hash a (low-entropy) user password with argon2 → a PHC string for storage.
fn hash_password(password: &str) -> String {
    use argon2::Argon2;
    use argon2::password_hash::{PasswordHasher, SaltString, rand_core::OsRng};
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("argon2 hashing")
        .to_string()
}

/// Verify a password against a stored argon2 PHC string.
fn verify_password(password: &str, phc: &str) -> bool {
    use argon2::Argon2;
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    PasswordHash::new(phc).is_ok_and(|parsed| {
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    })
}

/// Apply pending migrations on a connection already holding the advisory lock.
async fn run_migrations(conn: &mut sqlx::PgConnection) -> Result<(), sqlx::Error> {
    use sqlx::Connection;

    sqlx::query(
        "create table if not exists _sconce_migrations (\
             name text primary key, \
             applied_at timestamptz not null default now())",
    )
    .execute(&mut *conn)
    .await?;

    for (name, sql) in MIGRATIONS {
        let already: Option<String> =
            sqlx::query_scalar("select name from _sconce_migrations where name = $1")
                .bind(name)
                .fetch_optional(&mut *conn)
                .await?;
        if already.is_some() {
            continue;
        }
        let mut tx = conn.begin().await?;
        // `raw_sql` uses the simple query protocol, so a migration file may
        // contain multiple statements.
        sqlx::raw_sql(sql).execute(&mut *tx).await?;
        sqlx::query("insert into _sconce_migrations (name) values ($1)")
            .bind(name)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
    }
    Ok(())
}

/// Map a row to a [`PackageVersion`] by column name (no derive macros).
fn row_to_version(row: &sqlx::postgres::PgRow) -> Result<PackageVersion, sqlx::Error> {
    let dist: Option<Vec<u8>> = row.try_get("dist_blob_sha256")?;
    let dist_blob_sha256 = dist.map(|v| {
        let mut a = [0u8; 32];
        // A sha256 column is always 32 bytes; truncate/pad defensively rather
        // than panic if somehow not.
        let n = v.len().min(32);
        a[..n].copy_from_slice(&v[..n]);
        a
    });
    Ok(PackageVersion {
        version: row.try_get("version")?,
        normalized_version: row.try_get("normalized_version")?,
        stability: row.try_get("stability")?,
        composer_json: row.try_get("composer_json")?,
        dist_blob_sha256,
        dist_shasum: row.try_get("dist_shasum")?,
        source_reference: row.try_get("source_reference")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Tests need a Postgres; they're skipped unless `DATABASE_URL` is set, so
    /// `cargo test` stays green on machines without one. CI sets it against a
    /// postgres service. Each test gets its own fresh repository, so they're
    /// fully isolated and can't collide on names or policy.
    async fn repo() -> Option<(Catalog, Uuid)> {
        static C: AtomicU64 = AtomicU64::new(0);
        let url = std::env::var("DATABASE_URL").ok()?;
        let cat = Catalog::connect(&url).await.expect("connect");
        cat.migrate().await.expect("migrate");
        let n = C.fetch_add(1, Ordering::Relaxed);
        let slug = format!("t{}-{n}", std::process::id());
        cat.create_org(&slug, None).await.expect("org");
        let repo_id = cat.create_repo(&slug, "r").await.expect("repo");
        Some((cat, repo_id))
    }

    /// Serialize queue tests across processes (the job queue is global, and test
    /// binaries run in parallel against one DB) and give each a clean slate. The
    /// returned connection holds a Postgres advisory lock until dropped.
    async fn queue_guard() -> sqlx::PgConnection {
        use sqlx::Connection as _;
        let url = std::env::var("DATABASE_URL").expect("DATABASE_URL");
        let mut conn = sqlx::PgConnection::connect(&url).await.expect("guard conn");
        sqlx::query("select pg_advisory_lock(778899)")
            .execute(&mut conn)
            .await
            .expect("advisory lock");
        sqlx::query("delete from mirror_jobs")
            .execute(&mut conn)
            .await
            .expect("clear jobs");
        conn
    }

    #[tokio::test]
    async fn migrate_is_idempotent() {
        let Some((cat, _)) = repo().await else { return };
        cat.migrate().await.expect("re-migrate");
    }

    #[tokio::test]
    async fn upsert_and_read_back_a_version() {
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        let sha = [7u8; 32];
        cat.upsert_blob(&sha, 1234).await.unwrap();

        let pkg = cat
            .upsert_package(
                repo_id,
                "acme/lib",
                "git",
                Some(&serde_json::json!({"git": "https://x/y"})),
                Visibility::Private,
            )
            .await
            .unwrap();

        let cj = serde_json::json!({"name": "acme/lib", "version": "1.2.0"});
        cat.upsert_package_version(
            pkg,
            "v1.2.0",
            "1.2.0.0",
            "stable",
            &cj,
            Some(&sha),
            Some("da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            Some("abc123"),
            None,
        )
        .await
        .unwrap();

        let versions = cat.package_versions(repo_id, "acme/lib").await.unwrap();
        assert_eq!(versions.len(), 1);
        let v = &versions[0];
        assert_eq!(v.version, "v1.2.0");
        assert_eq!(v.dist_blob_sha256, Some(sha));
        assert_eq!(
            v.dist_shasum.as_deref(),
            Some("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        );
        assert_eq!(v.source_reference.as_deref(), Some("abc123"));
        assert_eq!(v.composer_json, cj);
    }

    #[tokio::test]
    async fn repos_are_isolated() {
        let Some((cat, repo_a)) = repo().await else {
            return;
        };
        let repo_b = {
            // A second repo in a fresh org.
            let (_, b) = repo().await.unwrap();
            b
        };
        let cj = serde_json::json!({"name": "shared/name"});
        // The SAME package name in two repos is two independent packages.
        let pa = cat
            .upsert_package(repo_a, "shared/name", "git", None, Visibility::Private)
            .await
            .unwrap();
        let pb = cat
            .upsert_package(repo_b, "shared/name", "git", None, Visibility::Private)
            .await
            .unwrap();
        assert_ne!(pa, pb);
        cat.upsert_package_version(
            pa, "v1.0.0", "1.0.0.0", "stable", &cj, None, None, None, None,
        )
        .await
        .unwrap();

        // The version exists only in repo_a; repo_b's same-named package has none.
        assert_eq!(
            cat.package_versions(repo_a, "shared/name")
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(
            cat.package_versions(repo_b, "shared/name")
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            cat.all_package_names(repo_a).await.unwrap(),
            ["shared/name"]
        );
        assert_eq!(
            cat.all_package_names(repo_b).await.unwrap(),
            ["shared/name"]
        );
    }

    /// The supply-chain controls, now per-repo: cooldown hides fresh releases,
    /// holds hide any version, approval reveals early.
    #[tokio::test]
    async fn cooldown_hold_and_approval_gate_visibility() {
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        let pkg = cat
            .upsert_package(repo_id, "acme/lib", "git", None, Visibility::Private)
            .await
            .unwrap();
        let cj = serde_json::json!({"name": "acme/lib"});
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
        let day = 86_400;

        cat.upsert_package_version(
            pkg,
            "v1.0.0",
            "1.0.0.0",
            "stable",
            &cj,
            None,
            None,
            None,
            Some(now - 30 * day),
        )
        .await
        .unwrap();
        cat.upsert_package_version(
            pkg,
            "v1.1.0",
            "1.1.0.0",
            "stable",
            &cj,
            None,
            None,
            None,
            Some(now),
        )
        .await
        .unwrap();

        let norm = |vs: Vec<PackageVersion>| -> Vec<String> {
            vs.into_iter().map(|v| v.normalized_version).collect()
        };
        let p = "acme/lib";

        assert_eq!(
            norm(cat.visible_versions(repo_id, p, "auto", 0).await.unwrap()),
            ["1.0.0.0", "1.1.0.0"]
        );
        assert_eq!(
            norm(
                cat.visible_versions(repo_id, p, "delayed", 7)
                    .await
                    .unwrap()
            ),
            ["1.0.0.0"]
        );

        assert!(cat.approve_version(repo_id, p, "1.1.0.0").await.unwrap());
        assert_eq!(
            norm(
                cat.visible_versions(repo_id, p, "delayed", 7)
                    .await
                    .unwrap()
            ),
            ["1.0.0.0", "1.1.0.0"]
        );
        assert_eq!(
            norm(cat.visible_versions(repo_id, p, "manual", 0).await.unwrap()),
            ["1.1.0.0"]
        );

        assert!(cat.hold_version(repo_id, p, "1.0.0.0").await.unwrap());
        assert_eq!(
            norm(cat.visible_versions(repo_id, p, "auto", 0).await.unwrap()),
            ["1.1.0.0"]
        );
        assert!(cat.unhold_version(repo_id, p, "1.0.0.0").await.unwrap());
        assert_eq!(
            norm(cat.visible_versions(repo_id, p, "auto", 0).await.unwrap()),
            ["1.0.0.0", "1.1.0.0"]
        );

        // Yank hides a version unconditionally (even though it was approved); a
        // prior approval doesn't override a yank. Un-yank reinstates it.
        assert!(cat.yank_version(repo_id, p, "1.1.0.0").await.unwrap());
        assert_eq!(
            norm(cat.visible_versions(repo_id, p, "auto", 0).await.unwrap()),
            ["1.0.0.0"]
        );
        assert!(cat.unyank_version(repo_id, p, "1.1.0.0").await.unwrap());

        // The operator view's countdown matches serving: under a 7-day cooldown
        // the 30-day-old version is past (0 left) while the just-released one has
        // ~7 days to go. (We set this repo's policy so admin_package_versions
        // computes against the real cooldown_days.)
        cat.set_update_policy(repo_id, "delayed", 7).await.unwrap();
        let av = cat.admin_package_versions(repo_id).await.unwrap();
        let old = av.iter().find(|v| v.normalized_version == "1.0.0.0").unwrap();
        let fresh = av.iter().find(|v| v.normalized_version == "1.1.0.0").unwrap();
        assert_eq!(old.cooldown_days_left, Some(0), "30-day-old is past cooldown");
        assert!(
            matches!(fresh.cooldown_days_left, Some(n) if (1..=7).contains(&n)),
            "fresh release counts down (got {:?})",
            fresh.cooldown_days_left
        );
        assert!(fresh.approved, "approved flag surfaces in the operator view");
    }

    #[tokio::test]
    async fn update_policy_is_per_repo() {
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        assert_eq!(
            cat.update_policy(repo_id).await.unwrap(),
            ("auto".to_owned(), 0)
        );
        cat.set_update_policy(repo_id, "delayed", 5).await.unwrap();
        assert_eq!(
            cat.update_policy(repo_id).await.unwrap(),
            ("delayed".to_owned(), 5)
        );
    }

    #[test]
    fn policy_override_tightens_only() {
        let none = PolicyOverride::default();
        assert_eq!(none.effective("auto", 0), ("auto".to_owned(), 0));
        assert_eq!(none.effective("delayed", 7), ("delayed".to_owned(), 7));

        // A bare cooldown override implies `delayed` (cooldown is meaningless
        // under auto) and tightens auto -> delayed/30.
        let cd30 = PolicyOverride { update_mode: None, cooldown_days: Some(30) };
        assert_eq!(cd30.effective("auto", 0), ("delayed".to_owned(), 30));

        // mode tighten: auto -> manual.
        let man = PolicyOverride { update_mode: Some("manual".into()), cooldown_days: None };
        assert_eq!(man.effective("auto", 0), ("manual".to_owned(), 0));

        // Tighten-only: a looser override can NEVER weaken the repo default.
        let loose = PolicyOverride { update_mode: Some("auto".into()), cooldown_days: Some(1) };
        assert_eq!(loose.effective("manual", 14), ("manual".to_owned(), 14));

        // Cooldown takes the max of repo and override.
        let cd5 = PolicyOverride { update_mode: Some("delayed".into()), cooldown_days: Some(5) };
        assert_eq!(cd5.effective("delayed", 10), ("delayed".to_owned(), 10));
    }

    #[tokio::test]
    async fn per_credential_policy_tightens_serving() {
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        let pkg = cat
            .upsert_package(repo_id, "acme/lib", "git", None, Visibility::Private)
            .await
            .unwrap();
        let cj = serde_json::json!({"name": "acme/lib"});
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
        let day = 86_400;
        for (v, n, rel) in [("v1.0.0", "1.0.0.0", now - 30 * day), ("v1.1.0", "1.1.0.0", now)] {
            cat.upsert_package_version(pkg, v, n, "stable", &cj, None, None, None, Some(rel))
                .await
                .unwrap();
        }
        let p = "acme/lib";
        // Repo default is `auto`: a plain token sees both versions.
        let plain = cat.create_token(repo_id, Some("latest"), None).await.unwrap();
        let pp = cat.resolve_token_policy(repo_id, &plain).await.unwrap().unwrap();
        let (m, c) = pp.effective("auto", 0);
        assert_eq!(cat.visible_versions(repo_id, p, &m, c).await.unwrap().len(), 2);

        // A conservative token (delayed/7) on the SAME repo hides the fresh one.
        let cons = cat.create_token(repo_id, Some("conservative"), None).await.unwrap();
        assert!(
            cat.set_token_policy(
                repo_id,
                "conservative",
                &PolicyOverride { update_mode: Some("delayed".into()), cooldown_days: Some(7) },
            )
            .await
            .unwrap()
        );
        let cp = cat.resolve_token_policy(repo_id, &cons).await.unwrap().unwrap();
        let (m2, c2) = cp.effective("auto", 0);
        assert_eq!((m2.as_str(), c2), ("delayed", 7));
        let vis = cat.visible_versions(repo_id, p, &m2, c2).await.unwrap();
        assert_eq!(vis.len(), 1, "conservative credential only sees the aged release");
        assert_eq!(vis[0].normalized_version, "1.0.0.0");

        // An invalid/expired token resolves to no policy at all.
        assert!(cat.resolve_token_policy(repo_id, "sconce_bogus").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn tokens_are_scoped_to_their_repo() {
        let Some((cat, repo_a)) = repo().await else {
            return;
        };
        let (_, repo_b) = repo().await.unwrap();
        let token = cat.create_token(repo_a, None, None).await.unwrap();
        assert!(
            cat.token_valid(repo_a, &token).await.unwrap(),
            "valid for its repo"
        );
        assert!(
            !cat.token_valid(repo_b, &token).await.unwrap(),
            "not valid for another repo"
        );
    }

    #[tokio::test]
    async fn org_settings_gate_token_creation() {
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        // Find the org owning this repo (repo() makes a fresh org per repo).
        let org_id = cat
            .list_repositories()
            .await
            .unwrap()
            .into_iter()
            .find(|r| r.id == repo_id)
            .unwrap()
            .org_id;

        // Default: raw tokens allowed, no TTL cap.
        assert!(cat.create_token(repo_id, None, None).await.is_ok());

        // Cap TTL at 30 days: a non-expiring or over-cap token is refused.
        cat.set_org_settings(
            org_id,
            OrgSettings {
                allow_raw_tokens: true,
                max_token_ttl_days: Some(30),
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            cat.create_token(repo_id, None, None).await,
            Err(CreateTokenError::Policy(_))
        ));
        assert!(matches!(
            cat.create_token(repo_id, None, Some(60)).await,
            Err(CreateTokenError::Policy(_))
        ));
        assert!(cat.create_token(repo_id, None, Some(7)).await.is_ok());

        // Disable raw tokens entirely: even a well-formed request is refused.
        cat.set_org_settings(
            org_id,
            OrgSettings {
                allow_raw_tokens: false,
                max_token_ttl_days: None,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            cat.create_token(repo_id, None, Some(7)).await,
            Err(CreateTokenError::Policy(_))
        ));
    }

    #[tokio::test]
    async fn repo_settings_can_only_tighten_org_policy() {
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        let org_id = cat
            .list_repositories()
            .await
            .unwrap()
            .into_iter()
            .find(|r| r.id == repo_id)
            .unwrap()
            .org_id;

        // Org: raw allowed, cap 90 days.
        cat.set_org_settings(
            org_id,
            OrgSettings {
                allow_raw_tokens: true,
                max_token_ttl_days: Some(90),
            },
        )
        .await
        .unwrap();

        // Repo tightens: cap 30 days. Effective = min(90, 30) = 30.
        cat.set_repo_settings(
            repo_id,
            RepoSettings {
                allow_raw_tokens: None,
                max_token_ttl_days: Some(30),
                ..RepoSettings::default()
            },
        )
        .await
        .unwrap();
        let eff = cat.effective_token_policy(repo_id).await.unwrap();
        assert_eq!(eff.max_token_ttl_days, Some(30));
        assert!(eff.allow_raw_tokens);
        // 60 > 30 effective → refused; 14 ok.
        assert!(matches!(
            cat.create_token(repo_id, None, Some(60)).await,
            Err(CreateTokenError::Policy(_))
        ));
        assert!(cat.create_token(repo_id, None, Some(14)).await.is_ok());

        // Repo tries to LOOSEN: cap 365 > org 90. Effective still 90 (can't loosen).
        cat.set_repo_settings(
            repo_id,
            RepoSettings {
                allow_raw_tokens: Some(true),
                max_token_ttl_days: Some(365),
                ..RepoSettings::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            cat.effective_token_policy(repo_id)
                .await
                .unwrap()
                .max_token_ttl_days,
            Some(90),
            "repo cannot raise the cap above the org's"
        );

        // Org disables raw tokens; repo 'allow' cannot re-enable.
        cat.set_org_settings(
            org_id,
            OrgSettings {
                allow_raw_tokens: false,
                max_token_ttl_days: None,
            },
        )
        .await
        .unwrap();
        assert!(
            !cat.effective_token_policy(repo_id)
                .await
                .unwrap()
                .allow_raw_tokens,
            "repo 'allow' cannot override an org disable"
        );
    }

    #[tokio::test]
    async fn upstream_crud_keeps_credentials_out_of_listing() {
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        // Public upstream, no credential.
        let pubid = cat
            .create_upstream(repo_id, "composer", "https://repo.packagist.org", Visibility::Public, Some("packagist"), None, "basic")
            .await
            .unwrap();
        // Private upstream with an (already-encrypted) credential blob.
        let privid = cat
            .create_upstream(repo_id, "git", "https://git/x.git", Visibility::Private, None, Some(b"enc"), "basic")
            .await
            .unwrap();

        let list = cat.list_upstreams(repo_id).await.unwrap();
        assert_eq!(list.len(), 2);
        let pub_s = list.iter().find(|u| u.id == pubid).unwrap();
        assert_eq!(pub_s.visibility, "public");
        assert!(!pub_s.has_credential);
        let priv_s = list.iter().find(|u| u.id == privid).unwrap();
        assert!(priv_s.has_credential, "private upstream has a credential");

        // get_upstream returns the ciphertext (for mirroring); visibility parsed.
        let got = cat.get_upstream(privid).await.unwrap().unwrap();
        assert_eq!(got.visibility, Visibility::Private);
        assert_eq!(got.credential.as_deref(), Some(&b"enc"[..]));

        // Remove is repo-scoped.
        assert!(cat.delete_upstream(repo_id, pubid).await.unwrap());
        assert_eq!(cat.list_upstreams(repo_id).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn job_kinds_and_dependency_plan() {
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        let _guard = queue_guard().await;
        let up = cat
            .create_upstream(repo_id, "composer", "https://x", Visibility::Public, None, None, "basic")
            .await
            .unwrap();

        // Generalized queue: each kind enqueues + claims with its fields.
        cat.enqueue_resolve_closure_job(repo_id).await.unwrap();
        cat.enqueue_mirror_package_job(up, "vendor/pkg").await.unwrap();
        let mut kinds = vec![];
        for _ in 0..2 {
            let j = cat.claim_mirror_job().await.unwrap().unwrap();
            match j.kind.as_str() {
                "mirror_package" => {
                    assert_eq!(j.upstream_id, Some(up));
                    assert_eq!(j.package.as_deref(), Some("vendor/pkg"));
                }
                "resolve_closure" => assert_eq!(j.repo_id, Some(repo_id)),
                other => panic!("unexpected kind {other}"),
            }
            kinds.push(j.kind);
        }
        assert!(kinds.iter().any(|k| k == "resolve_closure"));
        assert!(kinds.iter().any(|k| k == "mirror_package"));
        assert!(cat.claim_mirror_job().await.unwrap().is_none());

        // Dependency plan: replace (idempotent) / list / lookup.
        let entries = vec![
            DependencyPlanEntry {
                name: "a/b".to_owned(),
                status: "resolvable-public".to_owned(),
                resolver_upstream_id: Some(up),
                required_by: Some("x/y".to_owned()),
            },
            DependencyPlanEntry {
                name: "c/d".to_owned(),
                status: "missing".to_owned(),
                resolver_upstream_id: None,
                required_by: Some("x/y".to_owned()),
            },
        ];
        cat.replace_dependency_plan(repo_id, &entries).await.unwrap();
        cat.replace_dependency_plan(repo_id, &entries).await.unwrap(); // idempotent
        assert_eq!(cat.list_dependency_plan(repo_id).await.unwrap().len(), 2);
        let ab = cat.dependency_plan_entry(repo_id, "a/b").await.unwrap().unwrap();
        assert_eq!(ab.resolver_upstream_id, Some(up));
        assert!(cat.dependency_plan_entry(repo_id, "nope/x").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn scim_provision_then_deactivate_offboards() {
        let Some((cat, _)) = repo().await else {
            return;
        };
        let slug = format!("sc{}", std::process::id());
        let org_id = cat.create_org(&slug, None).await.unwrap();
        let email = format!("sc{}@x.io", std::process::id());

        // Token round-trips to its org.
        let tok = cat.create_scim_token(&slug).await.unwrap().unwrap();
        assert_eq!(cat.resolve_scim_token(&tok).await.unwrap(), Some(org_id));

        // Provision → active member; resolvable by id and userName.
        let uid = cat.scim_provision(org_id, &email).await.unwrap();
        assert_eq!(cat.scim_member(org_id, uid).await.unwrap(), Some((email.clone(), true)));
        assert_eq!(cat.scim_member_by_email(org_id, &email).await.unwrap(), Some((uid, true)));

        // The provisioned user has an active membership → a session sees the org.
        let session = cat.create_session(uid, 1).await.unwrap();
        assert!(
            cat.resolve_session(&session).await.unwrap().unwrap().tenant_org_ids.contains(&org_id)
        );

        // Deactivate (the offboarding action) + revoke sessions.
        assert!(cat.scim_set_active(org_id, uid, false).await.unwrap());
        assert_eq!(cat.delete_user_sessions(uid).await.unwrap(), 1);
        // Session gone, and even a fresh session sees no active membership.
        assert!(cat.resolve_session(&session).await.unwrap().is_none());
        let s2 = cat.create_session(uid, 1).await.unwrap();
        assert!(
            !cat.resolve_session(&s2).await.unwrap().unwrap().tenant_org_ids.contains(&org_id),
            "deactivated membership grants no access"
        );
        // SCIM still reports the user, now inactive.
        assert_eq!(cat.scim_member(org_id, uid).await.unwrap(), Some((email, false)));
    }

    #[tokio::test]
    async fn tenant_roles_resolve_through_the_session() {
        let Some((cat, _)) = repo().await else {
            return;
        };
        let slug = format!("ro{}", std::process::id());
        cat.create_org(&slug, None).await.unwrap();
        let email = format!("u{}@x.io", std::process::id());
        let uid = cat.create_user(&email, "pw", false).await.unwrap();

        // Grant as member → membership but not admin.
        assert!(cat.add_user_to_tenant(&email, &slug, "member").await.unwrap());
        let token = cat.create_session(uid, 1).await.unwrap();
        let au = cat.resolve_session(&token).await.unwrap().unwrap();
        let org_id = au.tenant_org_ids[0];
        assert!(au.tenant_org_ids.contains(&org_id));
        assert!(!au.admin_org_ids.contains(&org_id), "member is not admin");

        // Upsert to admin → now in admin set.
        assert!(cat.add_user_to_tenant(&email, &slug, "admin").await.unwrap());
        let au = cat.resolve_session(&token).await.unwrap().unwrap();
        assert!(au.admin_org_ids.contains(&org_id), "now admin");
    }

    #[tokio::test]
    async fn oidc_connection_and_flow_round_trip() {
        let Some((cat, _)) = repo().await else {
            return;
        };
        // Connection set/get (replaces any existing instance connection).
        let conn = OidcConnection {
            id: Uuid::nil(),
            org_slug: None,
            issuer_url: "https://idp.example.com".to_owned(),
            client_id: "sconce".to_owned(),
            client_secret: Some(b"enc-secret".to_vec()),
            redirect_url: "https://host/auth/callback".to_owned(),
            scopes: "openid email".to_owned(),
            allowed_domains: Some(vec!["acme.com".to_owned()]),
            admin_domains: None,
        };
        cat.set_oidc_connection(None, &conn).await.unwrap();
        let got = cat.oidc_connection().await.unwrap().unwrap();
        assert_eq!(got.client_id, "sconce");
        assert_eq!(got.client_secret.as_deref(), Some(&b"enc-secret"[..]));
        assert_eq!(got.allowed_domains.as_deref(), Some(&["acme.com".to_owned()][..]));
        assert!(got.org_slug.is_none(), "instance connection");
        // Routing an unknown domain falls back to the instance default.
        assert_eq!(
            cat.oidc_connection_for_email("x@nowhere.test").await.unwrap(),
            Some(got.id)
        );

        // Flow create → consume (single-use, carries conn_id) → gone.
        cat.create_oidc_flow("state-1", Some(got.id), "nonce-1", "verifier-1", "/repos", 600)
            .await
            .unwrap();
        let f = cat.consume_oidc_flow("state-1").await.unwrap().unwrap();
        assert_eq!(
            f,
            (Some(got.id), "nonce-1".to_owned(), "verifier-1".to_owned(), "/repos".to_owned())
        );
        assert!(cat.consume_oidc_flow("state-1").await.unwrap().is_none(), "single-use");

        // Expired flow is not consumable.
        cat.create_oidc_flow("state-exp", None, "n", "v", "/", -1).await.unwrap();
        assert!(cat.consume_oidc_flow("state-exp").await.unwrap().is_none());

        // JIT user: idempotent by email, superadmin updatable.
        let id1 = cat.find_or_create_sso_user("sso@acme.com", false).await.unwrap();
        let id2 = cat.find_or_create_sso_user("sso@acme.com", true).await.unwrap();
        assert_eq!(id1, id2, "same email = same user");
    }

    #[tokio::test]
    async fn upstream_package_filter_round_trips() {
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        let id = cat
            .create_upstream(repo_id, "composer", "https://repo.mage-os.org", Visibility::Public, None, None, "basic")
            .await
            .unwrap();
        // Default: no filter.
        assert!(cat.get_upstream(id).await.unwrap().unwrap().package_filter.is_none());
        // Set, then clear.
        cat.set_upstream_filter(repo_id, id, Some("^mage-os/")).await.unwrap();
        assert_eq!(
            cat.get_upstream(id).await.unwrap().unwrap().package_filter.as_deref(),
            Some("^mage-os/")
        );
        let listed = cat.list_upstreams(repo_id).await.unwrap();
        assert_eq!(listed[0].package_filter.as_deref(), Some("^mage-os/"));
        cat.set_upstream_filter(repo_id, id, None).await.unwrap();
        assert!(cat.get_upstream(id).await.unwrap().unwrap().package_filter.is_none());
    }

    #[tokio::test]
    async fn public_upstream_drops_any_credential() {
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        // A credential passed for a PUBLIC upstream must not be stored.
        let id = cat
            .create_upstream(
                repo_id,
                "composer",
                "https://repo.packagist.org",
                Visibility::Public,
                None,
                Some(b"should-be-dropped"),
                "github",
            )
            .await
            .unwrap();
        let got = cat.get_upstream(id).await.unwrap().unwrap();
        assert!(got.credential.is_none(), "public upstream stores no credential");
        let listed = cat.list_upstreams(repo_id).await.unwrap();
        assert!(!listed.iter().find(|u| u.id == id).unwrap().has_credential);
    }

    #[tokio::test]
    async fn package_lifecycle_broken_synced_archived() {
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        let name = "vendor/lifecycle";
        cat.upsert_package(repo_id, name, "composer", None, Visibility::Private)
            .await
            .unwrap();

        // Fresh package: healthy, not archived, no broken info.
        let p = &cat.list_packages(repo_id).await.unwrap()[0];
        assert_eq!(p.sync_health, "ok");
        assert!(!p.archived);
        assert!(p.broken_reason.is_none() && p.last_success_at.is_none());

        // A terminal failure flags an existing package; a missing one is a no-op.
        assert!(cat.mark_package_broken(repo_id, name, "source_gone").await.unwrap());
        assert!(!cat.mark_package_broken(repo_id, "vendor/nope", "x").await.unwrap());
        let p = &cat.list_packages(repo_id).await.unwrap()[0];
        assert_eq!(p.sync_health, "broken");
        assert_eq!(p.broken_reason.as_deref(), Some("source_gone"));
        assert!(p.broken_at.is_some());

        // A successful sync clears broken and stamps last_success_at.
        cat.mark_package_synced(repo_id, name).await.unwrap();
        let p = &cat.list_packages(repo_id).await.unwrap()[0];
        assert_eq!(p.sync_health, "ok");
        assert!(p.broken_reason.is_none() && p.broken_at.is_none());
        assert!(p.last_success_at.is_some());

        // Archiving masks the broken flag: a later terminal failure won't re-flag.
        cat.mark_package_broken(repo_id, name, "source_gone").await.unwrap();
        assert!(cat.archive_package(repo_id, name).await.unwrap());
        assert!(
            !cat.mark_package_broken(repo_id, name, "source_gone").await.unwrap(),
            "archived packages are not re-flagged"
        );
        assert!(cat.list_packages(repo_id).await.unwrap()[0].archived);

        // Un-archive resumes normal handling.
        assert!(cat.unarchive_package(repo_id, name).await.unwrap());
        assert!(!cat.list_packages(repo_id).await.unwrap()[0].archived);
    }

    #[tokio::test]
    async fn mirror_job_queue_enqueues_claims_and_dedupes() {
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        let _guard = queue_guard().await;
        let up = cat
            .create_upstream(repo_id, "git", "https://git/x.git", Visibility::Private, None, None, "basic")
            .await
            .unwrap();

        // First enqueue creates a job; a second is deduped while one is pending.
        assert!(cat.enqueue_mirror_job(up).await.unwrap(), "first enqueue");
        assert!(
            !cat.enqueue_mirror_job(up).await.unwrap(),
            "deduped while a pending job exists"
        );

        // Claim it: status running, attempt 1. No second job is claimable.
        let job = cat.claim_mirror_job().await.unwrap().expect("a job to claim");
        assert_eq!(job.upstream_id, Some(up));
        assert_eq!(job.kind, "mirror_upstream");
        assert_eq!(job.attempts, 1);
        assert!(
            cat.claim_mirror_job().await.unwrap().is_none(),
            "nothing else claimable"
        );

        // Complete it; a fresh enqueue is now allowed (prior job is 'ready').
        cat.complete_mirror_job(job.id).await.unwrap();
        assert!(cat.enqueue_mirror_job(up).await.unwrap(), "re-enqueue after ready");

        // Claim + reschedule with backoff → not immediately claimable again.
        let job2 = cat.claim_mirror_job().await.unwrap().unwrap();
        cat.retry_mirror_job(job2.id, 60.0, "boom").await.unwrap();
        assert!(
            cat.claim_mirror_job().await.unwrap().is_none(),
            "retry backoff hides the job"
        );
        // The failure is visible on the upstream listing.
        let listed = cat.list_upstreams(repo_id).await.unwrap();
        let u = listed.iter().find(|u| u.id == up).unwrap();
        assert_eq!(u.job_status.as_deref(), Some("pending"));
        assert_eq!(u.job_error.as_deref(), Some("boom"));
    }

    #[tokio::test]
    async fn public_only_repo_rejects_and_hides_private_packages() {
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        let ver = async |cat: &Catalog, pkg: Uuid, name: &str| {
            cat.upsert_package_version(
                pkg,
                "v1.0.0",
                "1.0.0.0",
                "stable",
                &serde_json::json!({ "name": name }),
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        };

        // Default allows private: add one and confirm it serves.
        let pkg = cat
            .upsert_package(repo_id, "acme/lib", "git", None, Visibility::Private)
            .await
            .unwrap();
        ver(&cat, pkg, "acme/lib").await;
        assert_eq!(cat.all_package_names(repo_id).await.unwrap(), ["acme/lib"]);

        // Flip to public-only.
        let mut s = cat.repo_settings(repo_id).await.unwrap();
        s.allow_private_packages = false;
        cat.set_repo_settings(repo_id, s).await.unwrap();

        // The existing private package is now hidden from both serve paths.
        assert!(cat.all_package_names(repo_id).await.unwrap().is_empty());
        assert!(
            cat.visible_versions(repo_id, "acme/lib", "auto", 0)
                .await
                .unwrap()
                .is_empty()
        );

        // Adding another private package is refused.
        assert!(matches!(
            cat.upsert_package(repo_id, "acme/two", "git", None, Visibility::Private)
                .await,
            Err(UpsertPackageError::Policy(_))
        ));

        // A public package is allowed and served.
        let pubp = cat
            .upsert_package(repo_id, "sym/console", "mirror", None, Visibility::Public)
            .await
            .unwrap();
        ver(&cat, pubp, "sym/console").await;
        assert_eq!(cat.all_package_names(repo_id).await.unwrap(), ["sym/console"]);
        assert_eq!(
            cat.visible_versions(repo_id, "sym/console", "auto", 0)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn tokens_expire_and_can_be_revoked_by_id() {
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        // An already-expired token (negative window) never validates.
        let dead = cat
            .create_token(repo_id, Some("old"), Some(-1))
            .await
            .unwrap();
        assert!(!cat.token_valid(repo_id, &dead).await.unwrap(), "expired");

        // A live, named token validates and shows up in the listing.
        let live = cat
            .create_token(repo_id, Some("ci"), Some(30))
            .await
            .unwrap();
        assert!(cat.token_valid(repo_id, &live).await.unwrap(), "live");
        let listed = cat.list_tokens(repo_id).await.unwrap();
        assert_eq!(listed.len(), 2);
        let ci = listed
            .iter()
            .find(|t| t.label.as_deref() == Some("ci"))
            .expect("named token listed");
        assert!(!ci.expired, "ci token not expired");
        assert!(ci.expires.is_some(), "ci token has an expiry date");

        // Revoke it by id → gone and no longer valid.
        assert!(cat.revoke_token(repo_id, ci.id).await.unwrap(), "revoked");
        assert!(
            !cat.token_valid(repo_id, &live).await.unwrap(),
            "revoked token rejected"
        );
        assert_eq!(cat.list_tokens(repo_id).await.unwrap().len(), 1);
    }

    /// Agency curation: a package mirrored once into a shared repo becomes
    /// visible in a client repo after being granted (no re-mirror).
    #[tokio::test]
    async fn granted_packages_are_visible_in_the_target_repo() {
        let Some((cat, shared)) = repo().await else {
            return;
        };
        let (_, client) = repo().await.unwrap();
        let cj = serde_json::json!({"name": "vendor/pub"});
        let pkg = cat
            .upsert_package(shared, "vendor/pub", "git", None, Visibility::Private)
            .await
            .unwrap();
        cat.upsert_package_version(
            pkg, "v1.0.0", "1.0.0.0", "stable", &cj, None, None, None, None,
        )
        .await
        .unwrap();

        // Invisible in the client before the grant.
        assert!(
            cat.visible_versions(client, "vendor/pub", "auto", 0)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(cat.all_package_names(client).await.unwrap().is_empty());

        assert!(
            cat.grant_package(client, shared, "vendor/pub")
                .await
                .unwrap()
        );
        assert_eq!(
            cat.visible_versions(client, "vendor/pub", "auto", 0)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(cat.all_package_names(client).await.unwrap(), ["vendor/pub"]);

        // Granting a non-existent package reports not-found.
        assert!(
            !cat.grant_package(client, shared, "nope/nope")
                .await
                .unwrap()
        );
    }

    /// Seller mode: a license key resolves only for its repo and unlocks only
    /// the purchased packages.
    #[tokio::test]
    async fn license_keys_entitle_only_purchased_packages() {
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        cat.upsert_package(repo_id, "seller/a", "commercial", None, Visibility::Private)
            .await
            .unwrap();
        cat.upsert_package(repo_id, "seller/b", "commercial", None, Visibility::Private)
            .await
            .unwrap();

        let (key, lic) = cat
            .create_license_key(repo_id, Some("alice"))
            .await
            .unwrap();
        assert!(cat.entitle_package(lic, repo_id, "seller/a").await.unwrap());
        assert!(
            !cat.entitle_package(lic, repo_id, "nope/nope")
                .await
                .unwrap(),
            "unknown pkg"
        );

        assert_eq!(cat.resolve_license(repo_id, &key).await.unwrap(), Some(lic));
        assert!(
            cat.resolve_license(repo_id, "sclk_bogus")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(cat.entitled_package_names(lic).await.unwrap(), ["seller/a"]);

        // A license from one repo does not resolve in another.
        let (_, other) = repo().await.unwrap();
        assert!(cat.resolve_license(other, &key).await.unwrap().is_none());
    }
}
