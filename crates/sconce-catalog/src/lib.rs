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
];

/// Arbitrary fixed key for the migration advisory lock (so all sconce instances
/// agree on the same lock).
const MIGRATE_LOCK: i64 = 6_927_654_321;

/// The catalog handle: a Postgres connection pool plus the query methods.
#[derive(Debug, Clone)]
pub struct Catalog {
    pool: PgPool,
}

/// A repository in the admin listing.
#[derive(Debug, Clone)]
pub struct RepoSummary {
    pub org: String,
    pub repo: String,
    pub id: Uuid,
    pub update_mode: String,
    pub cooldown_days: i32,
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
    /// Release time as text (`null` if unknown).
    pub released_at: Option<String>,
}

/// A license key in the admin listing (the key itself is never recoverable).
#[derive(Debug, Clone)]
pub struct LicenseSummary {
    pub id: Uuid,
    pub buyer: Option<String>,
    pub status: String,
    pub packages: Vec<String>,
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

    /// All organizations `(slug, name)`, sorted — so a freshly created org is
    /// visible in the dashboard even before it has any repositories.
    pub async fn list_organizations(&self) -> Result<Vec<(String, Option<String>)>, sqlx::Error> {
        let rows = sqlx::query("select slug, name from organizations order by slug")
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|r| Ok((r.try_get("slug")?, r.try_get("name")?)))
            .collect()
    }

    /// All repositories, for the admin dashboard.
    pub async fn list_repositories(&self) -> Result<Vec<RepoSummary>, sqlx::Error> {
        let rows = sqlx::query(
            "select o.slug as org, r.slug as repo, r.id as id, \
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
                    pv.released_at::text as released_at \
             from package_versions pv join packages p on p.id = pv.package_id \
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
                    released_at: row.try_get("released_at")?,
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
    pub async fn upsert_package(
        &self,
        repo_id: Uuid,
        name: &str,
        kind: &str,
        source: Option<&Value>,
    ) -> Result<Uuid, sqlx::Error> {
        sqlx::query_scalar(
            "insert into packages (repo_id, name, kind, source) values ($1, $2, $3, $4) \
             on conflict (repo_id, name) do update set kind = excluded.kind, source = excluded.source \
             returning id",
        )
        .bind(repo_id)
        .bind(name)
        .bind(kind)
        .bind(source)
        .fetch_one(&self.pool)
        .await
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
    pub async fn create_token(
        &self,
        repo_id: Uuid,
        label: Option<&str>,
    ) -> Result<String, sqlx::Error> {
        let token = generate_token();
        sqlx::query("insert into tokens (repo_id, token_hash, label) values ($1, $2, $3)")
            .bind(repo_id)
            .bind(token_hash(&token))
            .bind(label)
            .execute(&self.pool)
            .await?;
        Ok(token)
    }

    /// Whether `token` is valid **for this repository**. Bumps `last_used_at`.
    pub async fn token_valid(&self, repo_id: Uuid, token: &str) -> Result<bool, sqlx::Error> {
        let updated = sqlx::query(
            "update tokens set last_used_at = now() where repo_id = $1 and token_hash = $2",
        )
        .bind(repo_id)
        .bind(token_hash(token))
        .execute(&self.pool)
        .await?;
        Ok(updated.rows_affected() > 0)
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
        let rows = sqlx::query(
            "select name from packages where repo_id = $1 \
             union \
             select p.name from packages p \
             join repository_grants g on g.package_id = p.id where g.repo_id = $1 \
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
             where p.name = $2 \
               and ( p.repo_id = $1 \
                     or exists (select 1 from repository_grants g \
                                where g.repo_id = $1 and g.package_id = p.id) ) \
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
            .upsert_package(repo_a, "shared/name", "git", None)
            .await
            .unwrap();
        let pb = cat
            .upsert_package(repo_b, "shared/name", "git", None)
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
            .upsert_package(repo_id, "acme/lib", "git", None)
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

    #[tokio::test]
    async fn tokens_are_scoped_to_their_repo() {
        let Some((cat, repo_a)) = repo().await else {
            return;
        };
        let (_, repo_b) = repo().await.unwrap();
        let token = cat.create_token(repo_a, None).await.unwrap();
        assert!(
            cat.token_valid(repo_a, &token).await.unwrap(),
            "valid for its repo"
        );
        assert!(
            !cat.token_valid(repo_b, &token).await.unwrap(),
            "not valid for another repo"
        );
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
            .upsert_package(shared, "vendor/pub", "git", None)
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
        cat.upsert_package(repo_id, "seller/a", "commercial", None)
            .await
            .unwrap();
        cat.upsert_package(repo_id, "seller/b", "commercial", None)
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
