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

use std::time::Duration;

use serde_json::Value;
use sqlx::{PgPool, Row};
use uuid::Uuid;

/// A content-addressed blob's identity + size, as the catalog knows it.
#[derive(Debug, Clone, Copy)]
pub struct BlobRef {
    pub sha256: [u8; 32],
    pub size_bytes: i64,
}

impl BlobRef {
    fn from_row(row: (Vec<u8>, i64)) -> Option<Self> {
        let (bytes, size_bytes) = row;
        let sha256 = <[u8; 32]>::try_from(bytes.as_slice()).ok()?;
        Some(Self { sha256, size_bytes })
    }
}

/// Aggregate blob-storage accounting (see [`Catalog::storage_stats`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageStats {
    /// Total blobs in the catalog.
    pub blob_count: i64,
    /// Sum of all blob sizes, in bytes.
    pub total_bytes: i64,
    /// Bytes held by orphan (refcount 0) blobs — the reclaimable slice.
    pub orphan_bytes: i64,
    /// Number of orphan (refcount 0) blobs.
    pub orphan_count: i64,
}

/// Storage metered to a tenant (see [`Catalog::org_storage`]).
///
/// **Full logical size — dedup is not credited to tenants.** A blob shared
/// across orgs (e.g. the same public package both mirror) is counted *in full*
/// for each org that references it; the physical single-copy saving stays the
/// operator's margin (reflected only in the overall list price, per ROADMAP
/// pricing). Distinct *within* an org, so an org isn't billed twice for one
/// file two of its own versions happen to share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageUsage {
    /// Summed size of the distinct blobs the org's versions reference.
    pub bytes: i64,
    /// Number of distinct blobs.
    pub blob_count: i64,
}

/// One org's metered storage, with its identity (see [`Catalog::storage_by_org`]).
#[derive(Debug, Clone)]
pub struct OrgStorage {
    pub org_id: Uuid,
    pub org_slug: String,
    pub org_name: Option<String>,
    pub usage: StorageUsage,
}

/// A gate-able capability. The hosted control plane turns these off per org to
/// match a plan; the open engine only asks "is it allowed here?" (see
/// [`Entitlements`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feature {
    Agency,
    Sso,
    MultiOidc,
    RepoAccess,
    Scim,
    AuditLog,
    CustomHostname,
    WhiteLabel,
}

impl Feature {
    /// Stable machine name (CLI input, error text).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Feature::Agency => "agency",
            Feature::Sso => "sso",
            Feature::MultiOidc => "multi_oidc",
            Feature::RepoAccess => "repo_access",
            Feature::Scim => "scim",
            Feature::AuditLog => "audit_log",
            Feature::CustomHostname => "custom_hostname",
            Feature::WhiteLabel => "white_label",
        }
    }

    /// Parse a machine name (for the CLI); `None` if unknown.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.trim() {
            "agency" => Feature::Agency,
            "sso" => Feature::Sso,
            "multi_oidc" => Feature::MultiOidc,
            "repo_access" => Feature::RepoAccess,
            "scim" => Feature::Scim,
            "audit_log" => Feature::AuditLog,
            "custom_hostname" => Feature::CustomHostname,
            "white_label" => Feature::WhiteLabel,
            _ => return None,
        })
    }

    /// Every feature, in a stable order (for `entitlements show` and setters).
    #[must_use]
    pub fn all() -> [Feature; 8] {
        [
            Feature::Agency,
            Feature::Sso,
            Feature::MultiOidc,
            Feature::RepoAccess,
            Feature::Scim,
            Feature::AuditLog,
            Feature::CustomHostname,
            Feature::WhiteLabel,
        ]
    }
}

impl std::fmt::Display for Feature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The resource limits + feature switches in force for one org. **Unlimited /
/// all-on by default** ([`Entitlements::unlimited`]): the resolver returns that
/// when no `org_entitlements` row exists, so a self-hosted instance — which
/// never writes one — is unconstrained.
// A flat bag of independent feature flags; enums would just add indirection.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entitlements {
    /// Advisory storage limit for UI warnings (null = none). Never blocks.
    pub storage_soft_bytes: Option<i64>,
    /// Hard cap on sellable editions/SKUs (null = unlimited).
    pub max_skus: Option<i32>,
    pub agency: bool,
    pub sso: bool,
    pub multi_oidc: bool,
    pub repo_access: bool,
    pub scim: bool,
    pub audit_log: bool,
    pub custom_hostname: bool,
    pub white_label: bool,
}

impl Entitlements {
    /// The permissive default: every feature on, no caps. What a missing row
    /// resolves to (self-host, and fail-open per `BILLING_PLAN` P2).
    #[must_use]
    pub fn unlimited() -> Self {
        Self {
            storage_soft_bytes: None,
            max_skus: None,
            agency: true,
            sso: true,
            multi_oidc: true,
            repo_access: true,
            scim: true,
            audit_log: true,
            custom_hostname: true,
            white_label: true,
        }
    }

    /// Whether `feature` is enabled.
    #[must_use]
    pub fn allows(&self, feature: Feature) -> bool {
        match feature {
            Feature::Agency => self.agency,
            Feature::Sso => self.sso,
            Feature::MultiOidc => self.multi_oidc,
            Feature::RepoAccess => self.repo_access,
            Feature::Scim => self.scim,
            Feature::AuditLog => self.audit_log,
            Feature::CustomHostname => self.custom_hostname,
            Feature::WhiteLabel => self.white_label,
        }
    }
}

/// Failure from an entitlement-gated mutation: either the org's plan doesn't
/// include the [`Feature`], or the underlying query failed. `From<sqlx::Error>`
/// lets gated methods keep using `?` on their existing queries.
#[derive(Debug, thiserror::Error)]
pub enum EntitlementError {
    #[error("the '{0}' feature is not available on this organization's plan")]
    Denied(Feature),
    /// The org is at its `max_skus` cap (argument = the cap). Raised by
    /// [`Catalog::create_edition`]; deactivate an edition or raise the plan.
    #[error("this organization's plan allows at most {0} editions (SKUs)")]
    SkuCapReached(i32),
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
}

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
    (
        "0024_ci_oidc",
        include_str!("../migrations/0024_ci_oidc.sql"),
    ),
    (
        "0025_package_lifecycle",
        include_str!("../migrations/0025_package_lifecycle.sql"),
    ),
    (
        "0026_credential_policy",
        include_str!("../migrations/0026_credential_policy.sql"),
    ),
    (
        "0027_slug_history",
        include_str!("../migrations/0027_slug_history.sql"),
    ),
    (
        "0028_package_sets",
        include_str!("../migrations/0028_package_sets.sql"),
    ),
    (
        "0029_update_bound",
        include_str!("../migrations/0029_update_bound.sql"),
    ),
    (
        "0030_grant_policy",
        include_str!("../migrations/0030_grant_policy.sql"),
    ),
    (
        "0031_grant_rules",
        include_str!("../migrations/0031_grant_rules.sql"),
    ),
    (
        "0032_set_entitlements",
        include_str!("../migrations/0032_set_entitlements.sql"),
    ),
    (
        "0033_upstream_requires",
        include_str!("../migrations/0033_upstream_requires.sql"),
    ),
    (
        "0034_source_paths",
        include_str!("../migrations/0034_source_paths.sql"),
    ),
    (
        "0035_password_resets",
        include_str!("../migrations/0035_password_resets.sql"),
    ),
    (
        "0036_blob_refcount_gc",
        include_str!("../migrations/0036_blob_refcount_gc.sql"),
    ),
    (
        "0037_org_entitlements",
        include_str!("../migrations/0037_org_entitlements.sql"),
    ),
    (
        "0038_editions",
        include_str!("../migrations/0038_editions.sql"),
    ),
    (
        "0039_service_tokens",
        include_str!("../migrations/0039_service_tokens.sql"),
    ),
    (
        "0040_license_key_ciphertext",
        include_str!("../migrations/0040_license_key_ciphertext.sql"),
    ),
    (
        "0041_edition_integrity",
        include_str!("../migrations/0041_edition_integrity.sql"),
    ),
    (
        "0042_ci_policy_capability",
        include_str!("../migrations/0042_ci_policy_capability.sql"),
    ),
    (
        "0043_publish_tokens",
        include_str!("../migrations/0043_publish_tokens.sql"),
    ),
    (
        "0044_upload_sessions",
        include_str!("../migrations/0044_upload_sessions.sql"),
    ),
    (
        "0045_snapshots",
        include_str!("../migrations/0045_snapshots.sql"),
    ),
    (
        "0046_device_flows",
        include_str!("../migrations/0046_device_flows.sql"),
    ),
    (
        "0047_entitlement_bounds",
        include_str!("../migrations/0047_entitlement_bounds.sql"),
    ),
];

/// Arbitrary fixed key for the migration advisory lock (so all sconce instances
/// agree on the same lock).
const MIGRATE_LOCK: i64 = 6_927_654_321;

/// The catalog handle: a Postgres connection pool plus the query methods.
#[derive(Debug, Clone)]
pub struct Catalog {
    pool: PgPool,
    /// At-rest key for recoverable secrets (license keys), from `SCONCE_SECRET_KEY`.
    /// `None` ⇒ keys are hash-only (not recoverable), same policy as credentials.
    secret_key: Option<secret::SecretKey>,
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

/// One entry of an upstream's mirror subscription (require-list). A package is
/// mirrored iff it matches **any** entry; a version is kept iff it satisfies the
/// floor of at least one matching entry. `match_kind`: `prefix`|`exact`|`all`|`regex`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamRequire {
    pub match_kind: String,
    pub pattern: String,
    /// Bare version floor (e.g. `2.4`); `None` = every version.
    pub version_floor: Option<String>,
}

impl UpstreamRequire {
    /// Parse one subscription-entry spec (the CLI `--require` / UI textarea form):
    /// `vendor/*` or `vendor/` (prefix), `vendor/pkg` (exact), `*` (require-all),
    /// `re:<regex>` (regex); any may carry an `@<version>` floor suffix. Returns a
    /// human message on a malformed spec.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let spec = spec.trim();
        let (matcher, floor) = match spec.split_once('@') {
            Some((m, f)) if !f.trim().is_empty() => (m.trim(), Some(f.trim().to_owned())),
            _ => (spec.trim_end_matches('@').trim(), None),
        };
        let (match_kind, pattern) = if matcher == "*" {
            ("all", String::new())
        } else if let Some(re) = matcher.strip_prefix("re:") {
            if re.is_empty() {
                return Err(format!("empty regex in '{spec}'"));
            }
            ("regex", re.to_owned())
        } else if matcher.is_empty() {
            return Err(format!("empty match in '{spec}'"));
        } else if let Some(stem) = matcher.strip_suffix('*') {
            // A trailing star is a prefix glob: `mage-os/*`, `mage-os/composer*`.
            ("prefix", stem.to_owned())
        } else if matcher.ends_with('/') {
            // A bare vendor (`mage-os/`) is shorthand for the vendor prefix.
            ("prefix", matcher.to_owned())
        } else {
            ("exact", matcher.to_owned())
        };
        Ok(Self {
            match_kind: match_kind.to_owned(),
            pattern,
            version_floor: floor,
        })
    }

    /// Render back to the canonical spec form (inverse of [`parse`](Self::parse)).
    #[must_use]
    pub fn to_spec(&self) -> String {
        let matcher = match self.match_kind.as_str() {
            "all" => "*".to_owned(),
            "regex" => format!("re:{}", self.pattern),
            // A vendor prefix keeps its trailing slash; any other prefix shows
            // the `*` so it round-trips back to a prefix (not an exact match).
            "prefix" if self.pattern.ends_with('/') => self.pattern.clone(),
            "prefix" => format!("{}*", self.pattern),
            _ => self.pattern.clone(),
        };
        match &self.version_floor {
            Some(f) => format!("{matcher}@{f}"),
            None => matcher,
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
    /// How the credential authenticates: `basic`|`github`|`gitlab`|`bearer`.
    pub credential_type: String,
    /// Mirror subscription: the ordered require-list scoping what this upstream
    /// mirrors (empty = nothing matched yet / git source mirrored whole).
    pub requires: Vec<UpstreamRequire>,
    /// git monorepo subpaths this upstream mirrors (empty = repo root).
    pub source_paths: Vec<String>,
    /// Status of the most recent mirror job, if any (`pending`/`running`/
    /// `ready`/`failed`).
    pub job_status: Option<String>,
    /// Error from the most recent job, if it failed.
    pub job_error: Option<String>,
    /// Age in seconds of the most recent job (for a relative "6m"/"2h"/"1d"
    /// last-sync label); `None` if never synced.
    pub last_sync_age: Option<i64>,
}

/// A package with its lifecycle state, for the operator view. `sync_health` is
/// `ok`/`broken`; `archived_at` non-null means the operator froze it (which masks
/// a broken flag). `broken`/`stale` are *not* serving states — every mirrored
/// version keeps serving from the CAS regardless.
#[derive(Debug, Clone)]
pub struct PackageStatus {
    pub name: String,
    pub visibility: String,
    /// The upstream this package is mirrored from (`None` = added directly).
    pub upstream_id: Option<Uuid>,
    pub sync_health: String,
    pub broken_reason: Option<String>,
    pub broken_at: Option<String>,
    pub last_success_at: Option<String>,
    pub archived: bool,
    /// The bound upstream's most recent job error, if any. A *healthy* package
    /// (`sync_health = ok`) with a non-null error is **stale** — its last sync
    /// failed (non-terminal, still retrying) but its mirrored versions still serve.
    pub upstream_error: Option<String>,
}

/// A mirror job for the Activity view: what it targets, which repo it belongs
/// to, and its current state. The "is it done yet?" surface.
#[derive(Debug, Clone)]
pub struct JobActivity {
    pub kind: String,
    pub status: String,
    pub attempts: i32,
    pub last_error: Option<String>,
    /// Human label for the job's target (package name / upstream base / closure).
    pub target: String,
    /// `org/repo` the job belongs to, if resolvable.
    pub repo: Option<String>,
    pub updated: String,
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
    /// What the minted token can do: `"read"` (Composer serving) or `"publish"`
    /// (upload package versions). Selected by the matching exchange endpoint.
    pub capability: String,
}

/// The result of an immutable publish insert ([`Catalog::insert_pushed_version`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishOutcome {
    /// A new `(package, version)` row was created.
    Created,
    /// The version already exists with **identical** dist bytes — a safe,
    /// idempotent re-publish (e.g. a retried CI job).
    AlreadyPublished,
    /// The version already exists with **different** dist bytes — rejected, so
    /// published versions stay immutable.
    Conflict,
}

/// A chunked-upload session ([`Catalog::create_upload_session`] /
/// [`Catalog::create_snapshot_upload_session`]). `kind` discriminates: a
/// `"package"` session carries `vendor`/`name`/`version`, a `"snapshot"` session
/// carries `environment`. Both share the part-staging + assemble routes.
#[derive(Debug, Clone)]
pub struct UploadSession {
    pub id: Uuid,
    pub repo_id: Uuid,
    pub kind: String,
    pub vendor: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
    pub environment: Option<String>,
    pub status: String,
}

/// One staged part of a chunked upload; `chunk_sha256` is its CAS key.
#[derive(Debug, Clone)]
pub struct UploadPart {
    pub part_number: i32,
    pub chunk_sha256: Vec<u8>,
    pub size_bytes: i64,
}

/// A registered database snapshot ([`Catalog::list_snapshots`] /
/// [`Catalog::resolve_latest`]). `blob_sha256` is the `.jibsdump`'s CAS key.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub id: Uuid,
    pub environment: String,
    pub blob_sha256: [u8; 32],
    pub size_bytes: i64,
    pub source_ref: Option<String>,
    /// Unix seconds of `created_at`.
    pub created_at: i64,
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
    /// Mirror subscription (ordered require-list). For a composer upstream this
    /// scopes which packages sync (must be non-empty); for a git upstream it is
    /// an optional per-package version floor (empty = mirror every tag).
    pub requires: Vec<UpstreamRequire>,
    /// Explicit subpaths a git upstream mirrors (monorepo packages). Empty =
    /// mirror the repo root as a single package. Unused for composer upstreams.
    pub source_paths: Vec<String>,
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

/// Why a rename failed.
#[derive(Debug, thiserror::Error)]
pub enum RenameError {
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    /// The new slug is in use by a live entity.
    #[error("that name is already taken")]
    Taken,
    /// The new slug was previously used and is permanently retired (reusing it
    /// would let old locks/tokens resolve to different content).
    #[error("that name was previously used and is retired")]
    Retired,
    /// Invalid (empty/malformed) slug.
    #[error("invalid name")]
    Invalid,
}

/// Where an `(org, repo)` slug pair currently resolves: the repo id, its
/// **canonical** slugs, and whether the request used an old (renamed) slug and
/// should be redirected.
#[derive(Debug, Clone)]
pub struct RepoLocation {
    pub repo_id: Uuid,
    pub org_slug: String,
    pub repo_slug: String,
    pub moved: bool,
}

/// A repository row for the org overview: counts + last-sync, for the C1 table.
#[derive(Debug, Clone)]
pub struct RepoOverview {
    pub slug: String,
    pub allow_private_packages: bool,
    pub update_mode: String,
    pub packages: i64,
    pub broken: i64,
    /// Newest successful sync across the repo's packages (text), if any.
    pub last_sync: Option<String>,
}

/// A repository on the home dashboard: overview data plus its owning org, so
/// the whole dashboard can be built from one query (no per-org round-trips).
#[derive(Debug, Clone)]
pub struct HomeRepo {
    pub org_id: Uuid,
    pub slug: String,
    pub allow_private_packages: bool,
    pub update_mode: String,
    pub cooldown_days: i32,
    pub packages: i64,
    pub broken: i64,
    /// Versions awaiting approval under the repo's policy (manual mode, or still
    /// inside the `delayed` cooldown window).
    pub pending: i64,
    /// Newest successful sync across the repo's packages (text), if any.
    pub last_sync: Option<String>,
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

/// Result of polling a device-authorization flow (the RFC 8628 token endpoint).
#[derive(Debug)]
pub enum DeviceFlowPoll {
    /// Still waiting for the user to approve in the browser.
    Pending,
    /// Approved — mint an org-scoped read token for this org.
    Approved { org_id: Uuid },
    /// The request was denied.
    Denied,
    /// Unknown `device_code`, or the flow expired.
    Expired,
}

/// An org-scoped session token resolved for relay introspection: the org it
/// authenticates and its expiry as unix seconds (`None` = never expires). The
/// expiry is read as an epoch bigint SQL-side — `sqlx` here has no `time`/
/// `chrono` feature, so timestamps never cross the boundary as native types.
#[derive(Debug, Clone)]
pub struct OrgToken {
    pub org_id: Uuid,
    pub expires_at_unix: Option<i64>,
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

/// A user's membership in one tenant, with role and active state.
#[derive(Debug, Clone)]
pub struct TenantMembership {
    pub slug: String,
    pub role: String,
    pub active: bool,
}

/// A license's perpetual-fallback update bound (both `None` = unbounded). `until`
/// is the display date; `until_unix` feeds the serving clause; `major` is the max
/// allowed major version.
#[derive(Debug, Clone, Default)]
pub struct LicenseBound {
    pub until: Option<String>,
    pub until_unix: Option<i64>,
    pub major: Option<i32>,
}

/// An edition's update-bound **template** — resolved to concrete per-key values
/// at issue time (see [`Catalog::issue_from_edition`]). Mirrors [`LicenseBound`],
/// but a time bound is a relative *period*, not an absolute date.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditionBound {
    /// Perpetual / unbounded — the key never stops receiving updates.
    Perpetual,
    /// Updates for a period: resolves to `update_until = issue_date + months`.
    Time { period_months: i32 },
    /// Updates up to a major version (inclusive): resolves to `version_cap_major`.
    Version { major: i32 },
}

impl EditionBound {
    /// The `(kind, period_months, major)` triple stored in the `editions` row.
    #[must_use]
    fn columns(&self) -> (&'static str, Option<i32>, Option<i32>) {
        match self {
            EditionBound::Perpetual => ("perpetual", None, None),
            EditionBound::Time { period_months } => ("time", Some(*period_months), None),
            EditionBound::Version { major } => ("version", None, Some(*major)),
        }
    }

    /// Reconstruct from the stored columns (an unknown kind falls back to
    /// perpetual, so a malformed row is unbounded rather than an error).
    #[must_use]
    fn from_columns(kind: &str, period_months: Option<i32>, major: Option<i32>) -> Self {
        match kind {
            "time" => EditionBound::Time {
                period_months: period_months.unwrap_or(0),
            },
            "version" => EditionBound::Version {
                major: major.unwrap_or(0),
            },
            _ => EditionBound::Perpetual,
        }
    }

    /// Parse the CLI `--bound` spec: `perpetual` (or empty), `time:<n>` / `<n>m`
    /// (n months), `version:<n>` / `v<n>` (max major). Human message on error.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let s = spec.trim().to_lowercase();
        let months = |v: &str| {
            v.trim_end_matches('m')
                .trim()
                .parse::<i32>()
                .ok()
                .filter(|n| *n > 0)
        };
        let major = |v: &str| v.trim().parse::<i32>().ok().filter(|n| *n >= 0);
        if s.is_empty() || s == "perpetual" {
            Ok(EditionBound::Perpetual)
        } else if let Some(v) = s.strip_prefix("time:").map(str::to_owned).or_else(|| {
            s.strip_suffix('m')
                .filter(|r| r.chars().all(|c| c.is_ascii_digit()))
                .map(|_| s.clone())
        }) {
            months(&v)
                .map(|period_months| EditionBound::Time { period_months })
                .ok_or_else(|| format!("invalid time bound '{spec}' (want e.g. time:12 or 12m)"))
        } else if let Some(v) = s.strip_prefix("version:").or_else(|| s.strip_prefix('v')) {
            major(v)
                .map(|major| EditionBound::Version { major })
                .ok_or_else(|| {
                    format!("invalid version bound '{spec}' (want e.g. version:3 or v3)")
                })
        } else {
            Err(format!(
                "unknown bound '{spec}' (want perpetual, time:<months>, or version:<major>)"
            ))
        }
    }

    /// A compact human label for listings ("perpetual", "12 months", "≤ v3").
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            EditionBound::Perpetual => "perpetual".to_owned(),
            EditionBound::Time { period_months } => format!("{period_months} months"),
            EditionBound::Version { major } => format!("≤ v{major}"),
        }
    }
}

/// A seller **edition** (SKU): a reusable issuance template — a package set plus
/// an update-bound template and optional policy, that license keys are issued
/// against. See `SKU_PLAN.md`.
#[derive(Debug, Clone)]
pub struct Edition {
    pub id: Uuid,
    pub name: String,
    pub slug: Option<String>,
    pub set_id: Uuid,
    /// The target set's name (joined for display).
    pub set_name: String,
    pub bound: EditionBound,
    /// Freeze set membership at issue (snapshot) vs unlock by reference (auto-grow).
    pub snapshot: bool,
    /// Supply-chain policy stamped onto issued keys (empty = inherit the repo).
    pub policy: PolicyOverride,
    pub active: bool,
}

/// The result of issuing a license against an edition. `created` is true for a
/// freshly minted key and false for an idempotent replay (same edition +
/// `Idempotency-Key`). `key` is the plaintext (shown once on create, or recovered
/// from at-rest ciphertext on replay); it is `None` only when no secret key is
/// configured and this is a replay — i.e. the plaintext was never stored and so
/// can't be handed back.
#[derive(Debug, Clone)]
pub struct IssuedLicense {
    pub id: Uuid,
    pub key: Option<String>,
    pub created: bool,
}

/// The outcome of [`Catalog::merge_license_keys`] — folding one key's
/// entitlements into another and revoking the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseMerge {
    /// Entitlements moved (bounds materialized/unioned); source revoked.
    Merged,
    /// No active source key with that id in the repo.
    NoSource,
    /// No active target key with that id in the repo.
    NoTarget,
    /// The target key carries its own update bound — merge targets must be
    /// unbounded (account) keys, since a NULL edge inherits the key bound.
    TargetBounded,
    /// Source and target are the same key.
    SameKey,
}

/// The outcome of [`Catalog::add_edition_to_license`] — attaching an edition's
/// content to an existing key so a repeat buyer accumulates onto one key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditionAdd {
    /// The edition's content was attached (or was already present — idempotent).
    Added,
    /// The key or the edition can't be safely merged onto a shared key
    /// (non-perpetual bound, or a snapshot edition). The key is untouched; the
    /// caller should issue a standalone key instead.
    Standalone,
    /// No active key with that id in the repo.
    NoKey,
    /// No active edition with that id in the repo.
    NoEdition,
}

/// The outcome of resolving a single-package edition's target set via
/// [`Catalog::singleton_set`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SingletonSet {
    /// The singleton set id (created, or an existing genuine singleton reused).
    Set(Uuid),
    /// The package isn't in the org.
    UnknownPackage,
    /// A set of that name already exists but isn't a singleton for this package
    /// (a curated multi-package/rule set) — reusing it would over-entitle keys.
    NameCollision,
}

/// A license key's full detail for the management API's inspect endpoint.
#[derive(Debug, Clone)]
pub struct LicenseDetail {
    pub id: Uuid,
    pub buyer: Option<String>,
    pub status: String,
    /// The edition this key was issued from, if any (`None` = ad-hoc key).
    pub edition: Option<String>,
    /// Package names the key currently resolves to (by-reference sets included).
    pub packages: Vec<String>,
    pub bound: LicenseBound,
    /// The plaintext key, recovered from at-rest ciphertext — `None` if no secret
    /// key is configured or the key predates encrypted storage.
    pub key: Option<String>,
}

/// A management-API service token in a listing (the token itself is never
/// recoverable — only its hash is stored).
#[derive(Debug, Clone)]
pub struct ServiceTokenSummary {
    pub id: Uuid,
    pub label: Option<String>,
    pub created: String,
    pub last_used: Option<String>,
    pub expires: Option<String>,
}

/// A package set (named, org-scoped group of packages) in a listing.
#[derive(Debug, Clone)]
pub struct PackageSet {
    pub id: Uuid,
    pub name: String,
}

/// A user in the superadmin listing.
#[derive(Debug, Clone)]
pub struct UserSummary {
    pub email: String,
    pub is_superadmin: bool,
    pub tenants: Vec<TenantMembership>,
}

/// One of a user's active login sessions (for the account page).
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// Hex of the token hash — identifies the session for revocation.
    pub hash_hex: String,
    pub created: String,
    pub expires: String,
    /// Whether this is the session making the current request.
    pub current: bool,
}

/// A freshly-minted password-reset token. `token` is the plaintext (shown once,
/// emailed to the user); only its hash is persisted.
#[derive(Debug, Clone)]
pub struct PasswordReset {
    pub user_id: Uuid,
    pub token: String,
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
    /// Provenance (shown on the package detail page): the dist sha1 and the
    /// source git ref/commit.
    pub dist_shasum: Option<String>,
    pub source_reference: Option<String>,
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
        let ovr_mode = self.update_mode.as_deref().or(if ovr_cooldown > 0 {
            Some("delayed")
        } else {
            None
        });
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
    /// Entitled package sets as `(set_id, name, edge_bound)` — unlock by
    /// reference, auto-grow. The bound is the EDGE's own ceiling (0047): empty
    /// means the edge inherits the key bound (legacy) / is perpetual.
    pub sets: Vec<(Uuid, String, LicenseBound)>,
    /// Per-credential supply-chain policy override (empty = inherits the repo).
    pub policy: PolicyOverride,
    /// Perpetual-fallback update bound **on the key** (empty = unbounded).
    /// Accumulated keys keep this empty and carry bounds per set edge instead.
    pub bound: LicenseBound,
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
    /// Per-credential supply-chain policy override (empty = inherits the repo).
    pub policy: PolicyOverride,
}

/// A grant shown in the admin UI: a package owned elsewhere, exposed here.
#[derive(Debug, Clone)]
pub struct GrantSummary {
    pub package: String,
    pub source_org: String,
    pub source_repo: String,
    /// Grant-scoped supply-chain policy override (empty = inherit the repo).
    pub policy: PolicyOverride,
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

/// Shared WHERE fragment for the admin package-version list/count: `$2` = name
/// (`ilike`, null = any), `$3` = state (`held`|`yanked`|`approved`|`pending`,
/// null = any). `pending` = gated by the repo policy (the approval queue):
/// not held/yanked/approved and either `manual` mode or still in `delayed`
/// cooldown. Both callers join `repositories r` so `r.update_mode`/`cooldown_days`
/// are in scope.
const VERSION_FILTER: &str = " and ($2::text is null or p.name ilike '%' || $2 || '%') \
     and ($3::text is null \
          or ($3 = 'held' and pv.held_at is not null) \
          or ($3 = 'yanked' and pv.yanked_at is not null) \
          or ($3 = 'approved' and pv.approved_at is not null) \
          or ($3 = 'pending' and pv.held_at is null and pv.yanked_at is null \
              and pv.approved_at is null \
              and ( r.update_mode = 'manual' \
                    or ( r.update_mode = 'delayed' \
                         and ( pv.released_at is null \
                               or pv.released_at + make_interval(days => r.cooldown_days) > now() ) ) )))";

/// SQL `exists(...)` testing whether package `p` is granted into repo `$1` via an
/// **autogrant rule** (a subscribed package set). References `p.id`/`p.repo_id`/
/// `p.name`; inlined into the serving read path so rule-grants auto-grow.
const GRANT_RULE_EXISTS: &str = "exists ( \
    select 1 from repository_grant_rules gr \
    join package_sets ps on ps.id = gr.set_id \
    where gr.target_repo_id = $1 \
      and ( p.id in (select package_id from package_set_members m where m.set_id = gr.set_id) \
            or ( p.repo_id in (select rr.id from repositories rr where rr.org_id = ps.org_id) \
                 and exists (select 1 from package_set_rules sr \
                             where sr.set_id = gr.set_id and p.name like replace(sr.glob, '*', '%')) ) ) )";

impl Catalog {
    /// Connect to Postgres at `database_url` (e.g.
    /// `postgres://user:pass@host:5432/db`).
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPool::connect(database_url).await?;
        Ok(Self {
            pool,
            secret_key: secret::SecretKey::from_env().ok(),
        })
    }

    /// Build from an existing pool (loads `SCONCE_SECRET_KEY` from the env).
    #[must_use]
    pub fn from_pool(pool: PgPool) -> Self {
        Self {
            pool,
            secret_key: secret::SecretKey::from_env().ok(),
        }
    }

    /// Build from a pool with an explicit at-rest key (for tests / callers that
    /// load the key themselves rather than from the environment).
    #[must_use]
    pub fn with_secret(pool: PgPool, secret_key: Option<secret::SecretKey>) -> Self {
        Self { pool, secret_key }
    }

    /// Encrypt an issued key for at-rest storage — `None` when no secret key is
    /// configured (then the key is hash-only and unrecoverable).
    fn encrypt_key(&self, key: &str) -> Option<Vec<u8>> {
        self.secret_key.as_ref().map(|k| k.encrypt(key.as_bytes()))
    }

    /// Mint a fresh license key: the plaintext (shown once), its auth `key_hash`,
    /// and the at-rest `key_ciphertext` (`None` when no secret key is configured).
    /// Every `license_keys` insert path MUST go through this so the hash and the
    /// recovery ciphertext are always written together — a key can never be stored
    /// with a hash but no ciphertext, which would make it silently unrecoverable.
    fn mint_license_key(&self) -> (String, Vec<u8>, Option<Vec<u8>>) {
        let key = generate_secret("sclk_");
        let hash = token_hash(&key);
        let ciphertext = self.encrypt_key(&key);
        (key, hash, ciphertext)
    }

    /// Health probe: one round-trip to Postgres (backs the `/healthz`
    /// endpoints).
    pub async fn ping(&self) -> Result<(), sqlx::Error> {
        sqlx::query("select 1").execute(&self.pool).await?;
        Ok(())
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

    /// Resolve `(org, repo)` to its **canonical** location, following one or both
    /// renamed slugs via `slug_history`. `moved` is true when the request used an
    /// old slug (the wire router 301s it). `None` if neither resolves. Chained
    /// renames resolve to the final slug because history rows are repointed to the
    /// current entity id and the final lookup is always against the live tables.
    pub async fn resolve_repo_canonical(
        &self,
        org: &str,
        repo: &str,
    ) -> Result<Option<RepoLocation>, sqlx::Error> {
        // 1. Resolve the org slug → (org_id, canonical slug, moved?).
        let live_org: Option<(Uuid, String)> =
            sqlx::query_as("select id, slug from organizations where slug = $1")
                .bind(org)
                .fetch_optional(&self.pool)
                .await?;
        let (org_id, org_slug, org_moved) = if let Some((id, slug)) = live_org {
            (id, slug, false)
        } else {
            let hist: Option<(Uuid, String)> = sqlx::query_as(
                "select o.id, o.slug from slug_history h join organizations o on o.id = h.entity_id \
                 where h.entity_type = 'org' and h.old_slug = $1",
            )
            .bind(org)
            .fetch_optional(&self.pool)
            .await?;
            let Some((id, slug)) = hist else {
                return Ok(None);
            };
            (id, slug, true)
        };
        // 2. Resolve the repo slug within that org → (repo_id, canonical slug, moved?).
        let live_repo: Option<(Uuid, String)> =
            sqlx::query_as("select id, slug from repositories where org_id = $1 and slug = $2")
                .bind(org_id)
                .bind(repo)
                .fetch_optional(&self.pool)
                .await?;
        let (repo_id, repo_slug, repo_moved) = if let Some((id, slug)) = live_repo {
            (id, slug, false)
        } else {
            let hist: Option<(Uuid, String)> = sqlx::query_as(
                "select r.id, r.slug from slug_history h join repositories r on r.id = h.entity_id \
                 where h.entity_type = 'repo' and h.org_id = $1 and h.old_slug = $2",
            )
            .bind(org_id)
            .bind(repo)
            .fetch_optional(&self.pool)
            .await?;
            let Some((id, slug)) = hist else {
                return Ok(None);
            };
            (id, slug, true)
        };
        Ok(Some(RepoLocation {
            repo_id,
            org_slug,
            repo_slug,
            moved: org_moved || repo_moved,
        }))
    }

    /// Former (retired) slugs for an entity, newest first — for showing "formerly
    /// known as" on the settings page.
    pub async fn former_slugs(
        &self,
        entity_type: &str,
        entity_id: Uuid,
    ) -> Result<Vec<String>, sqlx::Error> {
        let rows = sqlx::query(
            "select old_slug from slug_history \
             where entity_type = $1 and entity_id = $2 order by retired_at desc",
        )
        .bind(entity_type)
        .bind(entity_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(|r| r.try_get("old_slug")).collect()
    }

    /// Whether an org slug is **retired** (in history) — the guard that blocks
    /// re-registering a name that still redirects elsewhere.
    pub async fn org_slug_retired(&self, slug: &str) -> Result<bool, sqlx::Error> {
        sqlx::query_scalar(
            "select exists(select 1 from slug_history where entity_type = 'org' and old_slug = $1)",
        )
        .bind(slug)
        .fetch_one(&self.pool)
        .await
    }

    /// As [`Self::org_slug_retired`], scoped within an org for a repo slug.
    pub async fn repo_slug_retired(&self, org_id: Uuid, slug: &str) -> Result<bool, sqlx::Error> {
        sqlx::query_scalar(
            "select exists(select 1 from slug_history \
             where entity_type = 'repo' and org_id = $1 and old_slug = $2)",
        )
        .bind(org_id)
        .bind(slug)
        .fetch_one(&self.pool)
        .await
    }

    /// Whether an org slug is in use by a live org **or** retired in history — the
    /// guard that keeps a retired slug from being re-registered.
    pub async fn org_slug_unavailable(&self, slug: &str) -> Result<bool, sqlx::Error> {
        sqlx::query_scalar(
            "select exists(select 1 from organizations where slug = $1) \
                 or exists(select 1 from slug_history where entity_type = 'org' and old_slug = $1)",
        )
        .bind(slug)
        .fetch_one(&self.pool)
        .await
    }

    /// Resolve a live org slug to its id (`None` if no such org).
    pub async fn org_id_by_slug(&self, slug: &str) -> Result<Option<Uuid>, sqlx::Error> {
        sqlx::query_scalar("select id from organizations where slug = $1")
            .bind(slug)
            .fetch_optional(&self.pool)
            .await
    }

    /// As [`Self::org_slug_unavailable`], scoped within an org for a repo slug.
    pub async fn repo_slug_unavailable(
        &self,
        org_id: Uuid,
        slug: &str,
    ) -> Result<bool, sqlx::Error> {
        sqlx::query_scalar(
            "select exists(select 1 from repositories where org_id = $1 and slug = $2) \
                 or exists(select 1 from slug_history \
                           where entity_type = 'repo' and org_id = $1 and old_slug = $2)",
        )
        .bind(org_id)
        .bind(slug)
        .fetch_one(&self.pool)
        .await
    }

    /// Rename an org: record the old slug in `slug_history` (so it redirects) and
    /// switch to `new_slug`. Rejects a name that's live or retired.
    pub async fn rename_org(&self, org_id: Uuid, new_slug: &str) -> Result<(), RenameError> {
        let new_slug = new_slug.trim();
        if new_slug.is_empty() {
            return Err(RenameError::Invalid);
        }
        let current: Option<String> =
            sqlx::query_scalar("select slug from organizations where id = $1")
                .bind(org_id)
                .fetch_optional(&self.pool)
                .await?;
        let Some(current) = current else {
            return Err(RenameError::Invalid);
        };
        if current == new_slug {
            return Ok(());
        }
        if self.org_slug_unavailable(new_slug).await? {
            // Distinguish live-taken from retired for a clearer message.
            let live: bool =
                sqlx::query_scalar("select exists(select 1 from organizations where slug = $1)")
                    .bind(new_slug)
                    .fetch_one(&self.pool)
                    .await?;
            return Err(if live {
                RenameError::Taken
            } else {
                RenameError::Retired
            });
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "insert into slug_history (entity_type, old_slug, entity_id) values ('org', $1, $2)",
        )
        .bind(&current)
        .bind(org_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query("update organizations set slug = $2 where id = $1")
            .bind(org_id)
            .bind(new_slug)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Permanently delete a repo (cascades packages/versions/tokens/upstreams/
    /// grants/licenses via FKs) and **retire its slug** so old `composer.lock`
    /// URLs can't be silently re-pointed at a different repo (a retired slug is
    /// blocked from re-creation; with no live target it simply 404s). Returns
    /// whether a repo was deleted.
    pub async fn delete_repo(&self, repo_id: Uuid) -> Result<bool, sqlx::Error> {
        let row: Option<(Uuid, String)> =
            sqlx::query_as("select org_id, slug from repositories where id = $1")
                .bind(repo_id)
                .fetch_optional(&self.pool)
                .await?;
        let Some((org_id, slug)) = row else {
            return Ok(false);
        };
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "insert into slug_history (entity_type, old_slug, org_id, entity_id) \
             values ('repo', $1, $2, $3)",
        )
        .bind(&slug)
        .bind(org_id)
        .bind(repo_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query("delete from repositories where id = $1")
            .bind(repo_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Rename a repo within its org: record the old slug and switch to `new_slug`.
    pub async fn rename_repo(&self, repo_id: Uuid, new_slug: &str) -> Result<(), RenameError> {
        let new_slug = new_slug.trim();
        if new_slug.is_empty() {
            return Err(RenameError::Invalid);
        }
        let row: Option<(Uuid, String)> =
            sqlx::query_as("select org_id, slug from repositories where id = $1")
                .bind(repo_id)
                .fetch_optional(&self.pool)
                .await?;
        let Some((org_id, current)) = row else {
            return Err(RenameError::Invalid);
        };
        if current == new_slug {
            return Ok(());
        }
        if self.repo_slug_unavailable(org_id, new_slug).await? {
            let live: bool = sqlx::query_scalar(
                "select exists(select 1 from repositories where org_id = $1 and slug = $2)",
            )
            .bind(org_id)
            .bind(new_slug)
            .fetch_one(&self.pool)
            .await?;
            return Err(if live {
                RenameError::Taken
            } else {
                RenameError::Retired
            });
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "insert into slug_history (entity_type, old_slug, org_id, entity_id) \
             values ('repo', $1, $2, $3)",
        )
        .bind(&current)
        .bind(org_id)
        .bind(repo_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query("update repositories set slug = $2 where id = $1")
            .bind(repo_id)
            .bind(new_slug)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
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

    /// Repositories in one org, newest-slug-ordered. Backs the `/api/v1/repos`
    /// discovery endpoint an org-scoped read token hits so `bougie login` can
    /// auto-provision a project's Composer `repositories`.
    pub async fn repos_for_org(&self, org_id: Uuid) -> Result<Vec<RepoSummary>, sqlx::Error> {
        let rows = sqlx::query(
            "select o.slug as org, o.id as org_id, r.slug as repo, r.id as id, \
                    r.update_mode as update_mode, r.cooldown_days as cooldown_days \
             from repositories r join organizations o on o.id = r.org_id \
             where r.org_id = $1 \
             order by r.slug",
        )
        .bind(org_id)
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

    /// Repos in an org with per-repo counts + last sync — the C1 org overview.
    pub async fn org_repo_overview(&self, org_id: Uuid) -> Result<Vec<RepoOverview>, sqlx::Error> {
        let rows = sqlx::query(
            "select r.slug as slug, r.allow_private_packages as allow_private_packages, \
                    r.update_mode as update_mode, \
                    count(p.id) as packages, \
                    count(p.id) filter (where p.sync_health = 'broken' and p.archived_at is null) as broken, \
                    to_char(max(p.last_success_at), 'YYYY-MM-DD HH24:MI') as last_sync \
             from repositories r left join packages p on p.repo_id = r.id \
             where r.org_id = $1 \
             group by r.id, r.slug, r.allow_private_packages, r.update_mode \
             order by r.slug",
        )
        .bind(org_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                Ok(RepoOverview {
                    slug: row.try_get("slug")?,
                    allow_private_packages: row.try_get("allow_private_packages")?,
                    update_mode: row.try_get("update_mode")?,
                    packages: row.try_get("packages")?,
                    broken: row.try_get("broken")?,
                    last_sync: row.try_get("last_sync")?,
                })
            })
            .collect()
    }

    /// Repos with overview data (visibility, package + broken counts, last sync)
    /// across the given orgs — `None` = all orgs. Powers the home dashboard in a
    /// single query. Ordered by org then slug so the UI can group in one pass.
    pub async fn home_repo_overview(
        &self,
        org_ids: Option<&[Uuid]>,
    ) -> Result<Vec<HomeRepo>, sqlx::Error> {
        let rows = sqlx::query(
            "select r.org_id as org_id, r.slug as slug, \
                    r.allow_private_packages as allow_private_packages, \
                    r.update_mode as update_mode, r.cooldown_days as cooldown_days, \
                    count(distinct p.id) as packages, \
                    count(distinct p.id) filter \
                        (where p.sync_health = 'broken' and p.archived_at is null) as broken, \
                    count(pv.id) filter (where pv.held_at is null and pv.yanked_at is null \
                        and pv.approved_at is null \
                        and ( r.update_mode = 'manual' \
                              or ( r.update_mode = 'delayed' \
                                   and ( pv.released_at is null \
                                         or pv.released_at + make_interval(days => r.cooldown_days) > now() ) ) )) \
                        as pending, \
                    to_char(max(p.last_success_at), 'YYYY-MM-DD HH24:MI') as last_sync \
             from repositories r \
             left join packages p on p.repo_id = r.id \
             left join package_versions pv on pv.package_id = p.id \
             where ($1::uuid[] is null or r.org_id = any($1)) \
             group by r.id, r.org_id, r.slug, r.allow_private_packages, r.update_mode, r.cooldown_days \
             order by r.org_id, r.slug",
        )
        .bind(org_ids)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                Ok(HomeRepo {
                    org_id: row.try_get("org_id")?,
                    slug: row.try_get("slug")?,
                    allow_private_packages: row.try_get("allow_private_packages")?,
                    update_mode: row.try_get("update_mode")?,
                    cooldown_days: row.try_get("cooldown_days")?,
                    packages: row.try_get("packages")?,
                    broken: row.try_get("broken")?,
                    pending: row.try_get("pending")?,
                    last_sync: row.try_get("last_sync")?,
                })
            })
            .collect()
    }

    /// Every version of every package **owned** by a repo, with control state —
    /// the admin view (unlike `visible_versions`, it ignores policy/holds so the
    /// operator can see and act on everything).
    /// Total package-versions in a repo matching the optional name (`ilike`) and
    /// state (`held`|`yanked`|`approved`) filters — for the paginator.
    pub async fn count_package_versions(
        &self,
        repo_id: Uuid,
        name: Option<&str>,
        state: Option<&str>,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(&format!(
            "select count(*) from package_versions pv \
             join packages p on p.id = pv.package_id \
             join repositories r on r.id = $1 \
             where p.repo_id = $1 {VERSION_FILTER}"
        ))
        .bind(repo_id)
        .bind(name)
        .bind(state)
        .fetch_one(&self.pool)
        .await
    }

    pub async fn admin_package_versions(
        &self,
        repo_id: Uuid,
        limit: i64,
        offset: i64,
        name: Option<&str>,
        state: Option<&str>,
    ) -> Result<Vec<AdminVersion>, sqlx::Error> {
        let rows = sqlx::query(&format!(
            "select p.name as package, pv.version, pv.normalized_version, pv.stability, \
                    (pv.held_at is not null) as held, (pv.approved_at is not null) as approved, \
                    (pv.yanked_at is not null) as yanked, \
                    pv.released_at::text as released_at, \
                    case when pv.released_at is null then null else \
                        greatest(0, ceil(extract(epoch from \
                            (pv.released_at + make_interval(days => r.cooldown_days) - now())) / 86400))::bigint \
                    end as cooldown_days_left, \
                    pv.dist_shasum as dist_shasum, pv.source_reference as source_reference \
             from package_versions pv \
             join packages p on p.id = pv.package_id \
             join repositories r on r.id = $1 \
             where p.repo_id = $1 {VERSION_FILTER} \
             -- Lexicographic on the normalized string (so 1.10 sorts before
             -- 1.9). Unlike package_versions/visible_versions, this list is
             -- LIMIT/OFFSET paginated, so it can't be re-sorted in Rust after
             -- the fetch; a Composer-correct order needs a sort-key column.
             order by p.name, pv.normalized_version \
             limit $4 offset $5"
        ))
        .bind(repo_id)
        .bind(name)
        .bind(state)
        .bind(limit)
        .bind(offset)
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
                    dist_shasum: row.try_get("dist_shasum")?,
                    source_reference: row.try_get("source_reference")?,
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
                    l.update_mode as update_mode, l.cooldown_days as cooldown_days, \
                    to_char(l.update_until, 'YYYY-MM-DD') as bound_until, \
                    extract(epoch from l.update_until)::bigint as bound_until_unix, \
                    l.version_cap_major as bound_major, \
                    coalesce(array_agg(distinct p.name) filter (where p.name is not null), '{}') as packages, \
                    coalesce(array_agg(distinct ps.id::text || '|' || ps.name || '|' \
                                       || coalesce(to_char(lse.update_until, 'YYYY-MM-DD'), '') || '|' \
                                       || coalesce(lse.version_cap_major::text, '')) \
                             filter (where ps.id is not null), '{}') as sets \
             from license_keys l \
             left join entitlements e on e.license_key_id = l.id \
             left join packages p on p.id = e.package_id \
             left join license_set_entitlements lse on lse.license_key_id = l.id \
             left join package_sets ps on ps.id = lse.set_id \
             where l.repo_id = $1 \
             group by l.id, l.buyer_ref, l.status, l.update_mode, l.cooldown_days, \
                      l.update_until, l.version_cap_major, l.created_at \
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
                    sets: {
                        let raw: Vec<String> = row.try_get("sets")?;
                        raw.iter()
                            .filter_map(|s| {
                                // "id|name|edge_until|edge_major" (empty = none).
                                let mut parts = s.splitn(4, '|');
                                let id = parts.next()?.parse().ok()?;
                                let name = parts.next()?.to_owned();
                                let until = parts.next().filter(|u| !u.is_empty());
                                let major = parts.next().and_then(|m| m.parse::<i32>().ok());
                                Some((
                                    id,
                                    name,
                                    LicenseBound {
                                        until: until.map(str::to_owned),
                                        until_unix: None,
                                        major,
                                    },
                                ))
                            })
                            .collect()
                    },
                    policy: PolicyOverride {
                        update_mode: row.try_get("update_mode").ok().flatten(),
                        cooldown_days: row.try_get("cooldown_days").ok().flatten(),
                    },
                    bound: LicenseBound {
                        until: row.try_get("bound_until").ok().flatten(),
                        until_unix: row.try_get("bound_until_unix").ok().flatten(),
                        major: row.try_get("bound_major").ok().flatten(),
                    },
                })
            })
            .collect()
    }

    /// Packages granted into a repository (with where they're owned).
    pub async fn list_grants(&self, repo_id: Uuid) -> Result<Vec<GrantSummary>, sqlx::Error> {
        let rows = sqlx::query(
            "select p.name as package, o.slug as source_org, r.slug as source_repo, \
                    g.update_mode as update_mode, g.cooldown_days as cooldown_days \
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
                    policy: PolicyOverride {
                        update_mode: row.try_get("update_mode").ok().flatten(),
                        cooldown_days: row.try_get("cooldown_days").ok().flatten(),
                    },
                })
            })
            .collect()
    }

    /// The grant-scoped policy for a package served into `repo_id` via a grant
    /// (empty if owned, ungranted, or no override). Folded into serving after the
    /// credential policy, tighten-only.
    pub async fn grant_policy(
        &self,
        repo_id: Uuid,
        package: &str,
    ) -> Result<PolicyOverride, sqlx::Error> {
        let row = sqlx::query(
            "select g.update_mode, g.cooldown_days from repository_grants g \
             join packages p on p.id = g.package_id \
             where g.repo_id = $1 and p.name = $2 limit 1",
        )
        .bind(repo_id)
        .bind(package)
        .fetch_optional(&self.pool)
        .await?;
        Ok(
            row.map_or_else(PolicyOverride::default, |r| PolicyOverride {
                update_mode: r.try_get("update_mode").ok().flatten(),
                cooldown_days: r.try_get("cooldown_days").ok().flatten(),
            }),
        )
    }

    /// Set (or clear) the grant-scoped policy for a granted package, by repo +
    /// package name. Returns whether a grant matched.
    pub async fn set_grant_policy(
        &self,
        repo_id: Uuid,
        package: &str,
        policy: &PolicyOverride,
    ) -> Result<bool, sqlx::Error> {
        let n = sqlx::query(
            "update repository_grants g set update_mode = $3, cooldown_days = $4 \
             from packages p where p.id = g.package_id and g.repo_id = $1 and p.name = $2",
        )
        .bind(repo_id)
        .bind(package)
        .bind(policy.update_mode.as_deref())
        .bind(policy.cooldown_days)
        .execute(&self.pool)
        .await?;
        Ok(n.rows_affected() > 0)
    }

    // ----- autogrant rules (subscribe a repo to a package set) -----

    /// Subscribe `target_repo_id` to a package set — every package the set
    /// resolves to (now and later) is granted into the repo. Idempotent.
    pub async fn add_grant_rule(
        &self,
        target_repo_id: Uuid,
        set_id: Uuid,
    ) -> Result<(), EntitlementError> {
        // Autogrant (a shared-repo "house bundle") is the agency-mode feature.
        let org_id = self.org_of_repo(target_repo_id).await?;
        self.require_feature(org_id, Feature::Agency).await?;
        sqlx::query(
            "insert into repository_grant_rules (target_repo_id, set_id) values ($1, $2) \
             on conflict do nothing",
        )
        .bind(target_repo_id)
        .bind(set_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Remove an autogrant rule (un-subscribe), scoped to the target repo.
    pub async fn remove_grant_rule(
        &self,
        target_repo_id: Uuid,
        rule_id: Uuid,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("delete from repository_grant_rules where id = $1 and target_repo_id = $2")
            .bind(rule_id)
            .bind(target_repo_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// A repo's autogrant rules: `(rule_id, set_id, set_name)`.
    pub async fn list_grant_rules(
        &self,
        target_repo_id: Uuid,
    ) -> Result<Vec<(Uuid, Uuid, String)>, sqlx::Error> {
        sqlx::query_as(
            "select gr.id, ps.id, ps.name from repository_grant_rules gr \
             join package_sets ps on ps.id = gr.set_id \
             where gr.target_repo_id = $1 order by ps.name",
        )
        .bind(target_repo_id)
        .fetch_all(&self.pool)
        .await
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

    /// Remove a user's membership in an org entirely. (Sessions stay valid for
    /// the user's other tenants; `resolve_session` only honors active memberships
    /// anyway.) Returns whether a membership was removed.
    pub async fn remove_from_tenant(
        &self,
        email: &str,
        org_slug: &str,
    ) -> Result<bool, sqlx::Error> {
        let n = sqlx::query(
            "delete from user_tenants ut using users u, organizations o \
             where ut.user_id = u.id and ut.org_id = o.id and u.email = $1 and o.slug = $2",
        )
        .bind(email)
        .bind(org_slug)
        .execute(&self.pool)
        .await?;
        Ok(n.rows_affected() > 0)
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

    /// A user's email (for the account page).
    pub async fn user_email(&self, user_id: Uuid) -> Result<Option<String>, sqlx::Error> {
        sqlx::query_scalar("select email from users where id = $1")
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await
    }

    /// A user's active login sessions, newest first. `current_token` marks which
    /// row is *this* session. The hex of the token hash identifies a session for
    /// revocation (the token itself is never stored).
    pub async fn list_sessions(
        &self,
        user_id: Uuid,
        current_token: Option<&str>,
    ) -> Result<Vec<SessionInfo>, sqlx::Error> {
        let current_hex = current_token.map(|t| hex_lower(&token_hash(t)));
        let rows = sqlx::query(
            "select encode(token_hash, 'hex') as h, \
                    to_char(created_at, 'YYYY-MM-DD HH24:MI') as created, \
                    to_char(expires_at, 'YYYY-MM-DD HH24:MI') as expires \
             from sessions where user_id = $1 and expires_at > now() order by created_at desc",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                let h: String = r.try_get("h")?;
                Ok(SessionInfo {
                    current: current_hex.as_deref() == Some(h.as_str()),
                    hash_hex: h,
                    created: r.try_get("created")?,
                    expires: r.try_get("expires")?,
                })
            })
            .collect()
    }

    /// Revoke one of a user's sessions by the hex of its token hash. Scoped to the
    /// user so nobody can revoke another's session.
    pub async fn revoke_session_for_user(
        &self,
        user_id: Uuid,
        hash_hex: &str,
    ) -> Result<bool, sqlx::Error> {
        let n = sqlx::query(
            "delete from sessions where user_id = $1 and encode(token_hash, 'hex') = $2",
        )
        .bind(user_id)
        .bind(hash_hex)
        .execute(&self.pool)
        .await?;
        Ok(n.rows_affected() > 0)
    }

    /// All users with their tenant slugs — for the superadmin user list.
    pub async fn list_users(&self) -> Result<Vec<UserSummary>, sqlx::Error> {
        let rows = sqlx::query(
            "select u.email as email, u.is_superadmin as is_superadmin, \
                    coalesce(json_agg(json_build_object('slug', o.slug, 'role', ut.role, \
                        'active', ut.active) order by o.slug) filter (where o.slug is not null), '[]') as tenants \
             from users u \
             left join user_tenants ut on ut.user_id = u.id \
             left join organizations o on o.id = ut.org_id \
             group by u.id, u.email, u.is_superadmin order by u.email",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                let tj: Value = row.try_get("tenants")?;
                let tenants = tj
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| {
                                Some(TenantMembership {
                                    slug: v.get("slug")?.as_str()?.to_owned(),
                                    role: v.get("role")?.as_str()?.to_owned(),
                                    active: v.get("active")?.as_bool()?,
                                })
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                Ok(UserSummary {
                    email: row.try_get("email")?,
                    is_superadmin: row.try_get("is_superadmin")?,
                    tenants,
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
    ) -> Result<(), EntitlementError> {
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
        // Org-scoped SSO is the gated tenant feature; the instance default
        // (org_slug None) is the operator's own login and always allowed.
        if let Some(id) = org_id {
            self.require_feature(id, Feature::Sso).await?;
        }
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

    const OIDC_SELECT: &'static str = "select c.id, o.slug as org_slug, c.issuer_url, c.client_id, c.client_secret, \
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

    /// The OIDC connection scoped to a specific org (`org_id = $1`), if any.
    pub async fn oidc_connection_for_org(
        &self,
        org_id: Uuid,
    ) -> Result<Option<OidcConnection>, sqlx::Error> {
        let row = sqlx::query(&format!("{} where c.org_id = $1", Self::OIDC_SELECT))
            .bind(org_id)
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
    ///
    /// The row is deleted **regardless of expiry** — consuming an expired flow
    /// still cleans it up (so expired rows don't accumulate, and a stale `state`
    /// can be reused) — but an expired flow returns `None`, never its payload.
    pub async fn consume_oidc_flow(
        &self,
        state: &str,
    ) -> Result<Option<(Option<Uuid>, String, String, String)>, sqlx::Error> {
        let row = sqlx::query(
            "delete from oidc_flows where state = $1 \
             returning conn_id, nonce, pkce_verifier, redirect_to, expires_at > now() as fresh",
        )
        .bind(state)
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            Some(r) if r.try_get::<bool, _>("fresh")? => Some((
                r.try_get("conn_id")?,
                r.try_get("nonce")?,
                r.try_get("pkce_verifier")?,
                r.try_get("redirect_to")?,
            )),
            // Unknown state, or it existed but had expired (now deleted).
            _ => None,
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
    pub async fn create_scim_token(
        &self,
        org_slug: &str,
    ) -> Result<Option<String>, EntitlementError> {
        let Some(org_id): Option<Uuid> =
            sqlx::query_scalar("select id from organizations where slug = $1")
                .bind(org_slug)
                .fetch_optional(&self.pool)
                .await?
        else {
            return Ok(None);
        };
        self.require_feature(org_id, Feature::Scim).await?;
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
        let done =
            sqlx::query("update user_tenants set active = $3 where org_id = $1 and user_id = $2")
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

    /// Begin a password reset for `email`: mint a single-use token (returning its
    /// plaintext) and store only its hash. Returns `None` when no user has that
    /// email — the caller must respond identically either way (no enumeration).
    /// Any earlier outstanding resets for the user are dropped (one live link).
    pub async fn create_password_reset(
        &self,
        email: &str,
        ttl_minutes: i64,
    ) -> Result<Option<PasswordReset>, sqlx::Error> {
        let Some(user_id): Option<Uuid> =
            sqlx::query_scalar("select id from users where email = $1")
                .bind(email)
                .fetch_optional(&self.pool)
                .await?
        else {
            return Ok(None);
        };
        let mut tx = self.pool.begin().await?;
        sqlx::query("delete from password_resets where user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        let token = generate_secret("scpr_");
        sqlx::query(
            "insert into password_resets (token_hash, user_id, expires_at) \
             values ($1, $2, now() + make_interval(mins => $3::int))",
        )
        .bind(token_hash(&token))
        .bind(user_id)
        .bind(i32::try_from(ttl_minutes).unwrap_or(i32::MAX))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Some(PasswordReset { user_id, token }))
    }

    /// Whether a reset token is currently valid (unexpired, unused) — for showing
    /// the set-new-password form without consuming the token.
    pub async fn password_reset_valid(&self, token: &str) -> Result<bool, sqlx::Error> {
        let ok: Option<i32> = sqlx::query_scalar(
            "select 1 from password_resets \
             where token_hash = $1 and used_at is null and expires_at > now()",
        )
        .bind(token_hash(token))
        .fetch_optional(&self.pool)
        .await?;
        Ok(ok.is_some())
    }

    /// Consume a reset token and set the user's new password in one transaction:
    /// validates the token is unexpired+unused, stamps it used, writes the new
    /// hash, and revokes every existing session for that user. Returns the user id
    /// on success, or `None` if the token is unknown/expired/already used.
    pub async fn reset_password(
        &self,
        token: &str,
        new_password: &str,
    ) -> Result<Option<Uuid>, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        // Mark used (single-use, race-safe): only a still-valid row updates.
        let user_id: Option<Uuid> = sqlx::query_scalar(
            "update password_resets set used_at = now() \
             where token_hash = $1 and used_at is null and expires_at > now() \
             returning user_id",
        )
        .bind(token_hash(token))
        .fetch_optional(&mut *tx)
        .await?;
        let Some(user_id) = user_id else {
            tx.rollback().await?;
            return Ok(None);
        };
        sqlx::query("update users set password_hash = $2 where id = $1")
            .bind(user_id)
            .bind(hash_password(new_password))
            .execute(&mut *tx)
            .await?;
        // A reset invalidates existing logins — the user re-authenticates.
        sqlx::query("delete from sessions where user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Some(user_id))
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
    #[allow(clippy::too_many_arguments)]
    pub async fn add_ci_policy(
        &self,
        repo_id: Uuid,
        provider: &str,
        issuer: &str,
        audience: &str,
        claims: &Value,
        token_ttl_secs: i64,
        capability: &str,
    ) -> Result<Uuid, sqlx::Error> {
        sqlx::query_scalar(
            "insert into ci_oidc_policies \
                 (repo_id, provider, issuer, audience, claims, token_ttl_secs, capability) \
             values ($1, $2, $3, $4, $5, $6, $7) returning id",
        )
        .bind(repo_id)
        .bind(provider)
        .bind(issuer)
        .bind(audience)
        .bind(claims)
        .bind(token_ttl_secs)
        .bind(capability)
        .fetch_one(&self.pool)
        .await
    }

    /// A repo's CI OIDC policies.
    pub async fn ci_policies(&self, repo_id: Uuid) -> Result<Vec<CiPolicy>, sqlx::Error> {
        let rows = sqlx::query(
            "select id, repo_id, provider, issuer, audience, claims, token_ttl_secs, capability \
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
                    capability: r.try_get("capability")?,
                })
            })
            .collect()
    }

    /// Remove a CI OIDC policy by id, scoped to its repo. Returns whether one was
    /// removed.
    pub async fn delete_ci_policy(&self, repo_id: Uuid, id: Uuid) -> Result<bool, sqlx::Error> {
        let n = sqlx::query("delete from ci_oidc_policies where repo_id = $1 and id = $2")
            .bind(repo_id)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(n.rows_affected() > 0)
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

    /// Mint an **org-scoped** read token (origin `session`) — the credential a
    /// device login issues. Like [`Catalog::create_ci_token`] it bypasses the
    /// `allow_raw_tokens` policy (a session-derived, deprovisionable, expiring
    /// credential, not a raw operator secret). Valid for every repo in the org
    /// (see [`Catalog::token_valid`]).
    pub async fn create_session_token(
        &self,
        org_id: Uuid,
        label: &str,
        ttl_secs: i64,
    ) -> Result<String, sqlx::Error> {
        let token = generate_token();
        sqlx::query(
            "insert into tokens (org_id, token_hash, label, expires_at, origin) values \
             ($1, $2, $3, now() + make_interval(secs => $4::double precision), 'session')",
        )
        .bind(org_id)
        .bind(token_hash(&token))
        .bind(label)
        .bind(ttl_secs)
        .execute(&self.pool)
        .await?;
        Ok(token)
    }

    /// Open a device-authorization flow (RFC 8628). Generates the opaque
    /// `device_code` (returned to the CLI, stored only as its sha256) and the
    /// short human `user_code` the user types into the approval page. Returns
    /// `(device_code, user_code)`. TTL in seconds.
    pub async fn start_device_flow(&self, ttl_secs: i64) -> Result<(String, String), sqlx::Error> {
        let device_code = generate_secret("scdv_");
        let user_code = generate_user_code();
        sqlx::query(
            "insert into device_flows (device_code_hash, user_code, expires_at) values \
             ($1, $2, now() + make_interval(secs => $3::double precision))",
        )
        .bind(token_hash(&device_code))
        .bind(&user_code)
        .bind(ttl_secs)
        .execute(&self.pool)
        .await?;
        Ok((device_code, user_code))
    }

    /// Whether `user_code` names a flow still awaiting approval (pending + not
    /// expired) — gates the approval page.
    pub async fn device_flow_pending(&self, user_code: &str) -> Result<bool, sqlx::Error> {
        sqlx::query_scalar(
            "select exists (select 1 from device_flows \
             where user_code = $1 and status = 'pending' and expires_at > now())",
        )
        .bind(user_code)
        .fetch_one(&self.pool)
        .await
    }

    /// Approve a pending device flow: bind the chosen `org_id` + approver and
    /// flip it to `approved`. Returns `false` if there's no matching pending +
    /// fresh flow (unknown / expired / already-decided code).
    pub async fn approve_device_flow(
        &self,
        user_code: &str,
        org_id: Uuid,
        approved_by: Option<Uuid>,
    ) -> Result<bool, sqlx::Error> {
        let updated = sqlx::query(
            "update device_flows set status = 'approved', org_id = $2, approved_by = $3 \
             where user_code = $1 and status = 'pending' and expires_at > now()",
        )
        .bind(user_code)
        .bind(org_id)
        .bind(approved_by)
        .execute(&self.pool)
        .await?;
        Ok(updated.rows_affected() > 0)
    }

    /// Deny a pending device flow, so the CLI's next poll fails fast with
    /// `access_denied` instead of waiting out the TTL. No-op for an unknown or
    /// already-decided code.
    pub async fn deny_device_flow(&self, user_code: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            "update device_flows set status = 'denied' \
             where user_code = $1 and status = 'pending' and expires_at > now()",
        )
        .bind(user_code)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Poll a device flow by its `device_code`. On approval this **consumes** the
    /// flow (deletes the row) and returns the org to mint a token for — a
    /// `device_code` is thus single-use. Pending flows are left in place.
    pub async fn poll_device_flow(&self, device_code: &str) -> Result<DeviceFlowPoll, sqlx::Error> {
        let hash = token_hash(device_code);
        // Consume an approved + fresh flow atomically.
        if let Some(org_id) = sqlx::query_scalar::<_, Uuid>(
            "delete from device_flows \
             where device_code_hash = $1 and status = 'approved' and expires_at > now() \
             returning org_id",
        )
        .bind(&hash)
        .fetch_optional(&self.pool)
        .await?
        {
            return Ok(DeviceFlowPoll::Approved { org_id });
        }
        // Otherwise report the current state.
        let row = sqlx::query(
            "select status, expires_at > now() as fresh from device_flows \
             where device_code_hash = $1",
        )
        .bind(&hash)
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            None => DeviceFlowPoll::Expired,
            Some(r) => {
                let fresh: bool = r.try_get("fresh")?;
                let status: String = r.try_get("status")?;
                if !fresh {
                    DeviceFlowPoll::Expired
                } else if status == "denied" {
                    DeviceFlowPoll::Denied
                } else {
                    DeviceFlowPoll::Pending
                }
            }
        })
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
    /// Record a blob's presence in the catalog. Called by the mirror worker
    /// right before it references the blob from a version, so the conflict path
    /// bumps `last_seen_at` — a blob that is about to be referenced is thereby
    /// freshly "seen", which is what keeps GC's grace window from racing an
    /// in-flight mirror job (see [`Self::orphan_blobs`]). `refcount` is left
    /// alone: it is owned by the `package_versions` triggers.
    pub async fn upsert_blob(&self, sha256: &[u8; 32], size_bytes: i64) -> Result<(), sqlx::Error> {
        sqlx::query(
            "insert into blobs (sha256, size_bytes) values ($1, $2) \
             on conflict (sha256) do update set last_seen_at = now()",
        )
        .bind(&sha256[..])
        .bind(size_bytes)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Aggregate blob-storage accounting: total blobs + bytes, and how much of
    /// that is currently orphaned (refcount 0) — the reclaimable slice. Backs
    /// `sconce gc` reporting and storage-metering visibility.
    pub async fn storage_stats(&self) -> Result<StorageStats, sqlx::Error> {
        // sum(bigint) is numeric in Postgres — cast back to bigint for decode.
        let row: (i64, i64, i64, i64) = sqlx::query_as(
            "select \
                 count(*), \
                 coalesce(sum(size_bytes), 0)::bigint, \
                 coalesce(sum(size_bytes) filter (where refcount = 0), 0)::bigint, \
                 count(*) filter (where refcount = 0) \
             from blobs",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(StorageStats {
            blob_count: row.0,
            total_bytes: row.1,
            orphan_bytes: row.2,
            orphan_count: row.3,
        })
    }

    /// Orphan blobs eligible for collection: refcount 0 **and** untouched for at
    /// least `grace` (so a blob a mirror job just wrote but hasn't referenced
    /// yet is protected). The caller deletes each from the object store, then
    /// confirms removal with [`Self::delete_blob_if_orphan`] — which re-checks
    /// the guard, so a blob re-referenced in between is never collected.
    pub async fn orphan_blobs(&self, grace: Duration) -> Result<Vec<BlobRef>, sqlx::Error> {
        let grace_secs = grace.as_secs_f64();
        let rows: Vec<(Vec<u8>, i64)> = sqlx::query_as(
            "select sha256, size_bytes from blobs \
             where refcount = 0 \
               and last_seen_at < now() - make_interval(secs => $1) \
             order by last_seen_at",
        )
        .bind(grace_secs)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().filter_map(BlobRef::from_row).collect())
    }

    /// Delete a blob row **iff it is still an orphan** past `grace`: the guard is
    /// re-evaluated atomically here, so a version inserted since the scan (which
    /// bumped `refcount` via trigger, or `last_seen_at` via [`Self::upsert_blob`])
    /// keeps the row. Returns whether the row was deleted. A blob genuinely
    /// referenced by a `package_versions` row can never be deleted — the foreign
    /// key would forbid it even if the guard somehow passed.
    pub async fn delete_blob_if_orphan(
        &self,
        sha256: &[u8; 32],
        grace: Duration,
    ) -> Result<bool, sqlx::Error> {
        let n = sqlx::query(
            "delete from blobs \
             where sha256 = $1 \
               and refcount = 0 \
               and last_seen_at < now() - make_interval(secs => $2)",
        )
        .bind(&sha256[..])
        .bind(grace.as_secs_f64())
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// Storage metered to one org — the summed size of the **distinct** blobs
    /// its package versions **and snapshots** reference. Full logical size: a blob
    /// shared with other orgs is counted here in full (no cross-tenant dedup
    /// credit); a blob shared between a package and a snapshot in this org is
    /// counted once. See [`StorageUsage`].
    pub async fn org_storage(&self, org_id: Uuid) -> Result<StorageUsage, sqlx::Error> {
        let (bytes, blob_count): (i64, i64) = sqlx::query_as(
            "select coalesce(sum(size_bytes), 0)::bigint, count(*) from ( \
                 select distinct sha, size_bytes from ( \
                     select pv.dist_blob_sha256 as sha, b.size_bytes \
                     from package_versions pv \
                     join packages p on p.id = pv.package_id \
                     join repositories r on r.id = p.repo_id \
                     join blobs b on b.sha256 = pv.dist_blob_sha256 \
                     where r.org_id = $1 and pv.dist_blob_sha256 is not null \
                     union all \
                     select s.blob_sha256 as sha, b.size_bytes \
                     from snapshots s \
                     join repositories r on r.id = s.repo_id \
                     join blobs b on b.sha256 = s.blob_sha256 \
                     where r.org_id = $1 \
                 ) u \
             ) t",
        )
        .bind(org_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(StorageUsage { bytes, blob_count })
    }

    /// Metered storage for **every** org (including those with none), busiest
    /// first — the billing/admin sweep. Same full-logical-size rule as
    /// [`Self::org_storage`]; summing this across orgs deliberately exceeds the
    /// physically-stored bytes, which is the dedup margin.
    pub async fn storage_by_org(&self) -> Result<Vec<OrgStorage>, sqlx::Error> {
        let rows: Vec<(Uuid, String, Option<String>, i64, i64)> = sqlx::query_as(
            "select o.id, o.slug, o.name, \
                    coalesce(sum(t.size_bytes), 0)::bigint, count(t.sha) \
             from organizations o \
             left join ( \
                 select distinct org_id, sha, size_bytes from ( \
                     select r.org_id, pv.dist_blob_sha256 as sha, b.size_bytes \
                     from package_versions pv \
                     join packages p on p.id = pv.package_id \
                     join repositories r on r.id = p.repo_id \
                     join blobs b on b.sha256 = pv.dist_blob_sha256 \
                     where pv.dist_blob_sha256 is not null \
                     union all \
                     select r.org_id, s.blob_sha256 as sha, b.size_bytes \
                     from snapshots s \
                     join repositories r on r.id = s.repo_id \
                     join blobs b on b.sha256 = s.blob_sha256 \
                 ) u \
             ) t on t.org_id = o.id \
             group by o.id, o.slug, o.name \
             order by 4 desc, o.slug",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(
                |(org_id, org_slug, org_name, bytes, blob_count)| OrgStorage {
                    org_id,
                    org_slug,
                    org_name,
                    usage: StorageUsage { bytes, blob_count },
                },
            )
            .collect())
    }

    /// The entitlements in force for an org. **Returns [`Entitlements::unlimited`]
    /// when no row exists** — so a self-hosted instance, which never writes one,
    /// is unconstrained, and a gate failure-mode is open (`BILLING_PLAN` P2).
    pub async fn entitlements(&self, org_id: Uuid) -> Result<Entitlements, sqlx::Error> {
        // (storage_soft_bytes, max_skus, then the 8 feature flags in column order).
        type Row = (
            Option<i64>,
            Option<i32>,
            bool,
            bool,
            bool,
            bool,
            bool,
            bool,
            bool,
            bool,
        );
        let row: Option<Row> = sqlx::query_as(
            "select storage_soft_bytes, max_skus, feat_agency, feat_sso, feat_multi_oidc, \
                    feat_repo_access, feat_scim, feat_audit_log, feat_custom_hostname, feat_white_label \
             from org_entitlements where org_id = $1",
        )
        .bind(org_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map_or_else(Entitlements::unlimited, |r| Entitlements {
            storage_soft_bytes: r.0,
            max_skus: r.1,
            agency: r.2,
            sso: r.3,
            multi_oidc: r.4,
            repo_access: r.5,
            scim: r.6,
            audit_log: r.7,
            custom_hostname: r.8,
            white_label: r.9,
        }))
    }

    /// Whether an org even has an explicit entitlements row (vs. the unlimited
    /// default). For display — "self-host / unlimited" vs "constrained".
    pub async fn has_entitlements(&self, org_id: Uuid) -> Result<bool, sqlx::Error> {
        sqlx::query_scalar("select exists(select 1 from org_entitlements where org_id = $1)")
            .bind(org_id)
            .fetch_one(&self.pool)
            .await
    }

    /// Set (upsert) an org's entitlements — the control plane's write path.
    pub async fn set_org_entitlements(
        &self,
        org_id: Uuid,
        e: &Entitlements,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "insert into org_entitlements \
                 (org_id, storage_soft_bytes, max_skus, feat_agency, feat_sso, feat_multi_oidc, \
                  feat_repo_access, feat_scim, feat_audit_log, feat_custom_hostname, feat_white_label, \
                  updated_at) \
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, now()) \
             on conflict (org_id) do update set \
                 storage_soft_bytes = excluded.storage_soft_bytes, \
                 max_skus = excluded.max_skus, \
                 feat_agency = excluded.feat_agency, \
                 feat_sso = excluded.feat_sso, \
                 feat_multi_oidc = excluded.feat_multi_oidc, \
                 feat_repo_access = excluded.feat_repo_access, \
                 feat_scim = excluded.feat_scim, \
                 feat_audit_log = excluded.feat_audit_log, \
                 feat_custom_hostname = excluded.feat_custom_hostname, \
                 feat_white_label = excluded.feat_white_label, \
                 updated_at = now()",
        )
        .bind(org_id)
        .bind(e.storage_soft_bytes)
        .bind(e.max_skus)
        .bind(e.agency)
        .bind(e.sso)
        .bind(e.multi_oidc)
        .bind(e.repo_access)
        .bind(e.scim)
        .bind(e.audit_log)
        .bind(e.custom_hostname)
        .bind(e.white_label)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Remove an org's entitlements row → back to the unlimited default.
    pub async fn clear_org_entitlements(&self, org_id: Uuid) -> Result<bool, sqlx::Error> {
        let n = sqlx::query("delete from org_entitlements where org_id = $1")
            .bind(org_id)
            .execute(&self.pool)
            .await?
            .rows_affected();
        Ok(n > 0)
    }

    /// Gate a mutation on a feature: `Ok(())` if the org's plan includes it,
    /// [`EntitlementError::Denied`] otherwise. Called at the top of gated
    /// catalog methods so both the UI and CLI paths are covered at one choke
    /// point.
    async fn require_feature(
        &self,
        org_id: Uuid,
        feature: Feature,
    ) -> Result<(), EntitlementError> {
        if self.entitlements(org_id).await?.allows(feature) {
            Ok(())
        } else {
            Err(EntitlementError::Denied(feature))
        }
    }

    /// Resolve the org that owns a repo (helper for repo-scoped feature gates).
    async fn org_of_repo(&self, repo_id: Uuid) -> Result<Uuid, sqlx::Error> {
        sqlx::query_scalar("select org_id from repositories where id = $1")
            .bind(repo_id)
            .fetch_one(&self.pool)
            .await
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
            "select p.name as name, p.visibility as visibility, p.upstream_id as upstream_id, \
                    p.sync_health as sync_health, \
                    p.broken_reason as broken_reason, \
                    to_char(p.broken_at,       'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') as broken_at, \
                    to_char(p.last_success_at, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') as last_success_at, \
                    p.archived_at is not null as archived, \
                    (select j.last_error from mirror_jobs j where j.upstream_id = p.upstream_id \
                     order by j.updated_at desc limit 1) as upstream_error \
             from packages p where p.repo_id = $1 \
             order by (p.sync_health = 'broken' and p.archived_at is null) desc, p.name",
        )
        .bind(repo_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok(PackageStatus {
                    name: r.try_get("name")?,
                    visibility: r.try_get("visibility")?,
                    upstream_id: r.try_get("upstream_id")?,
                    sync_health: r.try_get("sync_health")?,
                    broken_reason: r.try_get("broken_reason")?,
                    broken_at: r.try_get("broken_at")?,
                    last_success_at: r.try_get("last_success_at")?,
                    archived: r.try_get("archived")?,
                    upstream_error: r.try_get("upstream_error")?,
                })
            })
            .collect()
    }

    /// Per-repo count of packages that **need attention**: broken and not yet
    /// archived. `(repo_id, count)`, only repos with a non-zero count. Drives the
    /// home/repo "N packages can't sync" roll-up.
    pub async fn attention_counts(&self) -> Result<Vec<(Uuid, i64)>, sqlx::Error> {
        let rows = sqlx::query(
            "select repo_id, count(*) as n from packages \
             where sync_health = 'broken' and archived_at is null \
             group by repo_id",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| Ok((r.try_get("repo_id")?, r.try_get("n")?)))
            .collect()
    }

    // ----- package sets (shared collection primitive) -----

    /// Package sets in an org (id + name), sorted.
    pub async fn list_package_sets(&self, org_id: Uuid) -> Result<Vec<PackageSet>, sqlx::Error> {
        let rows = sqlx::query("select id, name from package_sets where org_id = $1 order by name")
            .bind(org_id)
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|r| {
                Ok(PackageSet {
                    id: r.try_get("id")?,
                    name: r.try_get("name")?,
                })
            })
            .collect()
    }

    /// Create a package set in an org. Errors on a duplicate name (unique).
    pub async fn create_package_set(&self, org_id: Uuid, name: &str) -> Result<Uuid, sqlx::Error> {
        sqlx::query_scalar("insert into package_sets (org_id, name) values ($1, $2) returning id")
            .bind(org_id)
            .bind(name.trim())
            .fetch_one(&self.pool)
            .await
    }

    /// Delete a package set (cascades members + rules).
    pub async fn delete_package_set(
        &self,
        org_id: Uuid,
        set_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let n = sqlx::query("delete from package_sets where id = $1 and org_id = $2")
            .bind(set_id)
            .bind(org_id)
            .execute(&self.pool)
            .await?;
        Ok(n.rows_affected() > 0)
    }

    /// A set's `(id, name, org_id)`, if it exists.
    pub async fn package_set(&self, set_id: Uuid) -> Result<Option<(String, Uuid)>, sqlx::Error> {
        sqlx::query_as("select name, org_id from package_sets where id = $1")
            .bind(set_id)
            .fetch_optional(&self.pool)
            .await
    }

    /// Explicit members of a set: `(package_id, name)`, sorted by name.
    pub async fn set_members(&self, set_id: Uuid) -> Result<Vec<(Uuid, String)>, sqlx::Error> {
        sqlx::query_as(
            "select p.id, p.name from package_set_members m join packages p on p.id = m.package_id \
             where m.set_id = $1 order by p.name",
        )
        .bind(set_id)
        .fetch_all(&self.pool)
        .await
    }

    /// Glob rules of a set: `(rule_id, glob)`.
    pub async fn set_rules(&self, set_id: Uuid) -> Result<Vec<(Uuid, String)>, sqlx::Error> {
        sqlx::query_as("select id, glob from package_set_rules where set_id = $1 order by glob")
            .bind(set_id)
            .fetch_all(&self.pool)
            .await
    }

    /// Resolve a set to its package **names**: explicit members ∪ packages in the
    /// set's org whose name matches a glob rule (`*` → SQL `%`). Auto-grows as
    /// matching packages are added.
    pub async fn resolve_set(&self, set_id: Uuid) -> Result<Vec<String>, sqlx::Error> {
        let rows = sqlx::query(
            "select distinct p.name from packages p \
             where p.id in (select package_id from package_set_members where set_id = $1) \
                or ( p.repo_id in (select id from repositories \
                                   where org_id = (select org_id from package_sets where id = $1)) \
                     and exists (select 1 from package_set_rules sr \
                                 where sr.set_id = $1 and p.name like replace(sr.glob, '*', '%')) ) \
             order by p.name",
        )
        .bind(set_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(|r| r.try_get("name")).collect()
    }

    /// Find a package id by name within an org (any of its repos) — for adding an
    /// explicit member by name. `None` if no such package.
    pub async fn find_package_in_org(
        &self,
        org_id: Uuid,
        name: &str,
    ) -> Result<Option<Uuid>, sqlx::Error> {
        sqlx::query_scalar(
            "select p.id from packages p join repositories r on r.id = p.repo_id \
             where r.org_id = $1 and p.name = $2 limit 1",
        )
        .bind(org_id)
        .bind(name)
        .fetch_optional(&self.pool)
        .await
    }

    /// Add an explicit member to a set (idempotent).
    pub async fn add_set_member(&self, set_id: Uuid, package_id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query(
            "insert into package_set_members (set_id, package_id) values ($1, $2) \
             on conflict do nothing",
        )
        .bind(set_id)
        .bind(package_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Remove an explicit member from a set.
    pub async fn remove_set_member(
        &self,
        set_id: Uuid,
        package_id: Uuid,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("delete from package_set_members where set_id = $1 and package_id = $2")
            .bind(set_id)
            .bind(package_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Add a glob rule to a set, returning its id.
    pub async fn add_set_rule(&self, set_id: Uuid, glob: &str) -> Result<Uuid, sqlx::Error> {
        sqlx::query_scalar(
            "insert into package_set_rules (set_id, glob) values ($1, $2) returning id",
        )
        .bind(set_id)
        .bind(glob.trim())
        .fetch_one(&self.pool)
        .await
    }

    /// Remove a glob rule by id.
    pub async fn remove_set_rule(&self, rule_id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query("delete from package_set_rules where id = $1")
            .bind(rule_id)
            .execute(&self.pool)
            .await?;
        Ok(())
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
        let n =
            sqlx::query("update packages set archived_at = null where repo_id = $1 and name = $2")
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

    /// Insert a **published** (pushed) version *immutably*. Unlike
    /// [`Self::upsert_package_version`] — which overwrites on conflict, correct for
    /// re-mirroring where the upstream is the source of truth — a published version
    /// cannot be silently replaced: re-publishing identical dist bytes is an
    /// idempotent no-op, and publishing *different* bytes for an existing version is
    /// rejected. Returns which of the three happened; the caller maps it to
    /// 201 / 200 / 409.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_pushed_version(
        &self,
        package_id: Uuid,
        version: &str,
        normalized_version: &str,
        stability: &str,
        composer_json: &Value,
        dist_blob_sha256: &[u8; 32],
        dist_shasum: &str,
        released_at_unix: i64,
    ) -> Result<PublishOutcome, sqlx::Error> {
        let inserted: Option<Uuid> = sqlx::query_scalar(
            "insert into package_versions \
                 (package_id, version, normalized_version, stability, composer_json, \
                  dist_blob_sha256, dist_shasum, released_at) \
             values ($1, $2, $3, $4, $5, $6, $7, to_timestamp($8::double precision)) \
             on conflict (package_id, normalized_version) do nothing \
             returning id",
        )
        .bind(package_id)
        .bind(version)
        .bind(normalized_version)
        .bind(stability)
        .bind(composer_json)
        .bind(&dist_blob_sha256[..])
        .bind(dist_shasum)
        .bind(released_at_unix)
        .fetch_optional(&self.pool)
        .await?;
        if inserted.is_some() {
            return Ok(PublishOutcome::Created);
        }
        // The row already existed (conflict) — compare dist bytes to tell an
        // idempotent retry from an immutability-violating republish.
        let existing: Option<Option<Vec<u8>>> = sqlx::query_scalar(
            "select dist_blob_sha256 from package_versions \
             where package_id = $1 and normalized_version = $2",
        )
        .bind(package_id)
        .bind(normalized_version)
        .fetch_optional(&self.pool)
        .await?;
        match existing.flatten() {
            Some(bytes) if bytes.as_slice() == &dist_blob_sha256[..] => {
                Ok(PublishOutcome::AlreadyPublished)
            }
            _ => Ok(PublishOutcome::Conflict),
        }
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
                    (u.credential is not null) as has_credential, u.credential_type, \
                    j.status as job_status, j.last_error as job_error, \
                    extract(epoch from (now() - j.created_at))::bigint as last_sync_age \
             from upstreams u \
             left join lateral ( \
                 select status, last_error, created_at from mirror_jobs m \
                 where m.upstream_id = u.id order by m.created_at desc limit 1 \
             ) j on true \
             where u.repo_id = $1 order by u.created_at",
        )
        .bind(repo_id)
        .fetch_all(&self.pool)
        .await?;
        // The require-lists for every upstream in this repo, in one query, grouped
        // by upstream so the listing avoids an N+1.
        let req_rows = sqlx::query(
            "select ur.upstream_id, ur.match_kind, ur.pattern, ur.version_floor \
             from upstream_requires ur join upstreams u on u.id = ur.upstream_id \
             where u.repo_id = $1 order by ur.position, ur.created_at",
        )
        .bind(repo_id)
        .fetch_all(&self.pool)
        .await?;
        let mut by_upstream: std::collections::HashMap<Uuid, Vec<UpstreamRequire>> =
            std::collections::HashMap::new();
        for r in &req_rows {
            by_upstream
                .entry(r.try_get("upstream_id")?)
                .or_default()
                .push(UpstreamRequire {
                    match_kind: r.try_get("match_kind")?,
                    pattern: r.try_get("pattern")?,
                    version_floor: r.try_get("version_floor")?,
                });
        }
        // Likewise the monorepo source-paths for every upstream in the repo.
        let sp_rows = sqlx::query(
            "select sp.upstream_id, sp.source_path \
             from upstream_source_paths sp join upstreams u on u.id = sp.upstream_id \
             where u.repo_id = $1 order by sp.source_path",
        )
        .bind(repo_id)
        .fetch_all(&self.pool)
        .await?;
        let mut paths_by_upstream: std::collections::HashMap<Uuid, Vec<String>> =
            std::collections::HashMap::new();
        for r in &sp_rows {
            paths_by_upstream
                .entry(r.try_get("upstream_id")?)
                .or_default()
                .push(r.try_get("source_path")?);
        }
        rows.iter()
            .map(|r| {
                let id: Uuid = r.try_get("id")?;
                Ok(UpstreamSummary {
                    id,
                    kind: r.try_get("kind")?,
                    base: r.try_get("base")?,
                    visibility: r.try_get("visibility")?,
                    label: r.try_get("label")?,
                    has_credential: r.try_get("has_credential")?,
                    credential_type: r.try_get("credential_type")?,
                    requires: by_upstream.remove(&id).unwrap_or_default(),
                    source_paths: paths_by_upstream.remove(&id).unwrap_or_default(),
                    job_status: r.try_get("job_status")?,
                    job_error: r.try_get("job_error")?,
                    last_sync_age: r.try_get("last_sync_age").ok().flatten(),
                })
            })
            .collect()
    }

    /// Load one upstream (with its encrypted credential) for mirroring.
    pub async fn get_upstream(
        &self,
        upstream_id: Uuid,
    ) -> Result<Option<UpstreamRow>, sqlx::Error> {
        let row = sqlx::query(
            "select id, repo_id, kind, base, visibility, credential, credential_type \
             from upstreams where id = $1",
        )
        .bind(upstream_id)
        .fetch_optional(&self.pool)
        .await?;
        let Some(r) = row else { return Ok(None) };
        let visibility = Visibility::parse(r.try_get("visibility")?).unwrap_or(Visibility::Private);
        Ok(Some(UpstreamRow {
            id: r.try_get("id")?,
            repo_id: r.try_get("repo_id")?,
            kind: r.try_get("kind")?,
            base: r.try_get("base")?,
            visibility,
            credential: r.try_get("credential")?,
            credential_type: r.try_get("credential_type")?,
            requires: self.list_upstream_requires(upstream_id).await?,
            source_paths: self.list_upstream_source_paths(upstream_id).await?,
        }))
    }

    /// An upstream's mirror subscription (require-list), in order.
    pub async fn list_upstream_requires(
        &self,
        upstream_id: Uuid,
    ) -> Result<Vec<UpstreamRequire>, sqlx::Error> {
        let rows = sqlx::query(
            "select match_kind, pattern, version_floor from upstream_requires \
             where upstream_id = $1 order by position, created_at",
        )
        .bind(upstream_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok(UpstreamRequire {
                    match_kind: r.try_get("match_kind")?,
                    pattern: r.try_get("pattern")?,
                    version_floor: r.try_get("version_floor")?,
                })
            })
            .collect()
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

    /// Replace an upstream's mirror subscription (require-list) wholesale,
    /// repo-scoped (a no-op if the upstream isn't in `repo_id`). Entries are
    /// stored in the given order.
    pub async fn set_upstream_requires(
        &self,
        repo_id: Uuid,
        upstream_id: Uuid,
        requires: &[UpstreamRequire],
    ) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        // Scope the write to the repo: only proceed if the upstream belongs to it.
        let owned: Option<Uuid> =
            sqlx::query_scalar("select id from upstreams where id = $1 and repo_id = $2")
                .bind(upstream_id)
                .bind(repo_id)
                .fetch_optional(&mut *tx)
                .await?;
        if owned.is_none() {
            tx.rollback().await?;
            return Ok(());
        }
        sqlx::query("delete from upstream_requires where upstream_id = $1")
            .bind(upstream_id)
            .execute(&mut *tx)
            .await?;
        for (pos, req) in requires.iter().enumerate() {
            sqlx::query(
                "insert into upstream_requires \
                     (upstream_id, position, match_kind, pattern, version_floor) \
                 values ($1, $2, $3, $4, $5)",
            )
            .bind(upstream_id)
            .bind(i32::try_from(pos).unwrap_or(i32::MAX))
            .bind(&req.match_kind)
            .bind(&req.pattern)
            .bind(req.version_floor.as_deref())
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
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

    /// Record the subdirectory a (monorepo) package was archived from (`""` =
    /// repo root). Provenance for the operator + the path the mirror re-archives.
    pub async fn set_package_source_path(
        &self,
        package_id: Uuid,
        source_path: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("update packages set source_path = $2 where id = $1")
            .bind(package_id)
            .bind(source_path)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// The explicit subpaths a git upstream mirrors (one package each), in a
    /// stable order. Empty = mirror the repo root as a single package.
    pub async fn list_upstream_source_paths(
        &self,
        upstream_id: Uuid,
    ) -> Result<Vec<String>, sqlx::Error> {
        sqlx::query_scalar(
            "select source_path from upstream_source_paths \
             where upstream_id = $1 order by source_path",
        )
        .bind(upstream_id)
        .fetch_all(&self.pool)
        .await
    }

    /// Replace a git upstream's explicit source-path list wholesale, repo-scoped
    /// (a no-op if the upstream isn't in `repo_id`). Blank paths are dropped and
    /// duplicates collapsed.
    pub async fn set_upstream_source_paths(
        &self,
        repo_id: Uuid,
        upstream_id: Uuid,
        paths: &[String],
    ) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let owned: Option<Uuid> =
            sqlx::query_scalar("select id from upstreams where id = $1 and repo_id = $2")
                .bind(upstream_id)
                .bind(repo_id)
                .fetch_optional(&mut *tx)
                .await?;
        if owned.is_none() {
            tx.rollback().await?;
            return Ok(());
        }
        sqlx::query("delete from upstream_source_paths where upstream_id = $1")
            .bind(upstream_id)
            .execute(&mut *tx)
            .await?;
        let mut seen = std::collections::HashSet::new();
        for p in paths {
            let p = p.trim().trim_matches('/');
            if p.is_empty() || !seen.insert(p.to_owned()) {
                continue;
            }
            sqlx::query(
                "insert into upstream_source_paths (upstream_id, source_path) values ($1, $2)",
            )
            .bind(upstream_id)
            .bind(p)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
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

    /// Recent mirror jobs for the Activity view, newest first. `org_ids = None`
    /// returns all (single-tenant / superadmin); `Some(ids)` scopes to those
    /// orgs (a tenant member only sees their own orgs' activity).
    pub async fn recent_jobs(
        &self,
        limit: i64,
        org_ids: Option<&[Uuid]>,
    ) -> Result<Vec<JobActivity>, sqlx::Error> {
        let rows = sqlx::query(
            "select j.kind, j.status, j.attempts, j.last_error, \
                    coalesce(j.package, u.base, 'dependency closure') as target, \
                    o.slug as org, r.slug as repo, \
                    to_char(j.updated_at, 'YYYY-MM-DD HH24:MI') as updated \
             from mirror_jobs j \
             left join upstreams u on u.id = j.upstream_id \
             left join repositories r on r.id = coalesce(j.repo_id, u.repo_id) \
             left join organizations o on o.id = r.org_id \
             where ($2::uuid[] is null or r.org_id = any($2)) \
             order by j.updated_at desc limit $1",
        )
        .bind(limit)
        .bind(org_ids)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                let org: Option<String> = r.try_get("org")?;
                let repo: Option<String> = r.try_get("repo")?;
                Ok(JobActivity {
                    kind: r.try_get("kind")?,
                    status: r.try_get("status")?,
                    attempts: r.try_get("attempts")?,
                    last_error: r.try_get("last_error")?,
                    target: r.try_get("target")?,
                    repo: org.zip(repo).map(|(o, r)| format!("{o}/{r}")),
                    updated: r.try_get("updated")?,
                })
            })
            .collect()
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
    /// `last_used_at`. This is the serving (read) credential path — it queries only
    /// the read `tokens` table, so a management-API service token is never accepted
    /// here (the two credential types are intentionally kept in separate tables;
    /// see the service-token section below).
    pub async fn token_valid(&self, repo_id: Uuid, token: &str) -> Result<bool, sqlx::Error> {
        // A token authenticates this repo if it's the repo's own per-repo token
        // (t.repo_id = r.id) OR an org-scoped token for the repo's org
        // (t.org_id = r.org_id) — the latter minted by the device-login flow.
        let updated = sqlx::query(
            "update tokens t set last_used_at = now() \
             from repositories r \
             where r.id = $1 and t.token_hash = $2 \
             and (t.expires_at is null or t.expires_at > now()) \
             and (t.repo_id = r.id or t.org_id = r.org_id)",
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
                    coalesce(expires_at <= now(), false) as expired, \
                    update_mode, cooldown_days \
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
                    policy: PolicyOverride {
                        update_mode: row.try_get("update_mode").ok().flatten(),
                        cooldown_days: row.try_get("cooldown_days").ok().flatten(),
                    },
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
        let (key, hash, ciphertext) = self.mint_license_key();
        let id: Uuid = sqlx::query_scalar(
            "insert into license_keys (repo_id, key_hash, buyer_ref, key_ciphertext) \
             values ($1, $2, $3, $4) returning id",
        )
        .bind(repo_id)
        .bind(hash)
        .bind(buyer_ref)
        .bind(ciphertext)
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
        let (key, hash, ciphertext) = self.mint_license_key();
        let license_id: Uuid = sqlx::query_scalar(
            "insert into license_keys (repo_id, key_hash, buyer_ref, key_ciphertext) \
             values ($1, $2, $3, $4) returning id",
        )
        .bind(repo_id)
        .bind(hash)
        .bind(buyer)
        .bind(ciphertext)
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
        // Matches the repo's own per-repo token (t.repo_id = r.id) or an
        // org-scoped token covering the repo's org (t.org_id = r.org_id, minted
        // by device login) — the same rule as [`Catalog::token_valid`]. An
        // org-scoped token carries no per-token policy override, so the repo's
        // default policy applies.
        let row = sqlx::query(
            "update tokens t set last_used_at = now() \
             from repositories r \
             where r.id = $1 and t.token_hash = $2 \
               and (t.expires_at is null or t.expires_at > now()) \
               and (t.repo_id = r.id or t.org_id = r.org_id) \
             returning t.update_mode, t.cooldown_days",
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

    /// Resolve an **org-scoped session token** (the credential `bougie login`
    /// mints via the device flow, `org_id` set / `repo_id` null) to the org it
    /// authenticates plus its expiry, for the relay introspection endpoint.
    /// Returns `None` for an unknown, expired, or repo-scoped token. Stamps
    /// `last_used_at` like the other verifiers ([`Catalog::token_valid`]). The
    /// expiry comes back as an epoch bigint so no timestamp type is needed on
    /// the sqlx boundary.
    pub async fn resolve_org_session_token(
        &self,
        token: &str,
    ) -> Result<Option<OrgToken>, sqlx::Error> {
        let row = sqlx::query(
            "update tokens set last_used_at = now() \
             where token_hash = $1 and org_id is not null \
               and (expires_at is null or expires_at > now()) \
             returning org_id, extract(epoch from expires_at)::bigint as expires_at_unix",
        )
        .bind(token_hash(token))
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some(r) => Ok(Some(OrgToken {
                org_id: r.try_get("org_id")?,
                expires_at_unix: r.try_get("expires_at_unix").ok().flatten(),
            })),
            None => Ok(None),
        }
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

    /// A license's perpetual-fallback update bound (empty = unbounded).
    pub async fn license_bound(&self, license_id: Uuid) -> Result<LicenseBound, sqlx::Error> {
        let row = sqlx::query(
            "select to_char(update_until, 'YYYY-MM-DD') as until, \
                    extract(epoch from update_until)::bigint as until_unix, \
                    version_cap_major as major \
             from license_keys where id = $1",
        )
        .bind(license_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(LicenseBound {
            until: row.try_get("until").ok().flatten(),
            until_unix: row.try_get("until_unix").ok().flatten(),
            major: row.try_get("major").ok().flatten(),
        })
    }

    /// Set (or clear) a license's update bound: `until` is a `YYYY-MM-DD` date
    /// (time bound) and/or `major` a max major version (version bound).
    pub async fn set_license_bound(
        &self,
        repo_id: Uuid,
        license_id: Uuid,
        until: Option<&str>,
        major: Option<i32>,
    ) -> Result<bool, sqlx::Error> {
        let n = sqlx::query(
            "update license_keys set update_until = $3::timestamptz, version_cap_major = $4 \
             where id = $1 and repo_id = $2",
        )
        .bind(license_id)
        .bind(repo_id)
        .bind(until)
        .bind(major)
        .execute(&self.pool)
        .await?;
        Ok(n.rows_affected() > 0)
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
             where e.license_key_id = $1 \
             union \
             select p.name from license_set_entitlements lse \
             join package_sets ps on ps.id = lse.set_id \
             join packages p on ( \
                 p.id in (select package_id from package_set_members where set_id = lse.set_id) \
                 or ( p.repo_id in (select id from repositories where org_id = ps.org_id) \
                      and exists (select 1 from package_set_rules sr \
                                  where sr.set_id = lse.set_id \
                                    and p.name like replace(sr.glob, '*', '%')) ) ) \
             where lse.license_key_id = $1 \
             order by name",
        )
        .bind(license_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(|r| r.try_get("name")).collect()
    }

    /// The packages a license unlocks **with each package's effective update
    /// bound** — the serve-time view. Every entitlement edge (direct package or
    /// by-reference set, 0047) resolves per axis to its own value or, when NULL,
    /// the key's (0029); a package covered by several edges gets the most
    /// permissive result (any unbounded edge wins, else the latest/highest
    /// ceiling). Keys with no edge bounds — every key issued before 0047 —
    /// resolve to exactly the key bound, so behavior is unchanged for them.
    pub async fn entitled_package_bounds(
        &self,
        license_id: Uuid,
    ) -> Result<Vec<(String, LicenseBound)>, sqlx::Error> {
        let rows = sqlx::query(
            "with edges as ( \
                 select p.name, \
                        coalesce(e.update_until, l.update_until) as eff_until, \
                        coalesce(e.version_cap_major, l.version_cap_major) as eff_major \
                 from entitlements e \
                 join license_keys l on l.id = e.license_key_id \
                 join packages p on p.id = e.package_id \
                 where e.license_key_id = $1 \
                 union all \
                 select p.name, \
                        coalesce(lse.update_until, l.update_until), \
                        coalesce(lse.version_cap_major, l.version_cap_major) \
                 from license_set_entitlements lse \
                 join license_keys l on l.id = lse.license_key_id \
                 join package_sets ps on ps.id = lse.set_id \
                 join packages p on ( \
                     p.id in (select package_id from package_set_members where set_id = lse.set_id) \
                     or ( p.repo_id in (select id from repositories where org_id = ps.org_id) \
                          and exists (select 1 from package_set_rules sr \
                                      where sr.set_id = lse.set_id \
                                        and p.name like replace(sr.glob, '*', '%')) ) ) \
                 where lse.license_key_id = $1 \
             ), unioned as ( \
                 select name, \
                        case when bool_or(eff_until is null) then null \
                             else max(eff_until) end as bound_until, \
                        case when bool_or(eff_major is null) then null \
                             else max(eff_major) end as bound_major \
                 from edges group by name \
             ) \
             select name, \
                    to_char(bound_until, 'YYYY-MM-DD') as until, \
                    extract(epoch from bound_until)::bigint as until_unix, \
                    bound_major as major \
             from unioned order by name",
        )
        .bind(license_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get("name")?,
                    LicenseBound {
                        until: r.try_get("until").ok().flatten(),
                        until_unix: r.try_get("until_unix").ok().flatten(),
                        major: r.try_get("major").ok().flatten(),
                    },
                ))
            })
            .collect()
    }

    /// Entitle a license to an entire **package set** (a SKU/edition). The license
    /// unlocks every package the set resolves to, by reference — auto-growing as
    /// the set grows. Idempotent.
    pub async fn entitle_set(&self, license_id: Uuid, set_id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query(
            "insert into license_set_entitlements (license_key_id, set_id) values ($1, $2) \
             on conflict do nothing",
        )
        .bind(license_id)
        .bind(set_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Revoke a set entitlement from a license.
    pub async fn remove_set_entitlement(
        &self,
        license_id: Uuid,
        set_id: Uuid,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "delete from license_set_entitlements where license_key_id = $1 and set_id = $2",
        )
        .bind(license_id)
        .bind(set_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Sets a license is entitled to, as `(set_id, name)` pairs.
    pub async fn entitled_sets(
        &self,
        license_id: Uuid,
    ) -> Result<Vec<(Uuid, String)>, sqlx::Error> {
        let rows = sqlx::query(
            "select ps.id, ps.name from license_set_entitlements lse \
             join package_sets ps on ps.id = lse.set_id \
             where lse.license_key_id = $1 order by ps.name",
        )
        .bind(license_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| Ok((r.try_get("id")?, r.try_get("name")?)))
            .collect()
    }

    // ----- Editions (SKUs) -------------------------------------------------
    // A reusable issuance template (target set + bound template + policy). Keys
    // are issued *against* an edition, which resolves the template into the
    // existing per-key columns/tables. Serving never reads editions. See
    // SKU_PLAN.md.

    /// Count an org's **active** editions across all its repos — the number the
    /// `max_skus` cap constrains.
    pub async fn count_active_editions(&self, org_id: Uuid) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            "select count(*)::bigint from editions e \
             join repositories r on r.id = e.repo_id \
             where r.org_id = $1 and e.active",
        )
        .bind(org_id)
        .fetch_one(&self.pool)
        .await
    }

    /// Enforce the org's `max_skus` cap for one more active edition, **inside**
    /// `tx` and under a per-org advisory lock, so a concurrent create/reactivate
    /// can't both read "under cap" and both commit (a check-then-insert TOCTOU that
    /// would drift the billed SKU count above the plan). `exclude` is an edition id
    /// not to count (the one being reactivated). `Ok(())` when under the cap or
    /// uncapped; [`EntitlementError::SkuCapReached`] at it. The lock releases when
    /// `tx` commits or rolls back.
    async fn require_sku_capacity_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        org_id: Uuid,
        exclude: Option<Uuid>,
    ) -> Result<(), EntitlementError> {
        // Distinct namespace from the migration lock (two-int form vs one-bigint).
        sqlx::query("select pg_advisory_xact_lock(hashtext('sconce:edition_cap'), hashtext($1))")
            .bind(org_id.to_string())
            .execute(&mut **tx)
            .await?;
        if let Some(cap) = self.entitlements(org_id).await?.max_skus {
            let count: i64 = sqlx::query_scalar(
                "select count(*)::bigint from editions e \
                 join repositories r on r.id = e.repo_id \
                 where r.org_id = $1 and e.active and ($2::uuid is null or e.id <> $2)",
            )
            .bind(org_id)
            .bind(exclude)
            .fetch_one(&mut **tx)
            .await?;
            if count >= i64::from(cap) {
                return Err(EntitlementError::SkuCapReached(cap));
            }
        }
        Ok(())
    }

    /// Get-or-create an org-scoped **singleton** package set holding exactly
    /// `package`, so a single-package edition can reuse the set primitive. The set
    /// is named after the package; an existing set of that name is reused **only if
    /// it is genuinely a singleton** (no rules, no member other than this package).
    /// A collision with a curated multi-package set of the same name is refused
    /// ([`SingletonSet::NameCollision`]) rather than silently over-entitling issued
    /// keys with that set's contents (and mutating it).
    pub async fn singleton_set(
        &self,
        org_id: Uuid,
        package: &str,
    ) -> Result<SingletonSet, sqlx::Error> {
        let Some(package_id) = self.find_package_in_org(org_id, package).await? else {
            return Ok(SingletonSet::UnknownPackage);
        };
        let name = package.trim();
        // Is there already a set with this name? If so, only reuse it when it's a
        // real singleton for this package.
        let existing: Option<(Uuid, bool)> = sqlx::query(
            "select ps.id, \
                    (not exists (select 1 from package_set_rules where set_id = ps.id) \
                     and not exists (select 1 from package_set_members \
                                     where set_id = ps.id and package_id <> $3)) as is_singleton \
             from package_sets ps where ps.org_id = $1 and ps.name = $2",
        )
        .bind(org_id)
        .bind(name)
        .bind(package_id)
        .fetch_optional(&self.pool)
        .await?
        .map(|r| Ok::<_, sqlx::Error>((r.try_get("id")?, r.try_get("is_singleton")?)))
        .transpose()?;
        let set_id = match existing {
            Some((_, false)) => return Ok(SingletonSet::NameCollision),
            Some((id, true)) => id,
            None => self.create_package_set(org_id, name).await?,
        };
        self.add_set_member(set_id, package_id).await?;
        Ok(SingletonSet::Set(set_id))
    }

    /// Create an edition in a repo. Gated on the org's `max_skus` (enforced under a
    /// per-org lock inside the transaction, so the cap can't be raced past). The
    /// target `set_id` must belong to the repo's org — returns `Ok(None)` if it
    /// doesn't (so callers can report "unknown set" without a DB error). A duplicate
    /// `(repo, name)` surfaces as a `Sqlx` unique violation.
    // The fields (name, slug, set, bound, snapshot, policy) are all independent
    // edition attributes; a params struct would just add indirection.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_edition(
        &self,
        repo_id: Uuid,
        name: &str,
        slug: Option<&str>,
        set_id: Uuid,
        bound: &EditionBound,
        snapshot: bool,
        policy: &PolicyOverride,
    ) -> Result<Option<Uuid>, EntitlementError> {
        let org_id = self.org_of_repo(repo_id).await?;
        let mut tx = self.pool.begin().await?;
        self.require_sku_capacity_tx(&mut tx, org_id, None).await?;
        let set_ok: bool = sqlx::query_scalar(
            "select exists(select 1 from package_sets where id = $1 and org_id = $2)",
        )
        .bind(set_id)
        .bind(org_id)
        .fetch_one(&mut *tx)
        .await?;
        if !set_ok {
            return Ok(None);
        }
        let (kind, period_months, major) = bound.columns();
        let id: Uuid = sqlx::query_scalar(
            "insert into editions \
                 (repo_id, name, slug, set_id, bound_kind, bound_period_months, bound_major, \
                  snapshot_at_issue, update_mode, cooldown_days) \
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) returning id",
        )
        .bind(repo_id)
        .bind(name.trim())
        .bind(slug.map(str::trim).filter(|s| !s.is_empty()))
        .bind(set_id)
        .bind(kind)
        .bind(period_months)
        .bind(major)
        .bind(snapshot)
        .bind(policy.update_mode.as_deref())
        .bind(policy.cooldown_days)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Some(id))
    }

    /// A repo's editions (active first, then by name), for the manager UI.
    pub async fn list_editions(&self, repo_id: Uuid) -> Result<Vec<Edition>, sqlx::Error> {
        let rows = sqlx::query(
            "select e.id, e.name, e.slug, e.set_id, ps.name as set_name, \
                    e.bound_kind, e.bound_period_months, e.bound_major, \
                    e.snapshot_at_issue, e.update_mode, e.cooldown_days, e.active \
             from editions e join package_sets ps on ps.id = e.set_id \
             where e.repo_id = $1 order by e.active desc, e.name",
        )
        .bind(repo_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::edition_from_row).collect()
    }

    /// One edition by id, scoped to its repo. `None` if it doesn't exist there.
    pub async fn edition(
        &self,
        repo_id: Uuid,
        edition_id: Uuid,
    ) -> Result<Option<Edition>, sqlx::Error> {
        let row = sqlx::query(
            "select e.id, e.name, e.slug, e.set_id, ps.name as set_name, \
                    e.bound_kind, e.bound_period_months, e.bound_major, \
                    e.snapshot_at_issue, e.update_mode, e.cooldown_days, e.active \
             from editions e join package_sets ps on ps.id = e.set_id \
             where e.repo_id = $1 and e.id = $2",
        )
        .bind(repo_id)
        .bind(edition_id)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(Self::edition_from_row).transpose()
    }

    /// Resolve an edition id by name or slug within a repo (for the CLI). Prefers
    /// a slug match, then a name match. `nulls last` is load-bearing: `(slug = $2)`
    /// is NULL (not false) for a slug-less edition, and `desc` sorts NULLs first by
    /// default — which would rank a name-match-with-null-slug above a real slug
    /// match, the opposite of "prefer slug". (slug is also unique per repo now.)
    pub async fn find_edition(
        &self,
        repo_id: Uuid,
        name_or_slug: &str,
    ) -> Result<Option<Uuid>, sqlx::Error> {
        sqlx::query_scalar(
            "select id from editions where repo_id = $1 and (slug = $2 or name = $2) \
             order by (slug = $2) desc nulls last limit 1",
        )
        .bind(repo_id)
        .bind(name_or_slug.trim())
        .fetch_optional(&self.pool)
        .await
    }

    /// Activate or deactivate an edition. Deactivating stops new sales and frees a
    /// `max_skus` slot without touching already-issued keys. **Reactivating**
    /// consumes a slot again, so it re-checks the cap (under the same per-org lock
    /// as create) — otherwise deactivate→create→reactivate would exceed `max_skus`.
    /// Returns whether a row matched.
    pub async fn set_edition_active(
        &self,
        repo_id: Uuid,
        edition_id: Uuid,
        active: bool,
    ) -> Result<bool, EntitlementError> {
        if !active {
            let n =
                sqlx::query("update editions set active = false where id = $1 and repo_id = $2")
                    .bind(edition_id)
                    .bind(repo_id)
                    .execute(&self.pool)
                    .await?;
            return Ok(n.rows_affected() > 0);
        }
        let org_id = self.org_of_repo(repo_id).await?;
        let mut tx = self.pool.begin().await?;
        self.require_sku_capacity_tx(&mut tx, org_id, Some(edition_id))
            .await?;
        let n = sqlx::query("update editions set active = true where id = $1 and repo_id = $2")
            .bind(edition_id)
            .bind(repo_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(n.rows_affected() > 0)
    }

    /// Delete an edition. Already-issued keys keep working — their `edition_id` is
    /// set null (they retain their resolved entitlements/bound). Returns whether a
    /// row was removed.
    pub async fn delete_edition(
        &self,
        repo_id: Uuid,
        edition_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let n = sqlx::query("delete from editions where id = $1 and repo_id = $2")
            .bind(edition_id)
            .bind(repo_id)
            .execute(&self.pool)
            .await?;
        Ok(n.rows_affected() > 0)
    }

    /// Issue a license key **against an edition**: the edition's bound template and
    /// policy are resolved onto the key, and its target set entitles the key —
    /// frozen as per-package rows (`snapshot`) or unlocked by reference
    /// (auto-grow). Serving is unchanged: it reads the resolved key exactly as for
    /// an ad-hoc one.
    ///
    /// `Ok(None)` if the edition doesn't exist in the repo or is inactive. When
    /// `idempotency_key` is set (the commerce order id), a repeated call for the
    /// **same edition** returns the existing key's [`IssuedLicense`] (its plaintext
    /// recovered from at-rest ciphertext when a secret key is configured) with
    /// `created: false` instead of minting a duplicate — so a retried checkout
    /// webhook is a no-op. Idempotency is scoped to `(repo, edition, key)`, so one
    /// order id still provisions one key per edition (a multi-SKU order does not
    /// collapse to a single license).
    pub async fn issue_from_edition(
        &self,
        repo_id: Uuid,
        edition_id: Uuid,
        buyer: Option<&str>,
        idempotency_key: Option<&str>,
    ) -> Result<Option<IssuedLicense>, sqlx::Error> {
        self.issue_from_edition_inner(repo_id, edition_id, buyer, idempotency_key, false)
            .await
    }

    /// Issue an **account key** from an edition: the key itself is minted
    /// unbounded and the edition's bound lands on its entitlement edge (0047) —
    /// so the key is a valid merge target for every later purchase, no matter
    /// which edition came first. This is what a commerce front-end that
    /// accumulates purchases onto one key per customer should always use; the
    /// plain [`Self::issue_from_edition`] keeps the legacy standalone shape
    /// (bound on the key). Snapshot editions freeze per-package rows, which now
    /// carry the bound per row.
    pub async fn issue_account_key_from_edition(
        &self,
        repo_id: Uuid,
        edition_id: Uuid,
        buyer: Option<&str>,
        idempotency_key: Option<&str>,
    ) -> Result<Option<IssuedLicense>, sqlx::Error> {
        self.issue_from_edition_inner(repo_id, edition_id, buyer, idempotency_key, true)
            .await
    }

    async fn issue_from_edition_inner(
        &self,
        repo_id: Uuid,
        edition_id: Uuid,
        buyer: Option<&str>,
        idempotency_key: Option<&str>,
        bound_on_edge: bool,
    ) -> Result<Option<IssuedLicense>, sqlx::Error> {
        // Fast path: a prior issue for this (repo, edition, idempotency_key) is a
        // replay — return the existing key (recovered from at-rest ciphertext, if a
        // secret key is configured), so the caller isn't stuck without it.
        if let Some(idem) = idempotency_key
            && let Some(id) = self
                .license_id_for_idempotency(repo_id, edition_id, idem)
                .await?
        {
            return Ok(Some(IssuedLicense {
                key: self.license_key_plaintext(repo_id, id).await?,
                id,
                created: false,
            }));
        }
        let mut tx = self.pool.begin().await?;
        // Insert the key with the bound resolved inline from the edition (time ->
        // now()+months, version -> cap), so no clock/date handling in Rust — or,
        // for an account key, unbounded (`$7` — the bound lands on the edge
        // below). A missing/inactive edition yields no row.
        let (key, hash, ciphertext) = self.mint_license_key();
        let inserted = sqlx::query(
            "insert into license_keys \
                 (repo_id, key_hash, key_ciphertext, buyer_ref, edition_id, idempotency_key, \
                  update_until, version_cap_major, update_mode, cooldown_days) \
             select $1, $2, $6, $3, ed.id, $5, \
                    case when not $7 and ed.bound_kind = 'time' \
                         then now() + make_interval(months => ed.bound_period_months) end, \
                    case when not $7 and ed.bound_kind = 'version' then ed.bound_major end, \
                    ed.update_mode, ed.cooldown_days \
             from editions ed where ed.id = $4 and ed.repo_id = $1 and ed.active \
             returning id, (select set_id from editions where id = $4) as set_id, \
                       (select snapshot_at_issue from editions where id = $4) as snapshot",
        )
        .bind(repo_id)
        .bind(hash)
        .bind(buyer)
        .bind(edition_id)
        .bind(idempotency_key)
        .bind(ciphertext)
        .bind(bound_on_edge)
        .fetch_optional(&mut *tx)
        .await;
        // Lost the race with a concurrent replay: the partial unique index on
        // (repo, edition, idempotency_key) rejected this insert — resolve to the winner.
        let row = match inserted {
            Ok(row) => row,
            Err(e) if is_unique_violation(&e) => {
                tx.rollback().await?;
                let Some(idem) = idempotency_key else {
                    return Err(e);
                };
                let Some(id) = self
                    .license_id_for_idempotency(repo_id, edition_id, idem)
                    .await?
                else {
                    return Ok(None);
                };
                return Ok(Some(IssuedLicense {
                    key: self.license_key_plaintext(repo_id, id).await?,
                    id,
                    created: false,
                }));
            }
            Err(e) => return Err(e),
        };
        let Some(row) = row else {
            tx.rollback().await?;
            return Ok(None);
        };
        let license_id: Uuid = row.try_get("id")?;
        let set_id: Uuid = row.try_get("set_id")?;
        let snapshot: bool = row.try_get("snapshot")?;
        Self::attach_edition_set(
            &mut tx,
            license_id,
            set_id,
            snapshot,
            bound_on_edge.then_some(edition_id),
        )
        .await?;
        tx.commit().await?;
        Ok(Some(IssuedLicense {
            id: license_id,
            key: Some(key),
            created: true,
        }))
    }

    /// Attach an edition's target set to a license inside a transaction: freeze
    /// current membership as explicit per-package entitlements when the edition
    /// snapshots at issue, else unlock the set by reference (auto-growing as the
    /// set grows). Idempotent (`on conflict do nothing`). Shared by issuance
    /// (both shapes) and [`Self::add_edition_to_license`]; `bound_from_edition`
    /// picks where the update bound lives (edge vs key — 0047).
    async fn attach_edition_set(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        license_id: Uuid,
        set_id: Uuid,
        snapshot: bool,
        // `Some(edition)` (account-key issuance) resolves that edition's bound
        // template onto the inserted edges; `None` leaves them NULL (the key
        // carries the bound — legacy standalone issuance).
        bound_from_edition: Option<Uuid>,
    ) -> Result<(), sqlx::Error> {
        if snapshot {
            // Freeze current set membership as explicit per-package entitlements
            // (each row carrying the edge bound when issuing an account key).
            sqlx::query(
                "insert into entitlements (license_key_id, package_id, update_until, version_cap_major) \
                 select $1, p.id, \
                        case when ed.bound_kind = 'time' \
                             then now() + make_interval(months => ed.bound_period_months) end, \
                        case when ed.bound_kind = 'version' then ed.bound_major end \
                 from packages p \
                 left join editions ed on ed.id = $3 \
                 where p.id in (select package_id from package_set_members where set_id = $2) \
                    or ( p.repo_id in (select id from repositories \
                                       where org_id = (select org_id from package_sets where id = $2)) \
                         and exists (select 1 from package_set_rules sr \
                                     where sr.set_id = $2 \
                                       and p.name like replace(sr.glob, '*', '%')) ) \
                 on conflict do nothing",
            )
            .bind(license_id)
            .bind(set_id)
            .bind(bound_from_edition)
            .execute(&mut **tx)
            .await?;
        } else {
            // Unlock by reference — auto-grows with the set.
            sqlx::query(
                "insert into license_set_entitlements \
                     (license_key_id, set_id, update_until, version_cap_major) \
                 select $1, $2, \
                        case when ed.bound_kind = 'time' \
                             then now() + make_interval(months => ed.bound_period_months) end, \
                        case when ed.bound_kind = 'version' then ed.bound_major end \
                 from (select 1) one \
                 left join editions ed on ed.id = $3 \
                 on conflict do nothing",
            )
            .bind(license_id)
            .bind(set_id)
            .bind(bound_from_edition)
            .execute(&mut **tx)
            .await?;
        }
        Ok(())
    }

    /// Attach an edition's sellable content to an **existing** license key, so a
    /// repeat buyer accumulates purchases onto one key (a single Composer auth
    /// entry then unlocks everything they own — Composer's http-basic auth is
    /// keyed by hostname, so a customer can only present one key per repo).
    /// Returns [`EditionAdd`].
    ///
    /// The edition's update bound lands on the **entitlement edge** (0047),
    /// resolved from its template exactly as issuance resolves the key bound
    /// (time -> now()+period, version -> cap, perpetual -> none) — so a time or
    /// version-bounded edition merges cleanly beside perpetual ones, each package
    /// served under its own ceiling. Two cases still yield
    /// [`EditionAdd::Standalone`] (caller issues a separate key):
    ///
    /// - a **bounded key**: a NULL edge inherits the key bound (the 0047
    ///   back-compat rule), so an explicitly-perpetual edge on a bounded key is
    ///   not expressible — merge targets must be unbounded (account) keys;
    /// - a **snapshot edition**: its frozen per-package rows can't be cleanly
    ///   detached on a refund.
    ///
    /// Idempotent: re-adding the same edition is a no-op (a renewal — not a
    /// re-add — is what extends a time edge, see [`Self::renew_license_edition`]).
    pub async fn add_edition_to_license(
        &self,
        repo_id: Uuid,
        license_id: Uuid,
        edition_id: Uuid,
    ) -> Result<EditionAdd, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        // Target must be an active key in this repo; capture whether it's perpetual
        // (no time bound and no version cap).
        let key_perpetual: Option<bool> = sqlx::query_scalar(
            "select (update_until is null and version_cap_major is null) \
             from license_keys where id = $1 and repo_id = $2 and status = 'active'",
        )
        .bind(license_id)
        .bind(repo_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(key_perpetual) = key_perpetual else {
            tx.rollback().await?;
            return Ok(EditionAdd::NoKey);
        };
        // Edition must be active in this repo; capture its snapshot flag (the
        // bound template is resolved inside the insert below).
        let ed: Option<(Uuid, bool)> = sqlx::query_as(
            "select set_id, snapshot_at_issue \
             from editions where id = $1 and repo_id = $2 and active",
        )
        .bind(edition_id)
        .bind(repo_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((set_id, snapshot)) = ed else {
            tx.rollback().await?;
            return Ok(EditionAdd::NoEdition);
        };
        if !key_perpetual || snapshot {
            tx.rollback().await?;
            return Ok(EditionAdd::Standalone);
        }
        // Unlock the set by reference with the edition's bound resolved onto the
        // edge, exactly as account-key issuance attaches it.
        Self::attach_edition_set(&mut tx, license_id, set_id, false, Some(edition_id)).await?;
        tx.commit().await?;
        Ok(EditionAdd::Added)
    }

    /// The update bound on one edition's set-entitlement **edge** of a license
    /// (empty = the edge is unbounded or inherits the key). Lets an API response
    /// report the concrete expiry a just-attached or just-renewed edition carries
    /// on an accumulated key.
    pub async fn edition_edge_bound(
        &self,
        license_id: Uuid,
        edition_id: Uuid,
    ) -> Result<LicenseBound, sqlx::Error> {
        let row = sqlx::query(
            "select to_char(lse.update_until, 'YYYY-MM-DD') as until, \
                    extract(epoch from lse.update_until)::bigint as until_unix, \
                    lse.version_cap_major as major \
             from license_set_entitlements lse \
             join editions e on e.set_id = lse.set_id \
             where lse.license_key_id = $1 and e.id = $2",
        )
        .bind(license_id)
        .bind(edition_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row
            .map(|r| LicenseBound {
                until: r.try_get("until").ok().flatten(),
                until_unix: r.try_get("until_unix").ok().flatten(),
                major: r.try_get("major").ok().flatten(),
            })
            .unwrap_or_default())
    }

    /// Fold one license key's entitlements into another and revoke the source —
    /// the operator's manual consolidation for customers who accumulated
    /// standalone keys before per-entitlement bounds existed (0047). In one
    /// transaction:
    ///
    /// - Every source entitlement edge (set and direct-package) is copied to the
    ///   target with its bound **materialized**: a NULL edge on the source means
    ///   "inherit the source KEY's bound", and moving it verbatim onto an
    ///   unbounded target would silently turn it perpetual — so each axis copies
    ///   `coalesce(edge, source key)`.
    /// - A collision (target already covers the set/package) keeps the more
    ///   permissive bound per axis: NULL (unbounded) wins, else the later date /
    ///   higher major.
    /// - The source key is revoked; buyers keep using the target only.
    ///
    /// The target must be an **unbounded** active key (the account key) — same
    /// rule as [`Self::add_edition_to_license`].
    pub async fn merge_license_keys(
        &self,
        repo_id: Uuid,
        source_id: Uuid,
        target_id: Uuid,
    ) -> Result<LicenseMerge, sqlx::Error> {
        if source_id == target_id {
            return Ok(LicenseMerge::SameKey);
        }
        let mut tx = self.pool.begin().await?;
        let source_ok: Option<bool> = sqlx::query_scalar(
            "select true from license_keys where id = $1 and repo_id = $2 and status = 'active'",
        )
        .bind(source_id)
        .bind(repo_id)
        .fetch_optional(&mut *tx)
        .await?;
        if source_ok.is_none() {
            tx.rollback().await?;
            return Ok(LicenseMerge::NoSource);
        }
        let target_perpetual: Option<bool> = sqlx::query_scalar(
            "select (update_until is null and version_cap_major is null) \
             from license_keys where id = $1 and repo_id = $2 and status = 'active'",
        )
        .bind(target_id)
        .bind(repo_id)
        .fetch_optional(&mut *tx)
        .await?;
        match target_perpetual {
            None => {
                tx.rollback().await?;
                return Ok(LicenseMerge::NoTarget);
            }
            Some(false) => {
                tx.rollback().await?;
                return Ok(LicenseMerge::TargetBounded);
            }
            Some(true) => {}
        }
        // Set entitlements: materialize the source's effective bound onto the
        // moved edge; union with any existing target edge (NULL wins per axis).
        sqlx::query(
            "insert into license_set_entitlements \
                 (license_key_id, set_id, update_until, version_cap_major) \
             select $2, lse.set_id, \
                    coalesce(lse.update_until, l.update_until), \
                    coalesce(lse.version_cap_major, l.version_cap_major) \
             from license_set_entitlements lse \
             join license_keys l on l.id = lse.license_key_id \
             where lse.license_key_id = $1 \
             on conflict (license_key_id, set_id) do update set \
                 update_until = case when license_set_entitlements.update_until is null \
                                       or excluded.update_until is null then null \
                                     else greatest(license_set_entitlements.update_until, \
                                                   excluded.update_until) end, \
                 version_cap_major = case when license_set_entitlements.version_cap_major is null \
                                            or excluded.version_cap_major is null then null \
                                          else greatest(license_set_entitlements.version_cap_major, \
                                                        excluded.version_cap_major) end",
        )
        .bind(source_id)
        .bind(target_id)
        .execute(&mut *tx)
        .await?;
        // Direct package entitlements (snapshot rows), same materialize + union.
        sqlx::query(
            "insert into entitlements \
                 (license_key_id, package_id, update_until, version_cap_major) \
             select $2, e.package_id, \
                    coalesce(e.update_until, l.update_until), \
                    coalesce(e.version_cap_major, l.version_cap_major) \
             from entitlements e \
             join license_keys l on l.id = e.license_key_id \
             where e.license_key_id = $1 \
             on conflict (license_key_id, package_id) do update set \
                 update_until = case when entitlements.update_until is null \
                                       or excluded.update_until is null then null \
                                     else greatest(entitlements.update_until, \
                                                   excluded.update_until) end, \
                 version_cap_major = case when entitlements.version_cap_major is null \
                                            or excluded.version_cap_major is null then null \
                                          else greatest(entitlements.version_cap_major, \
                                                        excluded.version_cap_major) end",
        )
        .bind(source_id)
        .bind(target_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query("update license_keys set status = 'revoked' where id = $1")
            .bind(source_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(LicenseMerge::Merged)
    }

    /// Detach an edition's set entitlement from a license — a refund of one line
    /// item on a shared key. Removes only the by-reference set entitlement, the
    /// mirror of how [`Self::add_edition_to_license`] attached it. Returns whether
    /// the key exists in the repo (so a caller distinguishes "removed / nothing to
    /// remove" from "no such key"). Idempotent, and deliberately does **not**
    /// revoke the key even when it now entitles nothing: the caller tracks the
    /// per-item rows and revokes once the last item is gone.
    pub async fn remove_edition_from_license(
        &self,
        repo_id: Uuid,
        license_id: Uuid,
        edition_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        // Both the key and the edition are repo-scoped (defense in depth): the
        // subselects yield no id for a foreign key/edition, so the delete matches
        // nothing.
        sqlx::query(
            "delete from license_set_entitlements \
             where license_key_id = (select id from license_keys \
                                     where id = $1 and repo_id = $2) \
               and set_id = (select set_id from editions \
                             where id = $3 and repo_id = $2)",
        )
        .bind(license_id)
        .bind(repo_id)
        .bind(edition_id)
        .execute(&self.pool)
        .await?;
        sqlx::query_scalar(
            "select exists(select 1 from license_keys where id = $1 and repo_id = $2)",
        )
        .bind(license_id)
        .bind(repo_id)
        .fetch_one(&self.pool)
        .await
    }

    /// The license id previously issued for a `(repo, edition, idempotency_key)`,
    /// if any. Scoped to the edition so one order id can provision one key per SKU.
    async fn license_id_for_idempotency(
        &self,
        repo_id: Uuid,
        edition_id: Uuid,
        idempotency_key: &str,
    ) -> Result<Option<Uuid>, sqlx::Error> {
        sqlx::query_scalar(
            "select id from license_keys \
             where repo_id = $1 and edition_id = $2 and idempotency_key = $3",
        )
        .bind(repo_id)
        .bind(edition_id)
        .bind(idempotency_key)
        .fetch_optional(&self.pool)
        .await
    }

    /// Recover a license key's plaintext from its at-rest ciphertext. `Ok(None)`
    /// if no secret key is configured, the key wasn't stored encrypted (issued
    /// before this / with no secret key), the license doesn't exist, or the
    /// ciphertext fails to decrypt. Auth never uses this — only recovery/display.
    pub async fn license_key_plaintext(
        &self,
        repo_id: Uuid,
        license_id: Uuid,
    ) -> Result<Option<String>, sqlx::Error> {
        let Some(secret) = self.secret_key.as_ref() else {
            return Ok(None);
        };
        let ciphertext: Option<Vec<u8>> = sqlx::query_scalar(
            "select key_ciphertext from license_keys where id = $1 and repo_id = $2",
        )
        .bind(license_id)
        .bind(repo_id)
        .fetch_optional(&self.pool)
        .await?
        .flatten();
        let Some(bytes) = ciphertext else {
            return Ok(None);
        };
        match secret.decrypt(&bytes) {
            Ok(plain) => Ok(String::from_utf8(plain).ok()),
            Err(e) => {
                // A stored ciphertext that won't decrypt means recoverability was
                // silently lost — almost always SCONCE_SECRET_KEY was rotated or a
                // replica is misconfigured with a different key. Surface it: the
                // caller still gets `None` (nothing to display), but operators need
                // the signal, since inspect/replay would otherwise just show blanks.
                tracing::warn!(
                    %license_id,
                    error = %e,
                    "license key ciphertext failed to decrypt — key unrecoverable \
                     (SCONCE_SECRET_KEY rotated or mismatched?)"
                );
                Ok(None)
            }
        }
    }

    /// Extend an active, time-bounded key's `update_until` by its edition's period.
    /// `$1` = repo id, `$2` = license id. The `status = 'active'` guard stops a
    /// revoked key from being "renewed" into a contradictory revoked-but-future
    /// state. No row (→ `None`) for a missing/revoked/non-time-bounded key.
    const RENEW_SQL: &'static str = "update license_keys l \
        set update_until = greatest(l.update_until, now()) \
                           + make_interval(months => e.bound_period_months) \
     from editions e \
     where l.id = $2 and l.repo_id = $1 and l.edition_id = e.id \
       and e.bound_kind = 'time' and l.status = 'active' \
     returning to_char(l.update_until, 'YYYY-MM-DD')";

    /// Extend an **active** license key's **time** bound by its edition's period
    /// (renewal): `update_until = greatest(update_until, now()) + period`, so a
    /// renewal before expiry stacks and one after expiry restarts from today.
    /// Returns the new `YYYY-MM-DD` bound, or `Ok(None)` if the key isn't found, is
    /// revoked, or wasn't issued from a time-bounded edition (version/perpetual
    /// editions renew by issuing against a new edition, not by extension).
    ///
    /// When `idempotency_key` is set, the renewal is recorded and a repeat with the
    /// same key is a **no-op** that returns the current bound instead of extending
    /// again — so an at-least-once "subscription renewed" webhook can't stack
    /// multiple periods onto one payment.
    pub async fn renew_license(
        &self,
        repo_id: Uuid,
        license_id: Uuid,
        idempotency_key: Option<&str>,
    ) -> Result<Option<String>, sqlx::Error> {
        // No idempotency key: extend directly (caller opted out of dedup).
        let Some(idem) = idempotency_key else {
            return self.extend_time_bound(repo_id, license_id).await;
        };
        let mut tx = self.pool.begin().await?;
        // Record this renewal; a duplicate (retry) inserts nothing.
        let fresh: Option<Uuid> = sqlx::query_scalar(
            "insert into license_renewals (license_key_id, idempotency_key) \
             select l.id, $3 from license_keys l where l.id = $2 and l.repo_id = $1 \
             on conflict (license_key_id, idempotency_key) do nothing \
             returning license_key_id",
        )
        .bind(repo_id)
        .bind(license_id)
        .bind(idem)
        .fetch_optional(&mut *tx)
        .await?;
        let bound = if fresh.is_some() {
            // First time for this key: extend the bound.
            self.extend_time_bound_tx(&mut tx, repo_id, license_id)
                .await?
        } else {
            // Replay: return the current bound unchanged (only for a renewable key,
            // so the response shape matches a fresh renewal).
            sqlx::query_scalar(
                "select to_char(l.update_until, 'YYYY-MM-DD') from license_keys l \
                 join editions e on e.id = l.edition_id \
                 where l.id = $2 and l.repo_id = $1 and l.status = 'active' \
                   and e.bound_kind = 'time'",
            )
            .bind(repo_id)
            .bind(license_id)
            .fetch_optional(&mut *tx)
            .await?
        };
        tx.commit().await?;
        Ok(bound)
    }

    /// The edge-renewal `UPDATE`: extend an explicitly time-bounded set
    /// entitlement (0047) on an active key by its edition's period. `$1` = repo,
    /// `$2` = license, `$3` = edition. Mirrors [`Self::RENEW_SQL`] semantics:
    /// renewing before expiry stacks, after expiry restarts from today. The
    /// `lse.update_until is not null` guard keeps legacy standalone keys (bound
    /// on the key, NULL edge) on the key-level renew path.
    const RENEW_EDGE_SQL: &'static str = "update license_set_entitlements lse \
        set update_until = greatest(lse.update_until, now()) \
                           + make_interval(months => e.bound_period_months) \
     from editions e, license_keys l \
     where lse.license_key_id = $2 and lse.set_id = e.set_id \
       and l.id = $2 and l.repo_id = $1 and l.status = 'active' \
       and e.id = $3 and e.repo_id = $1 and e.bound_kind = 'time' \
       and lse.update_until is not null \
     returning to_char(lse.update_until, 'YYYY-MM-DD')";

    /// Extend one **edition's** time-bounded entitlement edge on an active key
    /// (the renewal for accumulated keys, where the bound lives per entitlement —
    /// 0047 — not on the key). Returns the new `YYYY-MM-DD` edge bound, or
    /// `Ok(None)` if the key is missing/revoked, the edition isn't time-bounded,
    /// or the key has no explicitly-bounded edge for it (a legacy standalone key
    /// renews via [`Self::renew_license`] instead).
    ///
    /// Idempotent like key-level renewal: with an `idempotency_key`, a replayed
    /// "subscription renewed" webhook returns the current edge bound instead of
    /// stacking a second period (dedup shares the `license_renewals` ledger).
    pub async fn renew_license_edition(
        &self,
        repo_id: Uuid,
        license_id: Uuid,
        edition_id: Uuid,
        idempotency_key: Option<&str>,
    ) -> Result<Option<String>, sqlx::Error> {
        let Some(idem) = idempotency_key else {
            return sqlx::query_scalar(Self::RENEW_EDGE_SQL)
                .bind(repo_id)
                .bind(license_id)
                .bind(edition_id)
                .fetch_optional(&self.pool)
                .await;
        };
        let mut tx = self.pool.begin().await?;
        let fresh: Option<Uuid> = sqlx::query_scalar(
            "insert into license_renewals (license_key_id, idempotency_key) \
             select l.id, $3 from license_keys l where l.id = $2 and l.repo_id = $1 \
             on conflict (license_key_id, idempotency_key) do nothing \
             returning license_key_id",
        )
        .bind(repo_id)
        .bind(license_id)
        .bind(idem)
        .fetch_optional(&mut *tx)
        .await?;
        let bound = if fresh.is_some() {
            sqlx::query_scalar(Self::RENEW_EDGE_SQL)
                .bind(repo_id)
                .bind(license_id)
                .bind(edition_id)
                .fetch_optional(&mut *tx)
                .await?
        } else {
            // Replay: report the current edge bound unchanged (only for a
            // renewable edge, matching a fresh renewal's response shape).
            sqlx::query_scalar(
                "select to_char(lse.update_until, 'YYYY-MM-DD') \
                 from license_set_entitlements lse \
                 join license_keys l on l.id = lse.license_key_id \
                 join editions e on e.set_id = lse.set_id and e.repo_id = l.repo_id \
                 where l.id = $2 and l.repo_id = $1 and l.status = 'active' \
                   and e.id = $3 and e.bound_kind = 'time' \
                   and lse.update_until is not null",
            )
            .bind(repo_id)
            .bind(license_id)
            .bind(edition_id)
            .fetch_optional(&mut *tx)
            .await?
        };
        tx.commit().await?;
        Ok(bound)
    }

    /// The renewal `UPDATE` (extend the time bound of an active, time-bounded key),
    /// on the pool.
    async fn extend_time_bound(
        &self,
        repo_id: Uuid,
        license_id: Uuid,
    ) -> Result<Option<String>, sqlx::Error> {
        sqlx::query_scalar(Self::RENEW_SQL)
            .bind(repo_id)
            .bind(license_id)
            .fetch_optional(&self.pool)
            .await
    }

    /// The renewal `UPDATE`, inside a transaction (idempotent-renewal path).
    async fn extend_time_bound_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        repo_id: Uuid,
        license_id: Uuid,
    ) -> Result<Option<String>, sqlx::Error> {
        sqlx::query_scalar(Self::RENEW_SQL)
            .bind(repo_id)
            .bind(license_id)
            .fetch_optional(&mut **tx)
            .await
    }

    /// Revoke a license key (status → `revoked`); serving stops honoring it
    /// immediately. Returns whether a key matched. Idempotent.
    pub async fn revoke_license(
        &self,
        repo_id: Uuid,
        license_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let n = sqlx::query(
            "update license_keys set status = 'revoked' where id = $1 and repo_id = $2",
        )
        .bind(license_id)
        .bind(repo_id)
        .execute(&self.pool)
        .await?;
        Ok(n.rows_affected() > 0)
    }

    /// Full detail of one license key (management-API inspect): buyer, status, the
    /// edition it came from, the packages it currently resolves to, and its bound.
    /// `None` if the key isn't in the repo.
    pub async fn license_detail(
        &self,
        repo_id: Uuid,
        license_id: Uuid,
    ) -> Result<Option<LicenseDetail>, sqlx::Error> {
        let row = sqlx::query(
            "select l.buyer_ref as buyer, l.status as status, e.name as edition, \
                    to_char(l.update_until, 'YYYY-MM-DD') as until, \
                    extract(epoch from l.update_until)::bigint as until_unix, \
                    l.version_cap_major as major \
             from license_keys l left join editions e on e.id = l.edition_id \
             where l.id = $1 and l.repo_id = $2",
        )
        .bind(license_id)
        .bind(repo_id)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else { return Ok(None) };
        let packages = self.entitled_package_names(license_id).await?;
        let key = self.license_key_plaintext(repo_id, license_id).await?;
        Ok(Some(LicenseDetail {
            id: license_id,
            buyer: row.try_get("buyer").ok().flatten(),
            status: row.try_get("status")?,
            edition: row.try_get("edition").ok().flatten(),
            packages,
            bound: LicenseBound {
                until: row.try_get("until").ok().flatten(),
                until_unix: row.try_get("until_unix").ok().flatten(),
                major: row.try_get("major").ok().flatten(),
            },
            key,
        }))
    }

    // ----- Management-API service tokens -----------------------------------
    //
    // These deliberately mirror the read-`tokens` CRUD above but live in their own
    // `service_tokens` table, and that separation is INTENTIONAL — do not merge the
    // two into one table to remove the apparent duplication. Read tokens and
    // service tokens sit at opposite privilege levels: a read token only unlocks
    // Composer *serving* (download packages), while a service token can *provision*
    // license keys via `/api/v1` (issue / renew / revoke — money-adjacent writes).
    // Keeping them in separate tables makes the isolation hold *by construction*:
    // `resolve_service_token` only ever reads `service_tokens`, so a read token
    // physically cannot authenticate the management API (and vice versa for
    // `token_valid` / serving). A single table with a `kind` discriminator would
    // make that guarantee depend on every query remembering the right filter — one
    // slip is a privilege escalation. See `read_and_service_tokens_do_not_cross_
    // authenticate` for the regression guard. They also genuinely diverge: read
    // tokens are policy-gated at creation, carry serving policy + `origin`, and
    // resolve scoped to a known repo; service tokens have none of that and resolve
    // globally to discover their repo.

    /// Mint a repo-scoped service token for the management API. Returns the
    /// plaintext (shown once); only its hash is stored. `expires_days`, when set,
    /// bounds its lifetime.
    pub async fn create_service_token(
        &self,
        repo_id: Uuid,
        label: Option<&str>,
        expires_days: Option<i64>,
    ) -> Result<(String, Uuid), sqlx::Error> {
        let token = generate_secret("scst_");
        let id: Uuid = sqlx::query_scalar(
            "insert into service_tokens (repo_id, token_hash, label, expires_at) \
             values ($1, $2, $3, \
                     case when $4::bigint is null then null \
                          else now() + make_interval(days => $4::int) end) \
             returning id",
        )
        .bind(repo_id)
        .bind(token_hash(&token))
        .bind(label)
        .bind(expires_days)
        .fetch_one(&self.pool)
        .await?;
        Ok((token, id))
    }

    /// Validate a service token and return the repo it authorizes, stamping
    /// `last_used_at`. `None` if unknown, revoked (deleted), or expired.
    pub async fn resolve_service_token(&self, token: &str) -> Result<Option<Uuid>, sqlx::Error> {
        sqlx::query_scalar(
            "update service_tokens set last_used_at = now() \
             where token_hash = $1 and (expires_at is null or expires_at > now()) \
             returning repo_id",
        )
        .bind(token_hash(token))
        .fetch_optional(&self.pool)
        .await
    }

    /// Mint a short-lived **publish** token (`scpt_` prefix) for a repo. Minted only
    /// by the OIDC publish exchange; authorizes uploading package versions and
    /// nothing else. Returns the plaintext (shown once, stored only as sha256).
    pub async fn create_publish_token(
        &self,
        repo_id: Uuid,
        label: &str,
        ttl_secs: i64,
    ) -> Result<String, sqlx::Error> {
        let token = generate_secret("scpt_");
        sqlx::query(
            "insert into publish_tokens (repo_id, token_hash, label, expires_at) values \
             ($1, $2, $3, now() + make_interval(secs => $4::double precision))",
        )
        .bind(repo_id)
        .bind(token_hash(&token))
        .bind(label)
        .bind(ttl_secs)
        .execute(&self.pool)
        .await?;
        Ok(token)
    }

    /// Validate a publish token and return the repo it authorizes, stamping
    /// `last_used_at`. `None` if unknown, revoked, or expired. A read or service
    /// token can never resolve here — publish tokens live in their own table.
    pub async fn resolve_publish_token(&self, token: &str) -> Result<Option<Uuid>, sqlx::Error> {
        sqlx::query_scalar(
            "update publish_tokens set last_used_at = now() \
             where token_hash = $1 and (expires_at is null or expires_at > now()) \
             returning repo_id",
        )
        .bind(token_hash(token))
        .fetch_optional(&self.pool)
        .await
    }

    /// Open a chunked-upload session for `(vendor/name, version)` in a repo,
    /// expiring `ttl_secs` from now. Returns the new session id.
    pub async fn create_upload_session(
        &self,
        repo_id: Uuid,
        vendor: &str,
        name: &str,
        version: &str,
        ttl_secs: i64,
    ) -> Result<Uuid, sqlx::Error> {
        sqlx::query_scalar(
            "insert into upload_sessions (repo_id, vendor, name, version, expires_at) \
             values ($1, $2, $3, $4, now() + make_interval(secs => $5::double precision)) \
             returning id",
        )
        .bind(repo_id)
        .bind(vendor)
        .bind(name)
        .bind(version)
        .bind(ttl_secs)
        .fetch_one(&self.pool)
        .await
    }

    /// Fetch a session by id (any status). `None` if unknown.
    pub async fn upload_session(&self, id: Uuid) -> Result<Option<UploadSession>, sqlx::Error> {
        let row = sqlx::query(
            "select id, repo_id, kind, vendor, name, version, environment, status \
             from upload_sessions where id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|r| {
            Ok(UploadSession {
                id: r.try_get("id")?,
                repo_id: r.try_get("repo_id")?,
                kind: r.try_get("kind")?,
                vendor: r.try_get("vendor")?,
                name: r.try_get("name")?,
                version: r.try_get("version")?,
                environment: r.try_get("environment")?,
                status: r.try_get("status")?,
            })
        })
        .transpose()
    }

    /// Open a chunked-upload session for a **snapshot** — a `.jibsdump` for
    /// `environment` in a repo, expiring `ttl_secs` from now. Shares the part-staging
    /// and assemble routes with package uploads; `upload_complete` dispatches on the
    /// session's `kind`. Returns the new session id.
    pub async fn create_snapshot_upload_session(
        &self,
        repo_id: Uuid,
        environment: &str,
        ttl_secs: i64,
    ) -> Result<Uuid, sqlx::Error> {
        sqlx::query_scalar(
            "insert into upload_sessions (repo_id, kind, environment, expires_at) \
             values ($1, 'snapshot', $2, now() + make_interval(secs => $3::double precision)) \
             returning id",
        )
        .bind(repo_id)
        .bind(environment)
        .bind(ttl_secs)
        .fetch_one(&self.pool)
        .await
    }

    /// Record (or overwrite) a staged part — idempotent on `(session, part_number)`,
    /// so a retried or resumed part upload is safe.
    pub async fn record_upload_part(
        &self,
        session_id: Uuid,
        part_number: i32,
        chunk_sha256: &[u8; 32],
        size_bytes: i64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "insert into upload_parts (session_id, part_number, chunk_sha256, size_bytes) \
             values ($1, $2, $3, $4) \
             on conflict (session_id, part_number) do update set \
                 chunk_sha256 = excluded.chunk_sha256, size_bytes = excluded.size_bytes",
        )
        .bind(session_id)
        .bind(part_number)
        .bind(&chunk_sha256[..])
        .bind(size_bytes)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// All staged parts for a session, ordered by part number (assembly order).
    pub async fn upload_parts(&self, session_id: Uuid) -> Result<Vec<UploadPart>, sqlx::Error> {
        let rows = sqlx::query(
            "select part_number, chunk_sha256, size_bytes from upload_parts \
             where session_id = $1 order by part_number",
        )
        .bind(session_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok(UploadPart {
                    part_number: r.try_get("part_number")?,
                    chunk_sha256: r.try_get("chunk_sha256")?,
                    size_bytes: r.try_get("size_bytes")?,
                })
            })
            .collect()
    }

    /// Set a session's status (`completed` / `aborted`).
    pub async fn set_upload_status(&self, id: Uuid, status: &str) -> Result<(), sqlx::Error> {
        sqlx::query("update upload_sessions set status = $2 where id = $1")
            .bind(id)
            .bind(status)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Abort every `open` session past its deadline (worker sweep). Parts cascade;
    /// staged chunk blobs are reclaimed by the orphan GC. Returns how many aborted.
    pub async fn expire_upload_sessions(&self) -> Result<u64, sqlx::Error> {
        let n = sqlx::query(
            "update upload_sessions set status = 'aborted' \
             where status = 'open' and expires_at <= now()",
        )
        .execute(&self.pool)
        .await?;
        Ok(n.rows_affected())
    }

    /// Register an uploaded snapshot for `environment` in a repo, referencing the
    /// already-stored `.jibsdump` blob. Inserting the row bumps the blob's refcount
    /// (trigger, migration 0045). Call [`Catalog::upsert_blob`] first so the blob's
    /// size + `last_seen_at` are recorded before the GC grace window applies.
    pub async fn create_snapshot(
        &self,
        repo_id: Uuid,
        environment: &str,
        blob_sha256: &[u8; 32],
        size_bytes: i64,
        source_ref: Option<&str>,
    ) -> Result<Uuid, sqlx::Error> {
        sqlx::query_scalar(
            "insert into snapshots (repo_id, environment, blob_sha256, size_bytes, source_ref) \
             values ($1, $2, $3, $4, $5) returning id",
        )
        .bind(repo_id)
        .bind(environment)
        .bind(&blob_sha256[..])
        .bind(size_bytes)
        .bind(source_ref)
        .fetch_one(&self.pool)
        .await
    }

    /// Point `(repo, environment)`'s "latest" at `snapshot_id`. Upsert, so the first
    /// upload creates the pointer and every later one moves it.
    pub async fn advance_latest(
        &self,
        repo_id: Uuid,
        environment: &str,
        snapshot_id: Uuid,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "insert into snapshot_latest (repo_id, environment, snapshot_id) \
             values ($1, $2, $3) \
             on conflict (repo_id, environment) do update set \
                 snapshot_id = excluded.snapshot_id, updated_at = now()",
        )
        .bind(repo_id)
        .bind(environment)
        .bind(snapshot_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Resolve `(repo, environment)`'s current "latest" snapshot. `None` if the
    /// environment has never had a snapshot uploaded.
    pub async fn resolve_latest(
        &self,
        repo_id: Uuid,
        environment: &str,
    ) -> Result<Option<Snapshot>, sqlx::Error> {
        let row = sqlx::query(
            "select s.id, s.environment, s.blob_sha256, s.size_bytes, s.source_ref, \
                    extract(epoch from s.created_at)::bigint as created_at \
             from snapshot_latest l join snapshots s on s.id = l.snapshot_id \
             where l.repo_id = $1 and l.environment = $2",
        )
        .bind(repo_id)
        .bind(environment)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(row_to_snapshot).transpose()
    }

    /// Resolve a snapshot pinned by its blob digest within a repo+environment — for
    /// reproducible downloads. Scoped to the repo+environment so a read token can't
    /// resolve an arbitrary CAS blob it was never granted. `None` if no snapshot in
    /// that repo+environment references the digest.
    pub async fn resolve_snapshot_by_digest(
        &self,
        repo_id: Uuid,
        environment: &str,
        blob_sha256: &[u8; 32],
    ) -> Result<Option<Snapshot>, sqlx::Error> {
        let row = sqlx::query(
            "select id, environment, blob_sha256, size_bytes, source_ref, \
                    extract(epoch from created_at)::bigint as created_at \
             from snapshots \
             where repo_id = $1 and environment = $2 and blob_sha256 = $3 \
             order by created_at desc limit 1",
        )
        .bind(repo_id)
        .bind(environment)
        .bind(&blob_sha256[..])
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(row_to_snapshot).transpose()
    }

    /// A repo+environment's snapshots, newest first.
    pub async fn list_snapshots(
        &self,
        repo_id: Uuid,
        environment: &str,
    ) -> Result<Vec<Snapshot>, sqlx::Error> {
        let rows = sqlx::query(
            "select id, environment, blob_sha256, size_bytes, source_ref, \
                    extract(epoch from created_at)::bigint as created_at \
             from snapshots where repo_id = $1 and environment = $2 \
             order by created_at desc",
        )
        .bind(repo_id)
        .bind(environment)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(row_to_snapshot).collect()
    }

    /// Retention: keep the `keep` newest snapshots in `(repo, environment)`, deleting
    /// the rest. Never deletes the one the "latest" pointer references (so `latest`
    /// always resolves). Deleting a row decrements its blob's refcount; the existing
    /// orphan GC (`sconce gc`) then reclaims any blob that hits refcount 0. Returns
    /// how many snapshots were deleted.
    pub async fn prune_snapshots(
        &self,
        repo_id: Uuid,
        environment: &str,
        keep: i64,
    ) -> Result<u64, sqlx::Error> {
        let n = sqlx::query(
            "delete from snapshots \
             where repo_id = $1 and environment = $2 \
               and id not in ( \
                   select snapshot_id from snapshot_latest \
                   where repo_id = $1 and environment = $2 \
               ) \
               and id not in ( \
                   select id from snapshots \
                   where repo_id = $1 and environment = $2 \
                   order by created_at desc limit $3 \
               )",
        )
        .bind(repo_id)
        .bind(environment)
        .bind(keep.max(0))
        .execute(&self.pool)
        .await?;
        Ok(n.rows_affected())
    }

    /// A repo's service tokens (never the tokens themselves), newest first.
    pub async fn list_service_tokens(
        &self,
        repo_id: Uuid,
    ) -> Result<Vec<ServiceTokenSummary>, sqlx::Error> {
        let rows = sqlx::query(
            "select id, label, to_char(created_at, 'YYYY-MM-DD') as created, \
                    to_char(last_used_at, 'YYYY-MM-DD') as last_used, \
                    to_char(expires_at, 'YYYY-MM-DD') as expires \
             from service_tokens where repo_id = $1 order by created_at desc",
        )
        .bind(repo_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok(ServiceTokenSummary {
                    id: r.try_get("id")?,
                    label: r.try_get("label").ok().flatten(),
                    created: r.try_get("created")?,
                    last_used: r.try_get("last_used").ok().flatten(),
                    expires: r.try_get("expires").ok().flatten(),
                })
            })
            .collect()
    }

    /// Revoke (delete) a service token by id, scoped to its repo. Returns whether
    /// one was removed.
    pub async fn revoke_service_token(
        &self,
        repo_id: Uuid,
        token_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let n = sqlx::query("delete from service_tokens where id = $1 and repo_id = $2")
            .bind(token_id)
            .bind(repo_id)
            .execute(&self.pool)
            .await?;
        Ok(n.rows_affected() > 0)
    }

    /// Build an [`Edition`] from a listing row (shared by `list_editions` /
    /// `edition`).
    fn edition_from_row(row: &sqlx::postgres::PgRow) -> Result<Edition, sqlx::Error> {
        Ok(Edition {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            slug: row.try_get("slug").ok().flatten(),
            set_id: row.try_get("set_id")?,
            set_name: row.try_get("set_name")?,
            bound: EditionBound::from_columns(
                row.try_get("bound_kind")?,
                row.try_get("bound_period_months").ok().flatten(),
                row.try_get("bound_major").ok().flatten(),
            ),
            snapshot: row.try_get("snapshot_at_issue")?,
            policy: PolicyOverride {
                update_mode: row.try_get("update_mode").ok().flatten(),
                cooldown_days: row.try_get("cooldown_days").ok().flatten(),
            },
            active: row.try_get("active")?,
        })
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
        let rows = sqlx::query(&format!(
            "select distinct p.name from packages p \
             join repositories r on r.id = $1 \
             where (r.allow_private_packages or p.visibility = 'public') \
               and ( p.repo_id = $1 \
                     or exists (select 1 from repository_grants g \
                                where g.repo_id = $1 and g.package_id = p.id) \
                     or {GRANT_RULE_EXISTS} ) \
             order by p.name"
        ))
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
             where p.repo_id = $1 and p.name = $2 and pv.yanked_at is null",
        )
        .bind(repo_id)
        .bind(name)
        .fetch_all(&self.pool)
        .await?;
        let mut versions: Vec<PackageVersion> =
            rows.iter().map(row_to_version).collect::<Result<_, _>>()?;
        sort_versions_ascending(&mut versions);
        Ok(versions)
    }

    /// The versions of a package **visible** under an explicit update policy —
    /// the read path Composer serving builds on (the server passes its global
    /// policy in). A version is hidden if yanked or held; otherwise: `auto` →
    /// all visible; `manual` → only approved; `delayed` → visible once
    /// `released_at + cooldown_days` has passed (or it was approved early).
    ///
    /// Taking the policy as parameters (rather than reading the singleton here)
    /// keeps this pure and testable without mutating shared global state.
    #[allow(clippy::too_many_arguments)]
    pub async fn visible_versions(
        &self,
        repo_id: Uuid,
        name: &str,
        mode: &str,
        cooldown_days: i32,
        // Perpetual-fallback license bound (both `None` = unbounded). `$5` =
        // update-until (unix seconds), `$6` = max allowed major version.
        bound_until_unix: Option<i64>,
        bound_major: Option<i32>,
    ) -> Result<Vec<PackageVersion>, sqlx::Error> {
        let rows = sqlx::query(&format!(
            "select pv.version, pv.normalized_version, pv.stability, pv.composer_json, \
                    pv.dist_blob_sha256, pv.dist_shasum, pv.source_reference \
             from package_versions pv \
             join packages p on p.id = pv.package_id \
             join repositories r on r.id = $1 \
             where p.name = $2 \
               and ( p.repo_id = $1 \
                     or exists (select 1 from repository_grants g \
                                where g.repo_id = $1 and g.package_id = p.id) \
                     or {GRANT_RULE_EXISTS} ) \
               and (r.allow_private_packages or p.visibility = 'public') \
               and pv.yanked_at is null \
               and pv.held_at is null \
               and ( $3 = 'auto' \
                     or pv.approved_at is not null \
                     or ( $3 = 'delayed' \
                          and pv.released_at is not null \
                          and pv.released_at + make_interval(days => $4) <= now() ) ) \
               and ( $5::bigint is null \
                     or ( coalesce(pv.entitlement_date, pv.released_at) is not null \
                          and coalesce(pv.entitlement_date, pv.released_at) \
                              - make_interval(days => pv.grace_days) <= to_timestamp($5::double precision) ) ) \
               and ( $6::int is null \
                     or coalesce(nullif(split_part(pv.normalized_version, '.', 1), '')::int, 0) <= $6 )"
        ))
        .bind(repo_id)
        .bind(name)
        .bind(mode)
        .bind(cooldown_days)
        .bind(bound_until_unix)
        .bind(bound_major)
        .fetch_all(&self.pool)
        .await?;
        let mut versions: Vec<PackageVersion> =
            rows.iter().map(row_to_version).collect::<Result<_, _>>()?;
        sort_versions_ascending(&mut versions);
        Ok(versions)
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

    /// Bulk-approve every still-undecided version in a repo (those with no
    /// hold / yank / approval yet), optionally narrowed to one package. Powers
    /// the Approvals tab's per-package "Approve all N" and footer "Approve all
    /// pending" actions. Returns the number of versions exposed.
    pub async fn approve_all_pending(
        &self,
        repo_id: Uuid,
        package: Option<&str>,
    ) -> Result<u64, sqlx::Error> {
        let done = sqlx::query(
            "update package_versions pv set approved_at = now() \
             from packages p \
             where p.id = pv.package_id and p.repo_id = $1 \
               and ($2::text is null or p.name = $2) \
               and pv.held_at is null and pv.yanked_at is null and pv.approved_at is null",
        )
        .bind(repo_id)
        .bind(package)
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected())
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

/// A short, human-typeable device `user_code` like `WXYZ-1234` (8 hex chars from
/// a v4 UUID, upper-cased and hyphenated) — shown in the terminal and typed into
/// the approval page.
fn generate_user_code() -> String {
    let hex = Uuid::new_v4().simple().to_string();
    format!("{}-{}", &hex[..4], &hex[4..8]).to_uppercase()
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

/// Whether a query error is a Postgres unique-constraint violation (SQLSTATE
/// 23505) — used to turn a lost idempotency race into a graceful replay.
fn is_unique_violation(e: &sqlx::Error) -> bool {
    e.as_database_error()
        .is_some_and(sqlx::error::DatabaseError::is_unique_violation)
}

/// Lowercase hex of bytes (matches Postgres `encode(_, 'hex')`).
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
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
/// Sort versions ascending by Composer version order, so `1.10.0.0` sorts after
/// `1.9.0.0` (a lexicographic sort on the normalized string gets this wrong).
/// A value that fails to parse falls back to a string comparison, keeping the
/// ordering total.
fn sort_versions_ascending(versions: &mut [PackageVersion]) {
    use composer_semver::Version;
    versions.sort_by(|a, b| {
        match (
            Version::parse(&a.normalized_version),
            Version::parse(&b.normalized_version),
        ) {
            (Ok(va), Ok(vb)) => va.cmp(&vb),
            _ => a.normalized_version.cmp(&b.normalized_version),
        }
    });
}

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

fn row_to_snapshot(row: &sqlx::postgres::PgRow) -> Result<Snapshot, sqlx::Error> {
    let raw: Vec<u8> = row.try_get("blob_sha256")?;
    let mut blob = [0u8; 32];
    // A sha256 column is always 32 bytes; truncate/pad defensively rather than panic.
    let n = raw.len().min(32);
    blob[..n].copy_from_slice(&raw[..n]);
    Ok(Snapshot {
        id: row.try_get("id")?,
        environment: row.try_get("environment")?,
        blob_sha256: blob,
        size_bytes: row.try_get("size_bytes")?,
        source_ref: row.try_get("source_ref")?,
        created_at: row.try_get("created_at")?,
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
    #[allow(clippy::too_many_lines)]
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
            norm(
                cat.visible_versions(repo_id, p, "auto", 0, None, None)
                    .await
                    .unwrap()
            ),
            ["1.0.0.0", "1.1.0.0"]
        );
        assert_eq!(
            norm(
                cat.visible_versions(repo_id, p, "delayed", 7, None, None)
                    .await
                    .unwrap()
            ),
            ["1.0.0.0"]
        );

        assert!(cat.approve_version(repo_id, p, "1.1.0.0").await.unwrap());
        assert_eq!(
            norm(
                cat.visible_versions(repo_id, p, "delayed", 7, None, None)
                    .await
                    .unwrap()
            ),
            ["1.0.0.0", "1.1.0.0"]
        );
        assert_eq!(
            norm(
                cat.visible_versions(repo_id, p, "manual", 0, None, None)
                    .await
                    .unwrap()
            ),
            ["1.1.0.0"]
        );

        assert!(cat.hold_version(repo_id, p, "1.0.0.0").await.unwrap());
        assert_eq!(
            norm(
                cat.visible_versions(repo_id, p, "auto", 0, None, None)
                    .await
                    .unwrap()
            ),
            ["1.1.0.0"]
        );
        assert!(cat.unhold_version(repo_id, p, "1.0.0.0").await.unwrap());
        assert_eq!(
            norm(
                cat.visible_versions(repo_id, p, "auto", 0, None, None)
                    .await
                    .unwrap()
            ),
            ["1.0.0.0", "1.1.0.0"]
        );

        // Yank hides a version unconditionally (even though it was approved); a
        // prior approval doesn't override a yank. Un-yank reinstates it.
        assert!(cat.yank_version(repo_id, p, "1.1.0.0").await.unwrap());
        assert_eq!(
            norm(
                cat.visible_versions(repo_id, p, "auto", 0, None, None)
                    .await
                    .unwrap()
            ),
            ["1.0.0.0"]
        );
        assert!(cat.unyank_version(repo_id, p, "1.1.0.0").await.unwrap());

        // The operator view's countdown matches serving: under a 7-day cooldown
        // the 30-day-old version is past (0 left) while the just-released one has
        // ~7 days to go. (We set this repo's policy so admin_package_versions
        // computes against the real cooldown_days.)
        cat.set_update_policy(repo_id, "delayed", 7).await.unwrap();
        let av = cat
            .admin_package_versions(repo_id, 1000, 0, None, None)
            .await
            .unwrap();
        let old = av
            .iter()
            .find(|v| v.normalized_version == "1.0.0.0")
            .unwrap();
        let fresh = av
            .iter()
            .find(|v| v.normalized_version == "1.1.0.0")
            .unwrap();
        assert_eq!(
            old.cooldown_days_left,
            Some(0),
            "30-day-old is past cooldown"
        );
        assert!(
            matches!(fresh.cooldown_days_left, Some(n) if (1..=7).contains(&n)),
            "fresh release counts down (got {:?})",
            fresh.cooldown_days_left
        );
        assert!(
            fresh.approved,
            "approved flag surfaces in the operator view"
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

    #[test]
    fn policy_override_tightens_only() {
        let none = PolicyOverride::default();
        assert_eq!(none.effective("auto", 0), ("auto".to_owned(), 0));
        assert_eq!(none.effective("delayed", 7), ("delayed".to_owned(), 7));

        // A bare cooldown override implies `delayed` (cooldown is meaningless
        // under auto) and tightens auto -> delayed/30.
        let cd30 = PolicyOverride {
            update_mode: None,
            cooldown_days: Some(30),
        };
        assert_eq!(cd30.effective("auto", 0), ("delayed".to_owned(), 30));

        // mode tighten: auto -> manual.
        let man = PolicyOverride {
            update_mode: Some("manual".into()),
            cooldown_days: None,
        };
        assert_eq!(man.effective("auto", 0), ("manual".to_owned(), 0));

        // Tighten-only: a looser override can NEVER weaken the repo default.
        let loose = PolicyOverride {
            update_mode: Some("auto".into()),
            cooldown_days: Some(1),
        };
        assert_eq!(loose.effective("manual", 14), ("manual".to_owned(), 14));

        // Cooldown takes the max of repo and override.
        let cd5 = PolicyOverride {
            update_mode: Some("delayed".into()),
            cooldown_days: Some(5),
        };
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
        for (v, n, rel) in [
            ("v1.0.0", "1.0.0.0", now - 30 * day),
            ("v1.1.0", "1.1.0.0", now),
        ] {
            cat.upsert_package_version(pkg, v, n, "stable", &cj, None, None, None, Some(rel))
                .await
                .unwrap();
        }
        let p = "acme/lib";
        // Repo default is `auto`: a plain token sees both versions.
        let plain = cat
            .create_token(repo_id, Some("latest"), None)
            .await
            .unwrap();
        let pp = cat
            .resolve_token_policy(repo_id, &plain)
            .await
            .unwrap()
            .unwrap();
        let (m, c) = pp.effective("auto", 0);
        assert_eq!(
            cat.visible_versions(repo_id, p, &m, c, None, None)
                .await
                .unwrap()
                .len(),
            2
        );

        // A conservative token (delayed/7) on the SAME repo hides the fresh one.
        let cons = cat
            .create_token(repo_id, Some("conservative"), None)
            .await
            .unwrap();
        assert!(
            cat.set_token_policy(
                repo_id,
                "conservative",
                &PolicyOverride {
                    update_mode: Some("delayed".into()),
                    cooldown_days: Some(7)
                },
            )
            .await
            .unwrap()
        );
        let cp = cat
            .resolve_token_policy(repo_id, &cons)
            .await
            .unwrap()
            .unwrap();
        let (m2, c2) = cp.effective("auto", 0);
        assert_eq!((m2.as_str(), c2), ("delayed", 7));
        let vis = cat
            .visible_versions(repo_id, p, &m2, c2, None, None)
            .await
            .unwrap();
        assert_eq!(
            vis.len(),
            1,
            "conservative credential only sees the aged release"
        );
        assert_eq!(vis[0].normalized_version, "1.0.0.0");

        // An invalid/expired token resolves to no policy at all.
        assert!(
            cat.resolve_token_policy(repo_id, "sconce_bogus")
                .await
                .unwrap()
                .is_none()
        );
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

    /// The org that owns a `repo()`-made repository (one fresh org per repo).
    async fn org_of(cat: &Catalog, repo_id: Uuid) -> Uuid {
        cat.list_repositories()
            .await
            .unwrap()
            .into_iter()
            .find(|r| r.id == repo_id)
            .unwrap()
            .org_id
    }

    #[tokio::test]
    async fn repos_for_org_lists_only_that_orgs_repos() {
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        let org_id = org_of(&cat, repo_id).await;
        // The fresh org already has repo "r"; add two more.
        let slug = cat
            .list_repositories()
            .await
            .unwrap()
            .into_iter()
            .find(|r| r.id == repo_id)
            .unwrap()
            .org;
        cat.create_repo(&slug, "web").await.unwrap();
        cat.create_repo(&slug, "api").await.unwrap();
        // A second org with its own repo must not leak in.
        repo().await.unwrap();

        let mut got: Vec<String> = cat
            .repos_for_org(org_id)
            .await
            .unwrap()
            .into_iter()
            .map(|r| {
                assert_eq!(r.org, slug, "every row is this org");
                r.repo
            })
            .collect();
        got.sort();
        assert_eq!(got, ["api", "r", "web"]);
    }

    #[tokio::test]
    async fn device_flow_approve_mints_org_scoped_token() {
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        let org_id = org_of(&cat, repo_id).await;

        // Start a flow; it's pending and polling reports so.
        let (device_code, user_code) = cat.start_device_flow(600).await.unwrap();
        assert!(cat.device_flow_pending(&user_code).await.unwrap());
        assert!(matches!(
            cat.poll_device_flow(&device_code).await.unwrap(),
            DeviceFlowPoll::Pending
        ));

        // Approve it for the org (no approver row needed).
        assert!(
            cat.approve_device_flow(&user_code, org_id, None)
                .await
                .unwrap()
        );
        // It's no longer pending once decided.
        assert!(!cat.device_flow_pending(&user_code).await.unwrap());

        // The first post-approval poll consumes the flow and yields the org.
        match cat.poll_device_flow(&device_code).await.unwrap() {
            DeviceFlowPoll::Approved { org_id: got } => assert_eq!(got, org_id),
            other => panic!("expected Approved, got {other:?}"),
        }
        // A device_code is single-use: the second poll finds nothing.
        assert!(matches!(
            cat.poll_device_flow(&device_code).await.unwrap(),
            DeviceFlowPoll::Expired
        ));

        // The minted org-scoped token authenticates this repo on both serving
        // paths: `token_valid` (snapshot downloads) and `resolve_token_policy`
        // (the packages.json/p2/dist `authorize` path).
        let token = cat
            .create_session_token(org_id, "bougie login", 3600)
            .await
            .unwrap();
        assert!(
            cat.token_valid(repo_id, &token).await.unwrap(),
            "org-scoped token authenticates a repo in its org"
        );
        assert!(
            cat.resolve_token_policy(repo_id, &token)
                .await
                .unwrap()
                .is_some(),
            "org-scoped token resolves on the wire serving path"
        );
        // ...but not a repo in a different org.
        let (_, other_repo) = repo().await.unwrap();
        assert!(
            !cat.token_valid(other_repo, &token).await.unwrap(),
            "org-scoped token does not cross org boundaries"
        );
        assert!(
            cat.resolve_token_policy(other_repo, &token)
                .await
                .unwrap()
                .is_none(),
            "org-scoped token does not resolve for another org on the wire path"
        );
    }

    #[tokio::test]
    async fn resolve_org_session_token_matches_only_org_credentials() {
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        let org_id = org_of(&cat, repo_id).await;

        // A freshly minted org session token resolves to its org, with the
        // bounded TTL surfaced as a unix-seconds expiry.
        let token = cat
            .create_session_token(org_id, "bougie login", 3600)
            .await
            .unwrap();
        let resolved = cat
            .resolve_org_session_token(&token)
            .await
            .unwrap()
            .expect("org session token resolves");
        assert_eq!(resolved.org_id, org_id);
        assert!(
            resolved.expires_at_unix.is_some(),
            "a bounded TTL surfaces an expiry"
        );

        // An unknown token is inactive.
        assert!(
            cat.resolve_org_session_token("sconce_not_a_real_token")
                .await
                .unwrap()
                .is_none()
        );

        // A repo-scoped token (org_id null) is NOT an org session token.
        let repo_token = cat.create_token(repo_id, Some("r"), None).await.unwrap();
        assert!(
            cat.resolve_org_session_token(&repo_token)
                .await
                .unwrap()
                .is_none(),
            "a repo-scoped token does not resolve on the org introspection path"
        );

        // An already-expired org token is inactive.
        let expired = cat
            .create_session_token(org_id, "expired", -1)
            .await
            .unwrap();
        assert!(
            cat.resolve_org_session_token(&expired)
                .await
                .unwrap()
                .is_none(),
            "an expired org token does not resolve"
        );
    }

    #[tokio::test]
    async fn device_flow_deny_reports_denied() {
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        let (device_code, user_code) = cat.start_device_flow(600).await.unwrap();
        cat.deny_device_flow(&user_code).await.unwrap();
        assert!(matches!(
            cat.poll_device_flow(&device_code).await.unwrap(),
            DeviceFlowPoll::Denied
        ));
        // Approving a denied flow is a no-op (nothing pending to update).
        let org_id = org_of(&cat, repo_id).await;
        assert!(
            !cat.approve_device_flow(&user_code, org_id, None)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn device_flow_expired_before_approval() {
        let Some((cat, _)) = repo().await else {
            return;
        };
        // A zero-second TTL is already expired by the time we poll.
        let (device_code, user_code) = cat.start_device_flow(0).await.unwrap();
        assert!(!cat.device_flow_pending(&user_code).await.unwrap());
        assert!(matches!(
            cat.poll_device_flow(&device_code).await.unwrap(),
            DeviceFlowPoll::Expired
        ));
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
            .create_upstream(
                repo_id,
                "composer",
                "https://repo.packagist.org",
                Visibility::Public,
                Some("packagist"),
                None,
                "basic",
            )
            .await
            .unwrap();
        // Private upstream with an (already-encrypted) credential blob.
        let privid = cat
            .create_upstream(
                repo_id,
                "git",
                "https://git/x.git",
                Visibility::Private,
                None,
                Some(b"enc"),
                "basic",
            )
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
            .create_upstream(
                repo_id,
                "composer",
                "https://x",
                Visibility::Public,
                None,
                None,
                "basic",
            )
            .await
            .unwrap();

        // Generalized queue: each kind enqueues + claims with its fields.
        cat.enqueue_resolve_closure_job(repo_id).await.unwrap();
        cat.enqueue_mirror_package_job(up, "vendor/pkg")
            .await
            .unwrap();
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
        cat.replace_dependency_plan(repo_id, &entries)
            .await
            .unwrap();
        cat.replace_dependency_plan(repo_id, &entries)
            .await
            .unwrap(); // idempotent
        assert_eq!(cat.list_dependency_plan(repo_id).await.unwrap().len(), 2);
        let ab = cat
            .dependency_plan_entry(repo_id, "a/b")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ab.resolver_upstream_id, Some(up));
        assert!(
            cat.dependency_plan_entry(repo_id, "nope/x")
                .await
                .unwrap()
                .is_none()
        );
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
        assert_eq!(
            cat.scim_member(org_id, uid).await.unwrap(),
            Some((email.clone(), true))
        );
        assert_eq!(
            cat.scim_member_by_email(org_id, &email).await.unwrap(),
            Some((uid, true))
        );

        // The provisioned user has an active membership → a session sees the org.
        let session = cat.create_session(uid, 1).await.unwrap();
        assert!(
            cat.resolve_session(&session)
                .await
                .unwrap()
                .unwrap()
                .tenant_org_ids
                .contains(&org_id)
        );

        // Deactivate (the offboarding action) + revoke sessions.
        assert!(cat.scim_set_active(org_id, uid, false).await.unwrap());
        assert_eq!(cat.delete_user_sessions(uid).await.unwrap(), 1);
        // Session gone, and even a fresh session sees no active membership.
        assert!(cat.resolve_session(&session).await.unwrap().is_none());
        let s2 = cat.create_session(uid, 1).await.unwrap();
        assert!(
            !cat.resolve_session(&s2)
                .await
                .unwrap()
                .unwrap()
                .tenant_org_ids
                .contains(&org_id),
            "deactivated membership grants no access"
        );
        // SCIM still reports the user, now inactive.
        assert_eq!(
            cat.scim_member(org_id, uid).await.unwrap(),
            Some((email, false))
        );
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
        assert!(
            cat.add_user_to_tenant(&email, &slug, "member")
                .await
                .unwrap()
        );
        let token = cat.create_session(uid, 1).await.unwrap();
        let au = cat.resolve_session(&token).await.unwrap().unwrap();
        let org_id = au.tenant_org_ids[0];
        assert!(au.tenant_org_ids.contains(&org_id));
        assert!(!au.admin_org_ids.contains(&org_id), "member is not admin");

        // Upsert to admin → now in admin set.
        assert!(
            cat.add_user_to_tenant(&email, &slug, "admin")
                .await
                .unwrap()
        );
        let au = cat.resolve_session(&token).await.unwrap().unwrap();
        assert!(au.admin_org_ids.contains(&org_id), "now admin");
    }

    #[tokio::test]
    async fn password_reset_round_trip() {
        let Some((cat, _)) = repo().await else {
            return;
        };
        let email = format!("pr{}@x.io", std::process::id());
        let uid = cat
            .create_user(&email, "old-password", false)
            .await
            .unwrap();
        // A live session that the reset must invalidate.
        let old_session = cat.create_session(uid, 7).await.unwrap();
        assert!(cat.resolve_session(&old_session).await.unwrap().is_some());

        // Unknown email → None (no enumeration), and a request never errors.
        assert!(
            cat.create_password_reset("nobody@x.io", 60)
                .await
                .unwrap()
                .is_none()
        );

        // Real request mints a token bound to the user.
        let pr = cat
            .create_password_reset(&email, 60)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pr.user_id, uid);
        assert!(cat.password_reset_valid(&pr.token).await.unwrap());

        // A second request supersedes the first (one live link).
        let pr2 = cat
            .create_password_reset(&email, 60)
            .await
            .unwrap()
            .unwrap();
        assert!(
            !cat.password_reset_valid(&pr.token).await.unwrap(),
            "superseded"
        );
        assert!(cat.password_reset_valid(&pr2.token).await.unwrap());

        // Consume: sets the new password, returns the user, is single-use.
        assert_eq!(
            cat.reset_password(&pr2.token, "new-password")
                .await
                .unwrap(),
            Some(uid)
        );
        assert!(
            cat.reset_password(&pr2.token, "again")
                .await
                .unwrap()
                .is_none(),
            "single-use"
        );
        assert!(!cat.password_reset_valid(&pr2.token).await.unwrap());

        // New password works, old one doesn't, and the old session was revoked.
        assert_eq!(
            cat.verify_credentials(&email, "new-password")
                .await
                .unwrap(),
            Some(uid)
        );
        assert!(
            cat.verify_credentials(&email, "old-password")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            cat.resolve_session(&old_session).await.unwrap().is_none(),
            "reset revokes existing sessions"
        );

        // An expired token is neither valid nor consumable.
        let expd = cat
            .create_password_reset(&email, -1)
            .await
            .unwrap()
            .unwrap();
        assert!(!cat.password_reset_valid(&expd.token).await.unwrap());
        assert!(
            cat.reset_password(&expd.token, "x")
                .await
                .unwrap()
                .is_none()
        );
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
        assert_eq!(
            got.allowed_domains.as_deref(),
            Some(&["acme.com".to_owned()][..])
        );
        assert!(got.org_slug.is_none(), "instance connection");
        // Routing an unknown domain falls back to the instance default.
        assert_eq!(
            cat.oidc_connection_for_email("x@nowhere.test")
                .await
                .unwrap(),
            Some(got.id)
        );

        // Process-unique state keys so re-runs (and parallel test binaries
        // sharing the DB) never collide on the oidc_flows primary key.
        let ok_state = format!("state-ok-{}", std::process::id());
        let exp_state = format!("state-exp-{}", std::process::id());

        // Flow create → consume (single-use, carries conn_id) → gone.
        cat.create_oidc_flow(
            &ok_state,
            Some(got.id),
            "nonce-1",
            "verifier-1",
            "/repos",
            600,
        )
        .await
        .unwrap();
        let f = cat.consume_oidc_flow(&ok_state).await.unwrap().unwrap();
        assert_eq!(
            f,
            (
                Some(got.id),
                "nonce-1".to_owned(),
                "verifier-1".to_owned(),
                "/repos".to_owned()
            )
        );
        assert!(
            cat.consume_oidc_flow(&ok_state).await.unwrap().is_none(),
            "single-use"
        );

        // Expired flow is not consumable — and consuming it deletes the row, so a
        // second consume still finds nothing (no stale rows accumulate).
        cat.create_oidc_flow(&exp_state, None, "n", "v", "/", -1)
            .await
            .unwrap();
        assert!(cat.consume_oidc_flow(&exp_state).await.unwrap().is_none());
        assert!(
            cat.consume_oidc_flow(&exp_state).await.unwrap().is_none(),
            "expired flow was cleaned up on the first consume"
        );

        // JIT user: idempotent by email, superadmin updatable.
        let id1 = cat
            .find_or_create_sso_user("sso@acme.com", false)
            .await
            .unwrap();
        let id2 = cat
            .find_or_create_sso_user("sso@acme.com", true)
            .await
            .unwrap();
        assert_eq!(id1, id2, "same email = same user");
    }

    #[tokio::test]
    async fn upstream_requires_round_trip() {
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        let id = cat
            .create_upstream(
                repo_id,
                "composer",
                "https://repo.mage-os.org",
                Visibility::Public,
                None,
                None,
                "basic",
            )
            .await
            .unwrap();
        // Default: an empty subscription.
        assert!(
            cat.get_upstream(id)
                .await
                .unwrap()
                .unwrap()
                .requires
                .is_empty()
        );
        // Set an ordered require-list, then read it back (get + list paths).
        let reqs = vec![
            UpstreamRequire {
                match_kind: "prefix".into(),
                pattern: "mage-os/".into(),
                version_floor: Some("2.4".into()),
            },
            UpstreamRequire {
                match_kind: "exact".into(),
                pattern: "psr/log".into(),
                version_floor: None,
            },
        ];
        cat.set_upstream_requires(repo_id, id, &reqs).await.unwrap();
        assert_eq!(cat.get_upstream(id).await.unwrap().unwrap().requires, reqs);
        assert_eq!(cat.list_upstreams(repo_id).await.unwrap()[0].requires, reqs);
        // Replace-all wholesale: a new list supersedes the old.
        cat.set_upstream_requires(repo_id, id, &[]).await.unwrap();
        assert!(
            cat.get_upstream(id)
                .await
                .unwrap()
                .unwrap()
                .requires
                .is_empty()
        );
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
        assert!(
            got.credential.is_none(),
            "public upstream stores no credential"
        );
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
        assert!(
            cat.mark_package_broken(repo_id, name, "source_gone")
                .await
                .unwrap()
        );
        assert!(
            !cat.mark_package_broken(repo_id, "vendor/nope", "x")
                .await
                .unwrap()
        );
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
        cat.mark_package_broken(repo_id, name, "source_gone")
            .await
            .unwrap();
        assert!(cat.archive_package(repo_id, name).await.unwrap());
        assert!(
            !cat.mark_package_broken(repo_id, name, "source_gone")
                .await
                .unwrap(),
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
            .create_upstream(
                repo_id,
                "git",
                "https://git/x.git",
                Visibility::Private,
                None,
                None,
                "basic",
            )
            .await
            .unwrap();

        // First enqueue creates a job; a second is deduped while one is pending.
        assert!(cat.enqueue_mirror_job(up).await.unwrap(), "first enqueue");
        assert!(
            !cat.enqueue_mirror_job(up).await.unwrap(),
            "deduped while a pending job exists"
        );

        // Claim it: status running, attempt 1. No second job is claimable.
        let job = cat
            .claim_mirror_job()
            .await
            .unwrap()
            .expect("a job to claim");
        assert_eq!(job.upstream_id, Some(up));
        assert_eq!(job.kind, "mirror_upstream");
        assert_eq!(job.attempts, 1);
        assert!(
            cat.claim_mirror_job().await.unwrap().is_none(),
            "nothing else claimable"
        );

        // Complete it; a fresh enqueue is now allowed (prior job is 'ready').
        cat.complete_mirror_job(job.id).await.unwrap();
        assert!(
            cat.enqueue_mirror_job(up).await.unwrap(),
            "re-enqueue after ready"
        );

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
            cat.visible_versions(repo_id, "acme/lib", "auto", 0, None, None)
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
        assert_eq!(
            cat.all_package_names(repo_id).await.unwrap(),
            ["sym/console"]
        );
        assert_eq!(
            cat.visible_versions(repo_id, "sym/console", "auto", 0, None, None)
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
            cat.visible_versions(client, "vendor/pub", "auto", 0, None, None)
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
            cat.visible_versions(client, "vendor/pub", "auto", 0, None, None)
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

    #[tokio::test]
    async fn license_policy_round_trips() {
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        let (_key, lic) = cat
            .create_license_key(repo_id, Some("buyer"))
            .await
            .unwrap();
        // Default: no override.
        assert!(!cat.license_policy(lic).await.unwrap().is_some());

        // Set delayed/30; it reads back via both license_policy and list_licenses,
        // and tightens an `auto` repo default.
        assert!(
            cat.set_license_policy(
                repo_id,
                lic,
                &PolicyOverride {
                    update_mode: Some("delayed".into()),
                    cooldown_days: Some(30)
                },
            )
            .await
            .unwrap()
        );
        let pol = cat.license_policy(lic).await.unwrap();
        assert_eq!(pol.effective("auto", 0), ("delayed".to_owned(), 30));
        let listed = &cat.list_licenses(repo_id).await.unwrap()[0];
        assert_eq!(listed.policy.cooldown_days, Some(30));

        // Clear it (inherit again).
        cat.set_license_policy(repo_id, lic, &PolicyOverride::default())
            .await
            .unwrap();
        assert!(!cat.license_policy(lic).await.unwrap().is_some());

        // Scoped: another repo can't touch this license.
        let (_, other) = repo().await.unwrap();
        assert!(
            !cat.set_license_policy(other, lic, &PolicyOverride::default())
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn rename_redirects_retires_and_chains() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let cat = Catalog::connect(&url).await.unwrap();
        cat.migrate().await.unwrap();
        let o = format!("ren{}", std::process::id());
        let org_id = cat.create_org(&o, None).await.unwrap();
        let repo_id = cat.create_repo(&o, "web").await.unwrap();

        // Canonical resolves, not moved.
        let loc = cat
            .resolve_repo_canonical(&o, "web")
            .await
            .unwrap()
            .unwrap();
        assert!(!loc.moved && loc.repo_id == repo_id);

        // Rename the repo: the old slug now redirects to the canonical one.
        cat.rename_repo(repo_id, "site").await.unwrap();
        let loc = cat
            .resolve_repo_canonical(&o, "web")
            .await
            .unwrap()
            .unwrap();
        assert!(loc.moved && loc.repo_slug == "site" && loc.repo_id == repo_id);
        assert!(
            !cat.resolve_repo_canonical(&o, "site")
                .await
                .unwrap()
                .unwrap()
                .moved
        );

        // The retired slug can't be re-used (renamed back, or recreated).
        assert!(matches!(
            cat.rename_repo(repo_id, "web").await,
            Err(RenameError::Retired)
        ));
        assert!(cat.repo_slug_unavailable(org_id, "web").await.unwrap());

        // Rename the org too: the old org+repo slug pair redirects (chained) to
        // the new canonical pair.
        cat.rename_org(org_id, &format!("{o}-new")).await.unwrap();
        let loc = cat
            .resolve_repo_canonical(&o, "web")
            .await
            .unwrap()
            .unwrap();
        assert!(loc.moved);
        assert_eq!(loc.org_slug, format!("{o}-new"));
        assert_eq!(loc.repo_slug, "site");

        // A live slug can't be taken by another rename.
        cat.create_repo(&format!("{o}-new"), "site2").await.unwrap();
        assert!(matches!(
            cat.rename_repo(repo_id, "site2").await,
            Err(RenameError::Taken)
        ));

        // Unknown slug → no location.
        assert!(
            cat.resolve_repo_canonical("nope-org", "nope")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn package_sets_resolve_explicit_and_glob() {
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        let org_id: Uuid = sqlx::query_scalar("select org_id from repositories where id = $1")
            .bind(repo_id)
            .fetch_one(&cat.pool)
            .await
            .unwrap();
        for n in ["acme/a", "acme/b", "other/c"] {
            cat.upsert_package(repo_id, n, "git", None, Visibility::Public)
                .await
                .unwrap();
        }
        let set = cat.create_package_set(org_id, "Pro").await.unwrap();

        // explicit member + glob rule.
        let cid = cat
            .find_package_in_org(org_id, "other/c")
            .await
            .unwrap()
            .unwrap();
        cat.add_set_member(set, cid).await.unwrap();
        cat.add_set_rule(set, "acme/*").await.unwrap();
        assert_eq!(
            cat.resolve_set(set).await.unwrap(),
            vec!["acme/a", "acme/b", "other/c"]
        );

        // Auto-grow: a new acme/* package joins the set without re-config.
        cat.upsert_package(repo_id, "acme/d", "git", None, Visibility::Public)
            .await
            .unwrap();
        assert!(
            cat.resolve_set(set)
                .await
                .unwrap()
                .contains(&"acme/d".to_owned())
        );

        // Listing, members, rules, delete.
        assert_eq!(cat.list_package_sets(org_id).await.unwrap().len(), 1);
        assert_eq!(cat.set_members(set).await.unwrap().len(), 1);
        assert_eq!(cat.set_rules(set).await.unwrap().len(), 1);
        assert!(cat.delete_package_set(org_id, set).await.unwrap());
        assert!(cat.list_package_sets(org_id).await.unwrap().is_empty());
    }

    /// A license entitled to a package **set** unlocks every package the set
    /// resolves to (explicit + glob), auto-growing, alongside any per-package
    /// entitlements. Listing surfaces the set; removal revokes it.
    #[tokio::test]
    async fn license_set_entitlements_resolve_and_grow() {
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        let org_id: Uuid = sqlx::query_scalar("select org_id from repositories where id = $1")
            .bind(repo_id)
            .fetch_one(&cat.pool)
            .await
            .unwrap();
        for n in ["acme/a", "acme/b", "solo/x"] {
            cat.upsert_package(repo_id, n, "git", None, Visibility::Private)
                .await
                .unwrap();
        }
        let set = cat.create_package_set(org_id, "Edition").await.unwrap();
        cat.add_set_rule(set, "acme/*").await.unwrap();

        let (_key, lic) = cat
            .create_license_key(repo_id, Some("buyer"))
            .await
            .unwrap();
        // A direct package entitlement plus a set entitlement coexist.
        assert!(cat.entitle_package(lic, repo_id, "solo/x").await.unwrap());
        cat.entitle_set(lic, set).await.unwrap();

        assert_eq!(
            cat.entitled_package_names(lic).await.unwrap(),
            vec!["acme/a", "acme/b", "solo/x"]
        );

        // Auto-grow: a new acme/* package is unlocked without touching the license.
        cat.upsert_package(repo_id, "acme/c", "git", None, Visibility::Private)
            .await
            .unwrap();
        assert!(
            cat.entitled_package_names(lic)
                .await
                .unwrap()
                .contains(&"acme/c".to_owned())
        );

        // Listing surfaces the entitled set.
        let listed = &cat.list_licenses(repo_id).await.unwrap()[0];
        assert_eq!(listed.sets.len(), 1);
        assert_eq!(listed.sets[0].1, "Edition");
        assert_eq!(cat.entitled_sets(lic).await.unwrap()[0].1, "Edition");

        // Revoke the set: only the direct entitlement remains.
        cat.remove_set_entitlement(lic, set).await.unwrap();
        assert_eq!(
            cat.entitled_package_names(lic).await.unwrap(),
            vec!["solo/x"]
        );
    }

    #[tokio::test]
    async fn license_bound_caps_versions() {
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        let pkg = cat
            .upsert_package(repo_id, "acme/lib", "git", None, Visibility::Public)
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
        for (v, n, rel) in [
            ("1.0.0", "1.0.0.0", now - 400 * day),
            ("2.0.0", "2.0.0.0", now - 30 * day),
            ("3.0.0", "3.0.0.0", now),
        ] {
            cat.upsert_package_version(pkg, v, n, "stable", &cj, None, None, None, Some(rel))
                .await
                .unwrap();
        }
        let p = "acme/lib";
        let norm = |vs: Vec<PackageVersion>| -> Vec<String> {
            vs.into_iter().map(|v| v.normalized_version).collect()
        };

        // Unbounded: all three.
        assert_eq!(
            cat.visible_versions(repo_id, p, "auto", 0, None, None)
                .await
                .unwrap()
                .len(),
            3
        );
        // Time bound: a license whose window ended 60 days ago keeps only the
        // version released within it (perpetual fallback).
        assert_eq!(
            norm(
                cat.visible_versions(repo_id, p, "auto", 0, Some(now - 60 * day), None)
                    .await
                    .unwrap()
            ),
            ["1.0.0.0"]
        );
        // Version bound: "this major and below" (<= 2) excludes the 3.x line.
        assert_eq!(
            norm(
                cat.visible_versions(repo_id, p, "auto", 0, None, Some(2))
                    .await
                    .unwrap()
            ),
            ["1.0.0.0", "2.0.0.0"]
        );
    }

    #[tokio::test]
    async fn autogrant_rule_serves_set_packages() {
        let Some((cat, src_repo)) = repo().await else {
            return;
        };
        let (org_id, org_slug): (Uuid, String) =
            sqlx::query_as("select o.id, o.slug from repositories r join organizations o on o.id = r.org_id where r.id = $1")
                .bind(src_repo)
                .fetch_one(&cat.pool)
                .await
                .unwrap();
        let client = cat.create_repo(&org_slug, "client").await.unwrap();

        // A package in the source repo + a version.
        let pkg = cat
            .upsert_package(src_repo, "acme/x", "git", None, Visibility::Public)
            .await
            .unwrap();
        let cj = serde_json::json!({"name": "acme/x"});
        cat.upsert_package_version(
            pkg, "1.0.0", "1.0.0.0", "stable", &cj, None, None, None, None,
        )
        .await
        .unwrap();

        // A set with a glob rule, subscribed by the client repo.
        let set = cat.create_package_set(org_id, "Bundle").await.unwrap();
        cat.add_set_rule(set, "acme/*").await.unwrap();
        assert!(
            !cat.all_package_names(client)
                .await
                .unwrap()
                .contains(&"acme/x".to_owned())
        );
        cat.add_grant_rule(client, set).await.unwrap();

        // The client now serves the set's package (and its versions), virtually.
        assert!(
            cat.all_package_names(client)
                .await
                .unwrap()
                .contains(&"acme/x".to_owned())
        );
        assert_eq!(
            cat.visible_versions(client, "acme/x", "auto", 0, None, None)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(cat.list_grant_rules(client).await.unwrap().len(), 1);

        // Auto-grow: a new acme/* package flows in without re-config.
        cat.upsert_package(src_repo, "acme/y", "git", None, Visibility::Public)
            .await
            .unwrap();
        assert!(
            cat.all_package_names(client)
                .await
                .unwrap()
                .contains(&"acme/y".to_owned())
        );

        // Un-subscribe removes the inherited access.
        let rid = cat.list_grant_rules(client).await.unwrap()[0].0;
        cat.remove_grant_rule(client, rid).await.unwrap();
        assert!(
            !cat.all_package_names(client)
                .await
                .unwrap()
                .contains(&"acme/x".to_owned())
        );
    }

    /// The Approvals tab's bulk action: `approve_all_pending` exposes every
    /// still-undecided version (optionally one package) and never touches held
    /// ones. Also exercises the `pending` / `held` state filters the tab reads.
    #[tokio::test]
    async fn bulk_approve_pending_skips_held() {
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        cat.set_update_policy(repo_id, "manual", 0).await.unwrap();
        let cj = serde_json::json!({"name": "x"});
        // Two packages, two unapproved versions each; hold one of them.
        for name in ["acme/a", "acme/b"] {
            let pkg = cat
                .upsert_package(repo_id, name, "git", None, Visibility::Private)
                .await
                .unwrap();
            for v in ["1.0.0", "1.1.0"] {
                cat.upsert_package_version(
                    pkg,
                    v,
                    &format!("{v}.0"),
                    "stable",
                    &cj,
                    None,
                    None,
                    None,
                    None,
                )
                .await
                .unwrap();
            }
        }
        cat.hold_version(repo_id, "acme/b", "1.1.0.0")
            .await
            .unwrap();

        // 4 versions, 1 held → 3 pending, 1 held (the tab's bucket counts).
        assert_eq!(
            cat.count_package_versions(repo_id, None, Some("pending"))
                .await
                .unwrap(),
            3
        );
        assert_eq!(
            cat.count_package_versions(repo_id, None, Some("held"))
                .await
                .unwrap(),
            1
        );

        // Per-package "Approve all" only clears that package's pending versions.
        assert_eq!(
            cat.approve_all_pending(repo_id, Some("acme/a"))
                .await
                .unwrap(),
            2
        );
        assert_eq!(
            cat.count_package_versions(repo_id, None, Some("pending"))
                .await
                .unwrap(),
            1
        );

        // Repo-wide "Approve all pending" clears the remaining one and leaves the
        // held version held (approve_all_pending skips held_at-set rows).
        assert_eq!(cat.approve_all_pending(repo_id, None).await.unwrap(), 1);
        assert_eq!(
            cat.count_package_versions(repo_id, None, Some("pending"))
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            cat.count_package_versions(repo_id, None, Some("held"))
                .await
                .unwrap(),
            1
        );
    }

    /// Read a blob's refcount directly (test-only introspection).
    async fn refcount(cat: &Catalog, sha: &[u8; 32]) -> Option<i64> {
        sqlx::query_scalar("select refcount::bigint from blobs where sha256 = $1")
            .bind(&sha[..])
            .fetch_optional(&cat.pool)
            .await
            .unwrap()
    }

    /// `storage_stats` aggregates the **global** blob table, so its before/after
    /// deltas race any parallel test that inserts or deletes blobs. Serialize the
    /// blob-touching tests behind one lock. (`#[tokio::test]` is current-thread,
    /// so holding this std guard across awaits is fine.)
    fn serial_blobs() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    async fn org_of_repo(cat: &Catalog, repo_id: Uuid) -> Uuid {
        sqlx::query_scalar("select org_id from repositories where id = $1")
            .bind(repo_id)
            .fetch_one(&cat.pool)
            .await
            .unwrap()
    }

    /// Unwrap a [`SingletonSet::Set`] in tests (panics on collision/unknown).
    fn set_id(s: SingletonSet) -> Uuid {
        match s {
            SingletonSet::Set(id) => id,
            other => panic!("expected a singleton set, got {other:?}"),
        }
    }

    /// A blob sha unique to this test run (the `blobs` table is global — shared
    /// across every test and prior run — so fixed shas would collide). Seeds
    /// from the per-run `repo_id`, which is unique per `repo()` call.
    fn test_sha(repo_id: Uuid, tag: u8) -> [u8; 32] {
        let mut sha = [tag; 32];
        sha[..16].copy_from_slice(repo_id.as_bytes());
        sha
    }

    async fn add_version_with_blob(
        cat: &Catalog,
        pkg: Uuid,
        version: &str,
        normalized: &str,
        sha: &[u8; 32],
    ) {
        cat.upsert_blob(sha, 100).await.unwrap();
        cat.upsert_package_version(
            pkg,
            version,
            normalized,
            "stable",
            &serde_json::json!({ "name": "acme/lib" }),
            Some(sha),
            None,
            None,
            None,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    // Holds `serial_blobs()` across awaits by design (current-thread test rt).
    #[allow(clippy::await_holding_lock)]
    async fn triggers_maintain_blob_refcount() {
        let _serial = serial_blobs();
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        let pkg = cat
            .upsert_package(repo_id, "acme/lib", "git", None, Visibility::Private)
            .await
            .unwrap();
        let sha = test_sha(repo_id, 7);

        // Insert two versions sharing one blob → refcount 2 (global dedup).
        add_version_with_blob(&cat, pkg, "v1.0.0", "1.0.0.0", &sha).await;
        assert_eq!(refcount(&cat, &sha).await, Some(1));
        add_version_with_blob(&cat, pkg, "v1.0.1", "1.0.1.0", &sha).await;
        assert_eq!(
            refcount(&cat, &sha).await,
            Some(2),
            "shared blob counts both"
        );

        // Re-point one version at different bytes → old -1, new +1.
        let sha2 = test_sha(repo_id, 9);
        add_version_with_blob(&cat, pkg, "v1.0.1", "1.0.1.0", &sha2).await;
        assert_eq!(refcount(&cat, &sha).await, Some(1), "old blob decremented");
        assert_eq!(refcount(&cat, &sha2).await, Some(1), "new blob incremented");

        // Deleting the repo cascades to versions → both blobs drop to 0.
        assert!(cat.delete_repo(repo_id).await.unwrap());
        assert_eq!(refcount(&cat, &sha).await, Some(0));
        assert_eq!(refcount(&cat, &sha2).await, Some(0));
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn snapshot_latest_advances_and_lists() {
        let _serial = serial_blobs();
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        let sha1 = test_sha(repo_id, 21);
        let sha2 = test_sha(repo_id, 22);

        // Nothing uploaded yet.
        assert!(
            cat.resolve_latest(repo_id, "production")
                .await
                .unwrap()
                .is_none()
        );

        cat.upsert_blob(&sha1, 1000).await.unwrap();
        let s1 = cat
            .create_snapshot(repo_id, "production", &sha1, 1000, Some("commit-a"))
            .await
            .unwrap();
        cat.advance_latest(repo_id, "production", s1).await.unwrap();
        let latest = cat
            .resolve_latest(repo_id, "production")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(latest.blob_sha256, sha1);
        assert_eq!(latest.size_bytes, 1000);
        assert_eq!(latest.source_ref.as_deref(), Some("commit-a"));

        // A second upload moves the pointer.
        cat.upsert_blob(&sha2, 2000).await.unwrap();
        let s2 = cat
            .create_snapshot(repo_id, "production", &sha2, 2000, None)
            .await
            .unwrap();
        cat.advance_latest(repo_id, "production", s2).await.unwrap();
        assert_eq!(
            cat.resolve_latest(repo_id, "production")
                .await
                .unwrap()
                .unwrap()
                .blob_sha256,
            sha2,
            "latest moved to the newest upload"
        );

        // Environments are independent.
        assert!(
            cat.resolve_latest(repo_id, "staging")
                .await
                .unwrap()
                .is_none()
        );

        let all = cat.list_snapshots(repo_id, "production").await.unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].blob_sha256, sha2, "newest first");

        // Each snapshot refcounts its blob (via the 0045 trigger).
        assert_eq!(refcount(&cat, &sha1).await, Some(1));
        assert_eq!(refcount(&cat, &sha2).await, Some(1));
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn snapshot_resolve_by_digest_is_repo_and_env_scoped() {
        let _serial = serial_blobs();
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        let sha = test_sha(repo_id, 41);
        cat.upsert_blob(&sha, 500).await.unwrap();
        cat.create_snapshot(repo_id, "production", &sha, 500, None)
            .await
            .unwrap();

        // Pinned resolve of the exact digest in its repo+env.
        let got = cat
            .resolve_snapshot_by_digest(repo_id, "production", &sha)
            .await
            .unwrap()
            .expect("digest resolves in its repo+env");
        assert_eq!(got.blob_sha256, sha);
        assert_eq!(got.size_bytes, 500);

        // Same digest, wrong environment → not found (env-scoped).
        assert!(
            cat.resolve_snapshot_by_digest(repo_id, "staging", &sha)
                .await
                .unwrap()
                .is_none()
        );
        // A digest that is a real CAS blob but not a snapshot here → not found
        // (a read token can't fish arbitrary blobs by sha).
        let other = test_sha(repo_id, 42);
        cat.upsert_blob(&other, 500).await.unwrap();
        assert!(
            cat.resolve_snapshot_by_digest(repo_id, "production", &other)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn snapshot_prune_keeps_latest_and_reclaims_refcount() {
        let _serial = serial_blobs();
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        let mut shas = Vec::new();
        for i in 0..3u8 {
            let sha = test_sha(repo_id, 30 + i);
            cat.upsert_blob(&sha, 100).await.unwrap();
            let id = cat
                .create_snapshot(repo_id, "production", &sha, 100, None)
                .await
                .unwrap();
            cat.advance_latest(repo_id, "production", id).await.unwrap();
            shas.push(sha);
        }
        for sha in &shas {
            assert_eq!(refcount(&cat, sha).await, Some(1));
        }

        // Keep only the newest → the two oldest are pruned.
        let deleted = cat.prune_snapshots(repo_id, "production", 1).await.unwrap();
        assert_eq!(deleted, 2);
        assert_eq!(
            cat.list_snapshots(repo_id, "production")
                .await
                .unwrap()
                .len(),
            1
        );

        // The latest survives (pointer still resolves) and keeps its blob…
        assert_eq!(
            cat.resolve_latest(repo_id, "production")
                .await
                .unwrap()
                .unwrap()
                .blob_sha256,
            shas[2]
        );
        assert_eq!(refcount(&cat, &shas[2]).await, Some(1));
        // …while the pruned snapshots' blobs drop to 0 (now orphan-GC eligible).
        assert_eq!(refcount(&cat, &shas[0]).await, Some(0));
        assert_eq!(refcount(&cat, &shas[1]).await, Some(0));
    }

    #[tokio::test]
    // Holds `serial_blobs()` across awaits by design (current-thread test rt).
    #[allow(clippy::await_holding_lock)]
    async fn gc_collects_only_orphans_past_grace() {
        let _serial = serial_blobs();
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        let pkg = cat
            .upsert_package(repo_id, "acme/lib", "git", None, Visibility::Private)
            .await
            .unwrap();
        let referenced = test_sha(repo_id, 1);
        let orphan = test_sha(repo_id, 2);
        add_version_with_blob(&cat, pkg, "v1.0.0", "1.0.0.0", &referenced).await;
        // An orphan blob (present, never referenced).
        cat.upsert_blob(&orphan, 100).await.unwrap();

        // With a long grace, our just-written orphan is protected (last_seen is
        // fresh). The eligible set is global (other tests' aged orphans may
        // appear), so assert on membership, not size.
        let fresh = cat.orphan_blobs(Duration::from_hours(1)).await.unwrap();
        assert!(
            !fresh.iter().any(|b| b.sha256 == orphan),
            "fresh orphan is inside the grace window"
        );

        // With zero grace our orphan becomes eligible; the referenced blob never
        // is (refcount 1).
        let zero = Duration::ZERO;
        let eligible = cat.orphan_blobs(zero).await.unwrap();
        assert!(eligible.iter().any(|b| b.sha256 == orphan));
        assert!(
            !eligible.iter().any(|b| b.sha256 == referenced),
            "a referenced blob is never eligible"
        );

        // The guarded delete removes the orphan but refuses the referenced blob.
        assert!(cat.delete_blob_if_orphan(&orphan, zero).await.unwrap());
        assert!(
            !cat.delete_blob_if_orphan(&referenced, zero).await.unwrap(),
            "a referenced blob is never collected"
        );
        assert_eq!(refcount(&cat, &orphan).await, None, "orphan row gone");
        assert_eq!(
            refcount(&cat, &referenced).await,
            Some(1),
            "referenced kept"
        );
    }

    #[tokio::test]
    async fn entitlements_default_unlimited_and_gate_after_disable() {
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        let org_id = org_of_repo(&cat, repo_id).await;

        // No row → unlimited default; every feature allowed.
        assert!(!cat.has_entitlements(org_id).await.unwrap());
        let e = cat.entitlements(org_id).await.unwrap();
        assert!(e.allows(Feature::Agency) && e.allows(Feature::Scim) && e.allows(Feature::Sso));
        assert_eq!(e.max_skus, None);

        // A gated mutation succeeds while unlimited.
        let set_id = cat.create_package_set(org_id, "bundle").await.unwrap();
        let slug = sqlx::query_scalar::<_, String>("select slug from organizations where id = $1")
            .bind(org_id)
            .fetch_one(&cat.pool)
            .await
            .unwrap();
        cat.add_grant_rule(repo_id, set_id).await.unwrap();
        assert!(cat.create_scim_token(&slug).await.unwrap().is_some());

        // Constrain the org: agency + scim off (sso left on).
        let mut ent = Entitlements::unlimited();
        ent.agency = false;
        ent.scim = false;
        ent.max_skus = Some(15);
        cat.set_org_entitlements(org_id, &ent).await.unwrap();
        assert!(cat.has_entitlements(org_id).await.unwrap());

        // Both gates now deny with the specific feature; sso would still pass.
        assert!(
            matches!(
                cat.add_grant_rule(repo_id, set_id).await,
                Err(EntitlementError::Denied(Feature::Agency))
            ),
            "autogrant gated once agency is off"
        );
        assert!(matches!(
            cat.create_scim_token(&slug).await,
            Err(EntitlementError::Denied(Feature::Scim))
        ));

        // Clearing restores unlimited and the gate reopens.
        assert!(cat.clear_org_entitlements(org_id).await.unwrap());
        assert!(!cat.has_entitlements(org_id).await.unwrap());
        cat.add_grant_rule(repo_id, set_id).await.unwrap();
    }

    #[tokio::test]
    async fn edition_issue_resolves_bound_and_entitlements() {
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        let org_id = org_of_repo(&cat, repo_id).await;
        for n in ["acme/a", "acme/b"] {
            cat.upsert_package(repo_id, n, "git", None, Visibility::Private)
                .await
                .unwrap();
        }
        let set = cat.create_package_set(org_id, "Pro").await.unwrap();
        cat.add_set_rule(set, "acme/*").await.unwrap();

        // A by-reference, time-bounded edition (12 months of updates).
        let ed = cat
            .create_edition(
                repo_id,
                "Pro Annual",
                Some("pro-annual"),
                set,
                &EditionBound::Time { period_months: 12 },
                false,
                &PolicyOverride::default(),
            )
            .await
            .unwrap()
            .expect("set belongs to org");

        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
        let key = cat
            .issue_from_edition(repo_id, ed, Some("buyer@x"), None)
            .await
            .unwrap()
            .expect("issued")
            .key
            .expect("newly created → plaintext key");
        let lic = cat.resolve_license(repo_id, &key).await.unwrap().unwrap();

        // Entitled by reference to the set's packages, and auto-grows.
        assert_eq!(
            cat.entitled_package_names(lic).await.unwrap(),
            vec!["acme/a", "acme/b"]
        );
        cat.upsert_package(repo_id, "acme/c", "git", None, Visibility::Private)
            .await
            .unwrap();
        assert!(
            cat.entitled_package_names(lic)
                .await
                .unwrap()
                .contains(&"acme/c".to_owned()),
            "by-reference edition auto-grows with the set"
        );

        // The time template resolved to an absolute ~12-month bound on the key.
        let bound = cat.license_bound(lic).await.unwrap();
        let until = bound.until_unix.expect("time bound resolved");
        assert!(bound.major.is_none());
        assert!(
            (now + 360 * 86_400..now + 372 * 86_400).contains(&until),
            "until {until} should be ~now + 12 months"
        );

        // The key remembers the edition it was minted from.
        let ed_link: Option<Uuid> =
            sqlx::query_scalar("select edition_id from license_keys where id = $1")
                .bind(lic)
                .fetch_one(&cat.pool)
                .await
                .unwrap();
        assert_eq!(ed_link, Some(ed));
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn editions_accumulate_onto_perpetual_key_and_detach_on_refund() {
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        let org_id = org_of_repo(&cat, repo_id).await;
        for n in ["acme/a", "acme/b", "acme/c"] {
            cat.upsert_package(repo_id, n, "git", None, Visibility::Private)
                .await
                .unwrap();
        }
        // One by-reference set + edition per package: A and B perpetual, C annual.
        let mk_ed = async |name: &str, bound: EditionBound| {
            let set = cat.create_package_set(org_id, name).await.unwrap();
            cat.add_set_rule(set, &format!("acme/{}", name.to_lowercase()))
                .await
                .unwrap();
            cat.create_edition(
                repo_id,
                name,
                Some(&name.to_lowercase()),
                set,
                &bound,
                false,
                &PolicyOverride::default(),
            )
            .await
            .unwrap()
            .unwrap()
        };
        let ed_a = mk_ed("A", EditionBound::Perpetual).await;
        let ed_b = mk_ed("B", EditionBound::Perpetual).await;
        let ed_c = mk_ed("C", EditionBound::Time { period_months: 12 }).await;

        // First purchase mints the customer's account key: perpetual, A only.
        let key = cat
            .issue_from_edition(repo_id, ed_a, Some("buyer@x"), None)
            .await
            .unwrap()
            .unwrap()
            .key
            .unwrap();
        let lic = cat.resolve_license(repo_id, &key).await.unwrap().unwrap();
        assert_eq!(
            cat.entitled_package_names(lic).await.unwrap(),
            vec!["acme/a"]
        );

        // A second perpetual purchase accumulates onto the same key…
        assert_eq!(
            cat.add_edition_to_license(repo_id, lic, ed_b)
                .await
                .unwrap(),
            EditionAdd::Added
        );
        assert_eq!(
            cat.entitled_package_names(lic).await.unwrap(),
            vec!["acme/a", "acme/b"]
        );
        // …idempotently (a retried webhook is a no-op).
        assert_eq!(
            cat.add_edition_to_license(repo_id, lic, ed_b)
                .await
                .unwrap(),
            EditionAdd::Added
        );
        assert_eq!(
            cat.entitled_package_names(lic).await.unwrap(),
            vec!["acme/a", "acme/b"]
        );

        // A time-bounded edition merges too (0047): its bound lands on the
        // entitlement edge while the key itself stays perpetual, so each package
        // serves under its own ceiling.
        assert_eq!(
            cat.add_edition_to_license(repo_id, lic, ed_c)
                .await
                .unwrap(),
            EditionAdd::Added
        );
        let bounds: std::collections::HashMap<String, LicenseBound> = cat
            .entitled_package_bounds(lic)
            .await
            .unwrap()
            .into_iter()
            .collect();
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
        assert_eq!(bounds["acme/a"].until_unix, None);
        assert_eq!(bounds["acme/b"].until_unix, None);
        let c_until = bounds["acme/c"].until_unix.unwrap();
        assert!(
            (now + 300 * 86_400..now + 400 * 86_400).contains(&c_until),
            "annual edge bound should sit ~12 months out"
        );

        // Renewing that edition extends only its edge (idempotently), leaving the
        // key and the perpetual packages untouched.
        let renewed = cat
            .renew_license_edition(repo_id, lic, ed_c, Some("ren-1"))
            .await
            .unwrap()
            .unwrap();
        let replay = cat
            .renew_license_edition(repo_id, lic, ed_c, Some("ren-1"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(renewed, replay, "idempotent replay must not stack");
        let bounds: std::collections::HashMap<String, LicenseBound> = cat
            .entitled_package_bounds(lic)
            .await
            .unwrap()
            .into_iter()
            .collect();
        let c_renewed = bounds["acme/c"].until_unix.unwrap();
        assert!(
            (now + 660 * 86_400..now + 760 * 86_400).contains(&c_renewed),
            "renewal should extend the edge ~12 more months"
        );
        assert_eq!(bounds["acme/a"].until_unix, None);
        // A perpetual edition has no time edge to renew…
        assert_eq!(
            cat.renew_license_edition(repo_id, lic, ed_b, Some("ren-2"))
                .await
                .unwrap(),
            None
        );
        // …and the account key itself has no key-level time bound to renew.
        assert_eq!(cat.renew_license(repo_id, lic, None).await.unwrap(), None);

        // A perpetual edition still can't merge onto a **bounded** key (a NULL
        // edge would inherit the key's bound and silently expire the purchase) —
        // caller issues/uses an unbounded account key instead.
        let tkey = cat
            .issue_from_edition(repo_id, ed_c, None, None)
            .await
            .unwrap()
            .unwrap()
            .key
            .unwrap();
        let tlic = cat.resolve_license(repo_id, &tkey).await.unwrap().unwrap();
        assert_eq!(
            cat.add_edition_to_license(repo_id, tlic, ed_a)
                .await
                .unwrap(),
            EditionAdd::Standalone
        );
        assert_eq!(
            cat.entitled_package_names(tlic).await.unwrap(),
            vec!["acme/c"]
        );
        // The standalone key's bound still comes from the key itself (NULL edge
        // inherits it — the 0047 back-compat rule).
        let tbounds: std::collections::HashMap<String, LicenseBound> = cat
            .entitled_package_bounds(tlic)
            .await
            .unwrap()
            .into_iter()
            .collect();
        assert!(tbounds["acme/c"].until_unix.is_some());

        // Account-key issuance solves the bounded-first-purchase ordering: the
        // ANNUAL edition issued as an account key mints an unbounded key with the
        // bound on the edge — a valid merge target for later perpetual purchases,
        // unlike the standalone shape above.
        let akey = cat
            .issue_account_key_from_edition(repo_id, ed_c, Some("buyer2@x"), None)
            .await
            .unwrap()
            .unwrap()
            .key
            .unwrap();
        let alic = cat.resolve_license(repo_id, &akey).await.unwrap().unwrap();
        assert_eq!(
            cat.add_edition_to_license(repo_id, alic, ed_a)
                .await
                .unwrap(),
            EditionAdd::Added
        );
        let abounds: std::collections::HashMap<String, LicenseBound> = cat
            .entitled_package_bounds(alic)
            .await
            .unwrap()
            .into_iter()
            .collect();
        assert!(
            abounds["acme/c"].until_unix.is_some(),
            "annual stays bounded"
        );
        assert_eq!(
            abounds["acme/a"].until_unix, None,
            "perpetual add unbounded"
        );

        // Manual consolidation: merging the legacy standalone bounded key (tlic,
        // bound on the KEY, NULL edge) into the account key materializes its
        // effective bound onto the moved edge — acme/c must NOT become perpetual
        // on the unbounded target — and revokes the source. The collision with
        // alic's own (renewable) acme/c edge keeps the more permissive bound.
        assert_eq!(
            cat.merge_license_keys(repo_id, tlic, alic).await.unwrap(),
            LicenseMerge::Merged
        );
        assert!(
            cat.resolve_license(repo_id, &tkey).await.unwrap().is_none(),
            "source key revoked after merge"
        );
        let mbounds: std::collections::HashMap<String, LicenseBound> = cat
            .entitled_package_bounds(alic)
            .await
            .unwrap()
            .into_iter()
            .collect();
        assert!(
            mbounds["acme/c"].until_unix.is_some(),
            "materialized bound must not turn perpetual on the unbounded target"
        );
        assert_eq!(mbounds["acme/a"].until_unix, None);
        // A bounded key is refused as a merge target (a NULL edge would inherit
        // its bound); self-merge and unknowns are distinct non-mutating outcomes.
        let bkey = cat
            .issue_from_edition(repo_id, ed_c, None, None)
            .await
            .unwrap()
            .unwrap()
            .key
            .unwrap();
        let blic = cat.resolve_license(repo_id, &bkey).await.unwrap().unwrap();
        assert_eq!(
            cat.merge_license_keys(repo_id, alic, blic).await.unwrap(),
            LicenseMerge::TargetBounded
        );
        assert_eq!(
            cat.merge_license_keys(repo_id, lic, lic).await.unwrap(),
            LicenseMerge::SameKey
        );
        assert_eq!(
            cat.merge_license_keys(repo_id, Uuid::new_v4(), lic)
                .await
                .unwrap(),
            LicenseMerge::NoSource
        );
        assert_eq!(
            cat.merge_license_keys(repo_id, lic, Uuid::new_v4())
                .await
                .unwrap(),
            LicenseMerge::NoTarget
        );

        // Unknown key / edition are distinct, non-mutating outcomes.
        assert_eq!(
            cat.add_edition_to_license(repo_id, Uuid::new_v4(), ed_b)
                .await
                .unwrap(),
            EditionAdd::NoKey
        );
        assert_eq!(
            cat.add_edition_to_license(repo_id, lic, Uuid::new_v4())
                .await
                .unwrap(),
            EditionAdd::NoEdition
        );

        // Refund of the time-bounded item detaches just that edition — its edge
        // (and bound) go with the row; the other entitlements survive.
        assert!(
            cat.remove_edition_from_license(repo_id, lic, ed_c)
                .await
                .unwrap()
        );
        assert_eq!(
            cat.entitled_package_names(lic).await.unwrap(),
            vec!["acme/a", "acme/b"]
        );
        // Refund of a perpetual item likewise. Idempotent, and reports the key
        // still exists.
        assert!(
            cat.remove_edition_from_license(repo_id, lic, ed_b)
                .await
                .unwrap()
        );
        assert_eq!(
            cat.entitled_package_names(lic).await.unwrap(),
            vec!["acme/a"]
        );
        assert!(
            cat.remove_edition_from_license(repo_id, lic, ed_b)
                .await
                .unwrap()
        );
        // Removing from a key that isn't in the repo reports false (not found).
        assert!(
            !cat.remove_edition_from_license(repo_id, Uuid::new_v4(), ed_b)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn edition_snapshot_freezes_and_version_bound_resolves() {
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        let org_id = org_of_repo(&cat, repo_id).await;
        cat.upsert_package(repo_id, "acme/a", "git", None, Visibility::Private)
            .await
            .unwrap();
        let set = cat.create_package_set(org_id, "Bundle").await.unwrap();
        cat.add_set_rule(set, "acme/*").await.unwrap();

        // A snapshot edition, version-bounded (<= v2).
        let ed = cat
            .create_edition(
                repo_id,
                "Perpetual v2",
                None,
                set,
                &EditionBound::Version { major: 2 },
                true,
                &PolicyOverride::default(),
            )
            .await
            .unwrap()
            .unwrap();
        let key = cat
            .issue_from_edition(repo_id, ed, None, None)
            .await
            .unwrap()
            .unwrap()
            .key
            .unwrap();
        let lic = cat.resolve_license(repo_id, &key).await.unwrap().unwrap();

        // Frozen membership: only what the set resolved to at issue time.
        assert_eq!(
            cat.entitled_package_names(lic).await.unwrap(),
            vec!["acme/a"]
        );
        cat.upsert_package(repo_id, "acme/b", "git", None, Visibility::Private)
            .await
            .unwrap();
        assert_eq!(
            cat.entitled_package_names(lic).await.unwrap(),
            vec!["acme/a"],
            "a new matching package does not reach a snapshot key"
        );

        // The version template resolved to a major cap, with no time bound.
        let bound = cat.license_bound(lic).await.unwrap();
        assert_eq!(bound.major, Some(2));
        assert!(bound.until_unix.is_none());
    }

    #[tokio::test]
    async fn edition_creation_gated_by_max_skus() {
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        let org_id = org_of_repo(&cat, repo_id).await;
        cat.upsert_package(repo_id, "acme/only", "git", None, Visibility::Private)
            .await
            .unwrap();
        // Single-package convenience: a singleton set is created (and reused).
        let set = set_id(cat.singleton_set(org_id, "acme/only").await.unwrap());
        assert_eq!(cat.resolve_set(set).await.unwrap(), vec!["acme/only"]);
        assert_eq!(
            cat.singleton_set(org_id, "acme/only").await.unwrap(),
            SingletonSet::Set(set),
            "singleton set is reused, not duplicated"
        );

        // Cap the org at a single SKU.
        let mut ent = Entitlements::unlimited();
        ent.max_skus = Some(1);
        cat.set_org_entitlements(org_id, &ent).await.unwrap();

        let mk = |name: &'static str| {
            let cat = &cat;
            async move {
                cat.create_edition(
                    repo_id,
                    name,
                    None,
                    set,
                    &EditionBound::Perpetual,
                    false,
                    &PolicyOverride::default(),
                )
                .await
            }
        };

        let first = mk("Solo").await.unwrap().unwrap();
        // The second is refused at the cap.
        assert!(matches!(
            mk("Solo2").await,
            Err(EntitlementError::SkuCapReached(1))
        ));
        // Deactivating the first frees the slot.
        assert!(cat.set_edition_active(repo_id, first, false).await.unwrap());
        assert_eq!(cat.count_active_editions(org_id).await.unwrap(), 0);
        mk("Solo2").await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn issue_is_idempotent_and_renew_extends_bound() {
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        let org_id = org_of_repo(&cat, repo_id).await;
        cat.upsert_package(repo_id, "acme/a", "git", None, Visibility::Private)
            .await
            .unwrap();
        let set = set_id(cat.singleton_set(org_id, "acme/a").await.unwrap());
        let ed = cat
            .create_edition(
                repo_id,
                "Annual",
                None,
                set,
                &EditionBound::Time { period_months: 12 },
                false,
                &PolicyOverride::default(),
            )
            .await
            .unwrap()
            .unwrap();

        // First issue with an idempotency key mints a key.
        let first = cat
            .issue_from_edition(repo_id, ed, Some("buyer"), Some("order-1"))
            .await
            .unwrap()
            .unwrap();
        assert!(first.created && first.key.is_some());

        // A replay with the same key returns the same license, no new secret,
        // and does NOT create a second row.
        let replay = cat
            .issue_from_edition(repo_id, ed, Some("buyer"), Some("order-1"))
            .await
            .unwrap()
            .unwrap();
        assert!(!replay.created && replay.key.is_none());
        assert_eq!(replay.id, first.id);
        let count: i64 = sqlx::query_scalar("select count(*) from license_keys where repo_id = $1")
            .bind(repo_id)
            .fetch_one(&cat.pool)
            .await
            .unwrap();
        assert_eq!(count, 1, "replay must not mint a duplicate");

        // Renew extends the (time) bound further out; the detail reflects it.
        let before = cat
            .license_detail(repo_id, first.id)
            .await
            .unwrap()
            .unwrap();
        let before_until = before.bound.until_unix.unwrap();
        let renewed = cat.renew_license(repo_id, first.id, None).await.unwrap();
        assert!(renewed.is_some(), "a time-bound edition key renews");
        let after = cat
            .license_detail(repo_id, first.id)
            .await
            .unwrap()
            .unwrap();
        assert!(after.bound.until_unix.unwrap() > before_until);
        assert_eq!(after.edition.as_deref(), Some("Annual"));
        assert_eq!(after.packages, vec!["acme/a"]);

        // Revoke flips status; serving's resolve_license then rejects it.
        assert!(cat.revoke_license(repo_id, first.id).await.unwrap());
        assert_eq!(
            cat.license_detail(repo_id, first.id)
                .await
                .unwrap()
                .unwrap()
                .status,
            "revoked"
        );
    }

    #[tokio::test]
    async fn stored_key_is_recoverable_when_secret_configured() {
        use base64::Engine as _;
        let Some((base, repo_id)) = repo().await else {
            return;
        };
        // A catalog sharing the DB but with an at-rest key configured.
        let secret = secret::SecretKey::from_base64(
            &base64::engine::general_purpose::STANDARD.encode([42u8; 32]),
        )
        .unwrap();
        let cat = Catalog::with_secret(base.pool.clone(), Some(secret));
        let org_id = org_of_repo(&cat, repo_id).await;
        cat.upsert_package(repo_id, "acme/a", "git", None, Visibility::Private)
            .await
            .unwrap();
        let set = set_id(cat.singleton_set(org_id, "acme/a").await.unwrap());
        let ed = cat
            .create_edition(
                repo_id,
                "Ann",
                None,
                set,
                &EditionBound::Perpetual,
                false,
                &PolicyOverride::default(),
            )
            .await
            .unwrap()
            .unwrap();

        let first = cat
            .issue_from_edition(repo_id, ed, Some("b"), Some("ord-9"))
            .await
            .unwrap()
            .unwrap();
        let key = first.key.clone().expect("key on first create");
        assert!(key.starts_with("sclk_"));

        // Stored encrypted at rest, not as plaintext.
        let ct: Option<Vec<u8>> =
            sqlx::query_scalar("select key_ciphertext from license_keys where id = $1")
                .bind(first.id)
                .fetch_one(&cat.pool)
                .await
                .unwrap();
        let ct = ct.expect("ciphertext stored");
        assert_ne!(
            ct.as_slice(),
            key.as_bytes(),
            "key is not plaintext at rest"
        );

        // Recover it directly, on idempotent replay, and via inspect.
        assert_eq!(
            cat.license_key_plaintext(repo_id, first.id)
                .await
                .unwrap()
                .as_deref(),
            Some(key.as_str())
        );
        let replay = cat
            .issue_from_edition(repo_id, ed, Some("b"), Some("ord-9"))
            .await
            .unwrap()
            .unwrap();
        assert!(!replay.created && replay.id == first.id);
        assert_eq!(
            replay.key.as_deref(),
            Some(key.as_str()),
            "replay returns the key"
        );
        assert_eq!(
            cat.license_detail(repo_id, first.id)
                .await
                .unwrap()
                .unwrap()
                .key
                .as_deref(),
            Some(key.as_str())
        );

        // Without the secret key, the same row is not recoverable.
        let nosecret = Catalog::with_secret(base.pool.clone(), None);
        assert!(
            nosecret
                .license_key_plaintext(repo_id, first.id)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Regression coverage for the code-review fixes: edition-scoped idempotency,
    /// idempotent + status-guarded renewal, and singleton-set name-collision safety.
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn edition_issue_and_renew_edge_cases() {
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        let org_id = org_of_repo(&cat, repo_id).await;
        for p in ["acme/a", "acme/b"] {
            cat.upsert_package(repo_id, p, "git", None, Visibility::Private)
                .await
                .unwrap();
        }
        let mk_ed = |name: &'static str, slug: Option<&'static str>, pkg: &'static str| {
            let cat = &cat;
            async move {
                let set = set_id(cat.singleton_set(org_id, pkg).await.unwrap());
                cat.create_edition(
                    repo_id,
                    name,
                    slug,
                    set,
                    &EditionBound::Time { period_months: 12 },
                    false,
                    &PolicyOverride::default(),
                )
                .await
                .unwrap()
                .unwrap()
            }
        };
        let ed_a = mk_ed("Pro", Some("pro"), "acme/a").await;
        let ed_b = mk_ed("Team", Some("team"), "acme/b").await;

        // (#5) One order id across two editions provisions two distinct licenses —
        // idempotency is scoped to (repo, edition, key), not (repo, key).
        let a = cat
            .issue_from_edition(repo_id, ed_a, None, Some("order-7"))
            .await
            .unwrap()
            .unwrap();
        let b = cat
            .issue_from_edition(repo_id, ed_b, None, Some("order-7"))
            .await
            .unwrap()
            .unwrap();
        assert!(
            a.created && b.created && a.id != b.id,
            "one key per edition"
        );
        // ...but a retry of the same (edition, order) is still a no-op replay.
        let a_replay = cat
            .issue_from_edition(repo_id, ed_a, None, Some("order-7"))
            .await
            .unwrap()
            .unwrap();
        assert!(!a_replay.created && a_replay.id == a.id);

        // (#3) Renewal is idempotent per key: the same idempotency key doesn't
        // double-extend, a fresh one does.
        let before = cat
            .license_detail(repo_id, a.id)
            .await
            .unwrap()
            .unwrap()
            .bound
            .until_unix
            .unwrap();
        cat.renew_license(repo_id, a.id, Some("renew-1"))
            .await
            .unwrap()
            .expect("renews");
        let after_first = cat
            .license_detail(repo_id, a.id)
            .await
            .unwrap()
            .unwrap()
            .bound
            .until_unix
            .unwrap();
        assert!(after_first > before, "first renewal extends");
        cat.renew_license(repo_id, a.id, Some("renew-1"))
            .await
            .unwrap();
        let after_replay = cat
            .license_detail(repo_id, a.id)
            .await
            .unwrap()
            .unwrap()
            .bound
            .until_unix
            .unwrap();
        assert_eq!(after_replay, after_first, "renewal replay must not stack");

        // (#6) A revoked key cannot be renewed.
        assert!(cat.revoke_license(repo_id, b.id).await.unwrap());
        assert!(
            cat.renew_license(repo_id, b.id, Some("renew-x"))
                .await
                .unwrap()
                .is_none(),
            "revoked key does not renew"
        );

        // (#7) A curated multi-package set named exactly like a package is not
        // silently reused as that package's singleton.
        let curated = cat
            .create_package_set(org_id, "acme/collide")
            .await
            .unwrap();
        let a_id = cat
            .find_package_in_org(org_id, "acme/a")
            .await
            .unwrap()
            .unwrap();
        let b_id = cat
            .find_package_in_org(org_id, "acme/b")
            .await
            .unwrap()
            .unwrap();
        cat.add_set_member(curated, a_id).await.unwrap();
        cat.add_set_member(curated, b_id).await.unwrap();
        cat.upsert_package(repo_id, "acme/collide", "git", None, Visibility::Private)
            .await
            .unwrap();
        assert_eq!(
            cat.singleton_set(org_id, "acme/collide").await.unwrap(),
            SingletonSet::NameCollision,
            "collision with a curated set is refused, not silently reused"
        );

        // (#1) find_edition prefers a real slug match over a name match.
        assert_eq!(cat.find_edition(repo_id, "pro").await.unwrap(), Some(ed_a));
    }

    #[tokio::test]
    async fn service_token_resolves_to_its_repo() {
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        let (token, id) = cat
            .create_service_token(repo_id, Some("magento"), None)
            .await
            .unwrap();
        assert_eq!(
            cat.resolve_service_token(&token).await.unwrap(),
            Some(repo_id)
        );
        assert_eq!(cat.list_service_tokens(repo_id).await.unwrap().len(), 1);
        // An expired token doesn't resolve.
        let (expired, _) = cat
            .create_service_token(repo_id, None, Some(-1))
            .await
            .unwrap();
        assert_eq!(cat.resolve_service_token(&expired).await.unwrap(), None);
        // Revoked → no longer resolves.
        assert!(cat.revoke_service_token(repo_id, id).await.unwrap());
        assert_eq!(cat.resolve_service_token(&token).await.unwrap(), None);
    }

    /// The privilege boundary between the two credential types: a read token (which
    /// only unlocks serving) must never authenticate the management API, and a
    /// service token (which can provision/revoke licenses) must never unlock
    /// serving. This holds by construction — they live in separate tables — but is
    /// guarded here so a future refactor (e.g. merging the tables) can't silently
    /// erase it. See the service-token section in the impl for why they're split.
    #[tokio::test]
    async fn read_and_service_tokens_do_not_cross_authenticate() {
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        // A read token unlocks serving...
        let read = cat.create_token(repo_id, Some("ci"), None).await.unwrap();
        assert!(
            cat.token_valid(repo_id, &read).await.unwrap(),
            "read token unlocks serving"
        );
        // ...but is NOT accepted by the management-API resolve path.
        assert_eq!(
            cat.resolve_service_token(&read).await.unwrap(),
            None,
            "a read token must not authenticate the management API"
        );

        // A service token authenticates the management API...
        let (svc, _) = cat
            .create_service_token(repo_id, Some("magento"), None)
            .await
            .unwrap();
        assert_eq!(
            cat.resolve_service_token(&svc).await.unwrap(),
            Some(repo_id),
            "service token authenticates the management API"
        );
        // ...but must NOT unlock serving.
        assert!(
            !cat.token_valid(repo_id, &svc).await.unwrap(),
            "a service token must not unlock serving"
        );
        // ...nor carry a serving policy on the read path.
        assert!(
            cat.resolve_token_policy(repo_id, &svc)
                .await
                .unwrap()
                .is_none(),
            "a service token is not a serving credential"
        );

        // A publish token authorizes uploads on its own path...
        let pub_tok = cat.create_publish_token(repo_id, "ci", 900).await.unwrap();
        assert_eq!(
            cat.resolve_publish_token(&pub_tok).await.unwrap(),
            Some(repo_id),
            "publish token authorizes uploads"
        );
        // ...but must NOT unlock serving or the management API.
        assert!(
            !cat.token_valid(repo_id, &pub_tok).await.unwrap(),
            "a publish token must not unlock serving"
        );
        assert_eq!(
            cat.resolve_service_token(&pub_tok).await.unwrap(),
            None,
            "a publish token must not authenticate the management API"
        );
        // ...and neither a read nor a service token can resolve as a publish token.
        assert_eq!(
            cat.resolve_publish_token(&read).await.unwrap(),
            None,
            "a read token must not authorize uploads"
        );
        assert_eq!(
            cat.resolve_publish_token(&svc).await.unwrap(),
            None,
            "a service token must not authorize uploads"
        );
    }

    /// A published version is immutable: identical re-push is an idempotent no-op,
    /// but pushing different dist bytes for an existing version is rejected.
    #[tokio::test]
    async fn pushed_versions_are_immutable() {
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        let sha_a = [11u8; 32];
        let sha_b = [22u8; 32];
        cat.upsert_blob(&sha_a, 100).await.unwrap();
        cat.upsert_blob(&sha_b, 200).await.unwrap();
        let pkg = cat
            .upsert_package(repo_id, "acme/tool", "upload", None, Visibility::Private)
            .await
            .unwrap();
        let cj = serde_json::json!({"name": "acme/tool"});

        // First publish creates the version.
        assert_eq!(
            cat.insert_pushed_version(pkg, "1.0.0", "1.0.0.0", "stable", &cj, &sha_a, "aa", 0)
                .await
                .unwrap(),
            PublishOutcome::Created,
        );
        // Re-publishing the exact same bytes is an idempotent no-op.
        assert_eq!(
            cat.insert_pushed_version(pkg, "1.0.0", "1.0.0.0", "stable", &cj, &sha_a, "aa", 0)
                .await
                .unwrap(),
            PublishOutcome::AlreadyPublished,
        );
        // Publishing *different* bytes for the same version is rejected.
        assert_eq!(
            cat.insert_pushed_version(pkg, "1.0.0", "1.0.0.0", "stable", &cj, &sha_b, "bb", 0)
                .await
                .unwrap(),
            PublishOutcome::Conflict,
        );
        // The stored version still points at the original bytes (unchanged).
        let versions = cat.package_versions(repo_id, "acme/tool").await.unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].dist_blob_sha256, Some(sha_a));
    }

    #[tokio::test]
    // Holds `serial_blobs()` across awaits by design (current-thread test rt).
    #[allow(clippy::await_holding_lock)]
    async fn org_storage_meters_full_size_without_dedup_credit() {
        let _serial = serial_blobs();
        let Some((cat, repo_a)) = repo().await else {
            return;
        };
        let (_, repo_b) = repo().await.unwrap(); // a different org
        let org_a = org_of_repo(&cat, repo_a).await;
        let org_b = org_of_repo(&cat, repo_b).await;

        // A blob shared by both orgs' repos + a second blob only in org A.
        let shared = test_sha(repo_a, 1);
        let solo = test_sha(repo_a, 2);
        let pkg_a = cat
            .upsert_package(repo_a, "acme/lib", "git", None, Visibility::Private)
            .await
            .unwrap();
        cat.upsert_blob(&shared, 1000).await.unwrap();
        cat.upsert_blob(&solo, 500).await.unwrap();
        add_version_with_blob(&cat, pkg_a, "v1.0.0", "1.0.0.0", &shared).await;
        add_version_with_blob(&cat, pkg_a, "v2.0.0", "2.0.0.0", &solo).await;

        let pkg_b = cat
            .upsert_package(repo_b, "acme/lib", "git", None, Visibility::Private)
            .await
            .unwrap();
        add_version_with_blob(&cat, pkg_b, "v1.0.0", "1.0.0.0", &shared).await;

        // Org A: both blobs (1000 + 500). Org B: the shared blob counted in full
        // (1000) — no cross-tenant dedup credit even though it is stored once.
        let a = cat.org_storage(org_a).await.unwrap();
        assert_eq!((a.bytes, a.blob_count), (1500, 2));
        let b = cat.org_storage(org_b).await.unwrap();
        assert_eq!(
            (b.bytes, b.blob_count),
            (1000, 1),
            "shared blob billed in full"
        );

        // The sweep lists both orgs; summing exceeds the ~1500 physically stored.
        let by_org = cat.storage_by_org().await.unwrap();
        let a_row = by_org.iter().find(|o| o.org_id == org_a).unwrap();
        let b_row = by_org.iter().find(|o| o.org_id == org_b).unwrap();
        assert_eq!(a_row.usage.bytes, 1500);
        assert_eq!(b_row.usage.bytes, 1000);
    }

    #[tokio::test]
    // Holds `serial_blobs()` across awaits by design (current-thread test rt).
    #[allow(clippy::await_holding_lock)]
    async fn storage_stats_counts_orphans() {
        let _serial = serial_blobs();
        let Some((cat, repo_id)) = repo().await else {
            return;
        };
        let pkg = cat
            .upsert_package(repo_id, "acme/lib", "git", None, Visibility::Private)
            .await
            .unwrap();
        let before = cat.storage_stats().await.unwrap();

        add_version_with_blob(&cat, pkg, "v1.0.0", "1.0.0.0", &test_sha(repo_id, 11)).await;
        cat.upsert_blob(&test_sha(repo_id, 12), 100).await.unwrap(); // orphan

        let after = cat.storage_stats().await.unwrap();
        assert_eq!(after.blob_count, before.blob_count + 2);
        assert_eq!(after.total_bytes, before.total_bytes + 200);
        assert_eq!(after.orphan_count, before.orphan_count + 1);
        assert_eq!(after.orphan_bytes, before.orphan_bytes + 100);
    }
}
