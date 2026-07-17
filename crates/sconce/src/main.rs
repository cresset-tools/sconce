//! `sconce` — a self-hostable, Composer-compatible private repository.
//!
//! The CLI over the whole engine: mirror git sources into a repository, serve
//! the Composer v2 wire API, manage orgs/repos, read tokens, supply-chain
//! controls (cooldown / hold / approve), agency curation (`grant`), and seller
//! license keys (`license-create`). The low-level `archive`/`ingest` commands
//! expose the deterministic archiver + CAS directly.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

/// Parse a `key=value` CLI argument.
fn parse_kv(s: &str) -> std::result::Result<(String, String), String> {
    s.split_once('=')
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .ok_or_else(|| format!("expected key=value, got '{s}'"))
}

/// Tri-state repo override for raw tokens.
#[derive(Clone, Copy, Debug, ValueEnum)]
enum RawTokenOverride {
    /// Inherit the org's setting (clear the override).
    Inherit,
    /// Allow raw tokens (still capped by the org if the org forbids them).
    Allow,
    /// Disable raw tokens for this repo.
    Deny,
}

/// Upstream visibility (drives package visibility + dependency classification).
#[derive(Clone, Copy, Debug, ValueEnum)]
enum Visib {
    Public,
    Private,
}

impl From<Visib> for sconce_catalog::Visibility {
    fn from(v: Visib) -> Self {
        match v {
            Visib::Public => sconce_catalog::Visibility::Public,
            Visib::Private => sconce_catalog::Visibility::Private,
        }
    }
}

/// How a private upstream's credential is presented when cloning.
#[derive(Clone, Copy, Debug, ValueEnum)]
enum CredType {
    /// The secret is full userinfo (`user:token` / `oauth2:token`).
    Basic,
    /// The secret is a token → `x-access-token:<token>`.
    Github,
    /// The secret is a token → `oauth2:<token>`.
    Gitlab,
    /// The secret is a token → `Authorization: Bearer <token>` header.
    Bearer,
}

impl CredType {
    fn as_str(self) -> &'static str {
        match self {
            CredType::Basic => "basic",
            CredType::Github => "github",
            CredType::Gitlab => "gitlab",
            CredType::Bearer => "bearer",
        }
    }
}
use sconce_archive::{CanonicalArchive, Entry, Mode};

#[derive(Parser, Debug)]
#[command(name = "sconce", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Produce a deterministic ZIP archive of a directory tree.
    ///
    /// Walks `src`, normalizing each file into the canonical form (regular vs
    /// executable vs symlink), and writes a byte-reproducible archive to `out`.
    /// Re-running on the same tree yields identical bytes — the basis for CAS
    /// dedup. For the real package source, prefer `archive-ref`.
    Archive {
        /// Directory to archive.
        src: PathBuf,
        /// Output `.zip` path.
        out: PathBuf,
    },

    /// Produce a deterministic ZIP archive of a git ref (the real source path).
    ///
    /// Reads the tree at `ref` straight from the repository's object database —
    /// canonical modes, verbatim blob content, no working-copy/umask drift — so
    /// the same `(repo, ref)` always yields byte-identical output. Tags and
    /// commits both work (`ref` is peeled to a tree).
    ArchiveRef {
        /// Path to the git repository.
        repo: PathBuf,
        /// Ref to archive (e.g. `HEAD`, `v1.2.0`, a commit sha).
        r#ref: String,
        /// Output `.zip` path.
        out: PathBuf,
    },

    /// Archive a git ref and store it in a content-addressed store (CAS).
    ///
    /// Reads the tree at `ref`, builds the deterministic archive, and stores it
    /// under `--cas` keyed by its sha256. Re-ingesting the same content is a
    /// no-op that returns the same blob id — this is the dedup the whole catalog
    /// is built on. Prints the blob id.
    Ingest {
        /// Path to the git repository.
        repo: PathBuf,
        /// Ref to archive (e.g. `HEAD`, `v1.2.0`, a commit sha).
        r#ref: String,
        /// Directory of the filesystem CAS. Omit when the S3 backend is
        /// configured via the `SCONCE_S3`_* environment variables.
        #[arg(long)]
        cas: Option<PathBuf>,
    },

    /// Mirror every tagged version of a git repository into the CAS + catalog.
    ///
    /// Enumerates tags, derives a Composer version from each, reads its
    /// `composer.json`, archives the tree, stores it content-addressed, and
    /// upserts the catalog. Idempotent — re-running dedupes blobs and upserts
    /// the same rows.
    Mirror {
        /// Path to the git checkout to mirror.
        source: PathBuf,
        /// Target catalog repository, as `<org>/<repo>`.
        #[arg(long)]
        repo: String,
        /// Public source URL recorded for the package (e.g. the git remote).
        #[arg(long)]
        git_url: String,
        /// Directory of the filesystem CAS. Omit when the S3 backend is
        /// configured via the `SCONCE_S3`_* environment variables.
        #[arg(long)]
        cas: Option<PathBuf>,
        /// Postgres connection string.
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },

    /// Create an organization.
    OrgCreate {
        /// Slug, e.g. `acme`.
        slug: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },

    /// Show or change org-wide settings (raw-token toggle, max token TTL).
    OrgSettings {
        /// Organization slug.
        org: String,
        /// Allow raw repo tokens to be created (`true`/`false`). Omit to leave
        /// unchanged.
        #[arg(long)]
        allow_raw_tokens: Option<bool>,
        /// Max token expiry in days; `0` clears the limit. Omit to leave
        /// unchanged.
        #[arg(long)]
        max_token_ttl_days: Option<i64>,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },

    /// Create a repository in an organization.
    RepoCreate {
        /// Organization slug.
        org: String,
        /// Repository slug.
        repo: String,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },

    /// Register a project's git remote so a client can fetch its team config
    /// (Composer repositories, and later pinned services / policy) keyed by the
    /// remote alone. Any URL form (https, ssh, scp) is accepted and normalized;
    /// re-registering reassigns the remote to the given org.
    RemoteAdd {
        /// Organization slug.
        org: String,
        /// The project's git remote URL.
        remote: String,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },

    /// List the git remotes registered to an organization.
    RemoteList {
        /// Organization slug.
        org: String,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },

    /// Unregister a git remote (any URL form).
    RemoteRemove {
        /// The project's git remote URL.
        remote: String,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },

    /// Set (or clear) the database snapshot source a registered remote's team
    /// manifest advertises, so `bougie db pull` needs no `--repo`. Point it at
    /// the repo whose `snapshots/<env>/latest` holds the dump.
    RemoteSnapshot {
        /// The project's git remote URL (any form; normalized).
        remote: String,
        /// Dataset repository holding the snapshots, as `<org>/<repo>`.
        #[arg(long, value_name = "ORG/REPO", conflicts_with = "clear")]
        repo: Option<String>,
        /// Environment whose snapshots to seed from.
        #[arg(long, default_value = "production")]
        env: String,
        /// Default data profile the manifest advertises (omit for `full`).
        #[arg(long, conflicts_with = "clear")]
        profile: Option<String>,
        /// Clear the snapshot config instead of setting it.
        #[arg(long, conflicts_with = "repo")]
        clear: bool,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },

    /// Set (or clear) a named database source a registered remote's team
    /// manifest advertises, for `bougie db get --source <name>`. Point it at the
    /// jibs SSH host a dev with access reproduces prod/staging rows from — the
    /// manifest carries the connection, never a credential.
    RemoteSource {
        /// The project's git remote URL (any form; normalized).
        remote: String,
        /// Source name, e.g. `production` or `staging`.
        name: String,
        /// SSH target jibs connects to on the source side (`user@host`).
        #[arg(long, conflicts_with = "clear")]
        host: Option<String>,
        /// Source-side MySQL/MariaDB DSN jibs reads (defaults to jibs's own).
        #[arg(long)]
        remote_mysql: Option<String>,
        /// SSH identity file to authenticate with.
        #[arg(long)]
        identity: Option<String>,
        /// SSH port, if not the default 22.
        #[arg(long)]
        port: Option<u16>,
        /// Remove this named source instead of setting it.
        #[arg(long, conflicts_with = "host")]
        clear: bool,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },

    /// Rename an organization. The old slug keeps redirecting (so composer.lock
    /// URLs still work) and is permanently retired.
    OrgRename {
        /// Current organization slug.
        org: String,
        /// New slug.
        new_slug: String,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },

    /// Rename a repository. The old name keeps redirecting and is retired.
    RepoRename {
        /// Repository, as `<org>/<repo>`.
        repo: String,
        /// New repository slug.
        new_slug: String,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },

    /// Manage a repo's upstreams (where packages are mirrored from).
    Upstream {
        #[command(subcommand)]
        action: UpstreamAction,
    },

    /// Mirror a registered git upstream by id (clone + enumerate tags).
    MirrorUpstream {
        /// Upstream id (see `upstream list`).
        id: uuid::Uuid,
        /// Directory of the filesystem CAS. Omit when the S3 backend is
        /// configured via the `SCONCE_S3`_* environment variables.
        #[arg(long)]
        cas: Option<PathBuf>,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },

    /// Mirror one package from a registered composer upstream (Packagist /
    /// Mage-OS style): fetch its p2 metadata + download dists verbatim.
    MirrorPackage {
        /// Composer upstream id (see `upstream list`).
        #[arg(long)]
        upstream: uuid::Uuid,
        /// Package name, e.g. `mage-os/composer`.
        #[arg(long)]
        package: String,
        /// Directory of the filesystem CAS. Omit when the S3 backend is
        /// configured via the `SCONCE_S3`_* environment variables.
        #[arg(long)]
        cas: Option<PathBuf>,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },

    /// Mirror a composer registry per the upstream's stored require-list: every
    /// package in `available-packages` it selects (set the list with `upstream
    /// add --require …`). An upstream with no requires is refused.
    MirrorRegistry {
        /// Composer upstream id (see `upstream list`).
        #[arg(long)]
        upstream: uuid::Uuid,
        /// Directory of the filesystem CAS. Omit when the S3 backend is
        /// configured via the `SCONCE_S3`_* environment variables.
        #[arg(long)]
        cas: Option<PathBuf>,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },

    /// Dependency closure: resolve (background), review the plan, and add picks.
    Deps {
        #[command(subcommand)]
        action: DepsAction,
    },

    /// Inspect package lifecycle and archive/un-archive broken packages.
    Package {
        #[command(subcommand)]
        action: PackageAction,
    },

    /// Run the background mirror worker: drain the job queue, then wait for
    /// NOTIFY (with a poll backstop) and repeat. Runs until killed.
    Worker {
        /// Directory of the filesystem CAS. Omit when the S3 backend is
        /// configured via the `SCONCE_S3`_* environment variables.
        #[arg(long)]
        cas: Option<PathBuf>,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },

    /// Reclaim unreferenced blobs from the store (garbage collection).
    ///
    /// A blob is collectable once no package version references it (refcount 0)
    /// and it has been untouched for the grace period — the grace window keeps
    /// a sweep from racing a mirror job that is mid-flight. Safe to run against
    /// a live server; schedule it off-peak for the least contention. Reports
    /// storage totals and what it freed.
    Gc {
        /// Directory of the filesystem CAS. Omit when the S3 backend is
        /// configured via the `SCONCE_S3`_* environment variables.
        #[arg(long)]
        cas: Option<PathBuf>,
        /// Only collect blobs unreferenced and untouched for at least this many
        /// hours. Larger = safer against concurrent mirroring.
        #[arg(long, default_value_t = 24)]
        grace_hours: u64,
        /// Report what would be collected without deleting anything.
        #[arg(long)]
        dry_run: bool,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },

    /// Report metered storage per organization (the storage-tier billing input).
    ///
    /// Storage is metered at full logical size: a blob shared across orgs (the
    /// same public package mirrored by two tenants) is counted in full for each
    /// — the physical dedup saving is the operator's margin, not a per-tenant
    /// discount. Without `--org`, lists every org busiest-first.
    Usage {
        /// Limit to one organization (by slug). Omit for all orgs.
        #[arg(long)]
        org: Option<String>,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },

    /// Show or set an org's entitlements — the neutral per-org resource throttle
    /// the hosted control plane drives (self-host leaves it unset = unlimited).
    Entitlements {
        #[command(subcommand)]
        action: EntitlementsAction,
    },

    /// Show or change a repo's token-policy overrides (tighten-only vs the org).
    RepoSettings {
        /// Repository, as `<org>/<repo>`.
        repo: String,
        /// Raw-token override: `inherit`, `allow`, or `deny`. Omit to leave
        /// unchanged.
        #[arg(long)]
        allow_raw_tokens: Option<RawTokenOverride>,
        /// Max token expiry in days; `0` clears the override (inherit). Omit to
        /// leave unchanged.
        #[arg(long)]
        max_token_ttl_days: Option<i64>,
        /// Whether the repo may contain private packages (`true`/`false`). When
        /// false the repo is public-only. Omit to leave unchanged.
        #[arg(long)]
        allow_private_packages: Option<bool>,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },

    /// Create (or update) an admin-UI user. Use `--superadmin` for the first,
    /// all-tenant account.
    UserCreate {
        /// Login email.
        email: String,
        /// Password.
        password: String,
        /// Grant access to all tenants.
        #[arg(long)]
        superadmin: bool,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },

    /// Give a user access to a tenant (organization).
    UserGrant {
        /// User email.
        email: String,
        /// Tenant (organization) slug.
        tenant: String,
        /// Role in the tenant: `member` (read-only) or `admin` (manage).
        #[arg(long, default_value = "member")]
        role: String,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },

    /// Manage CI OIDC exchange policies (zero-secret CI installs).
    CiPolicy {
        #[command(subcommand)]
        action: CiPolicyAction,
    },

    /// Publish (push) a package directory to a sconce server.
    ///
    /// Tars `dir`, obtains a short-lived **publish token** (via GitHub Actions
    /// OIDC, or `--token`), and uploads it to `<url>/<org>/<repo>` — one request for
    /// small packages, resumable chunks for large ones. The package **name** is read
    /// from `dir/composer.json`; the **version** is `--version` or `$GITHUB_REF_NAME`.
    /// Unlike the other commands, this talks to the running server over HTTP, not the
    /// database.
    Publish {
        /// Package directory (must contain `composer.json` at its root).
        dir: PathBuf,
        /// Target repository, as `<org>/<repo>`.
        #[arg(long)]
        repo: String,
        /// Base URL of the sconce wire server, e.g. `https://repo.example.com`.
        #[arg(long, env = "SCONCE_URL")]
        url: String,
        /// Version to publish (e.g. `1.2.0`). Defaults to `$GITHUB_REF_NAME`.
        #[arg(long)]
        version: Option<String>,
        /// OIDC audience the repo's publish policy expects.
        #[arg(long, default_value = "sconce")]
        audience: String,
        /// A publish token to use directly (otherwise obtained via GitHub OIDC).
        #[arg(long, env = "SCONCE_PUBLISH_TOKEN")]
        token: Option<String>,
        /// Upload as chunks of at most this many bytes (also the single-shot
        /// threshold). Defaults to 32 MiB.
        #[arg(long)]
        part_size: Option<u64>,
    },

    /// Create (or replace) an org's SCIM bearer token for identity-provider
    /// provisioning / deprovisioning. Printed once — set it in the provider's
    /// SCIM settings.
    ScimToken {
        /// Organization slug.
        org: String,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },

    /// Configure dashboard SSO. Without --org sets the instance default; with
    /// --org <slug> sets that org's connection (users from it land in that org).
    OidcConfig {
        /// Scope to an org slug (omit for the instance-default connection).
        #[arg(long)]
        org: Option<String>,
        /// Identity-provider issuer URL (its openid-configuration base).
        #[arg(long)]
        issuer: String,
        #[arg(long)]
        client_id: String,
        /// Client secret (stored encrypted; needs `SCONCE_SECRET_KEY`). Omit for
        /// a public PKCE-only client.
        #[arg(long)]
        client_secret: Option<String>,
        /// The callback URL — must be `<ui-base>/auth/callback`.
        #[arg(long)]
        redirect_url: String,
        /// Space-separated scopes.
        #[arg(long, default_value = "openid email profile")]
        scopes: String,
        /// Comma-separated email domains allowed to sign in (default: any).
        #[arg(long)]
        allowed_domains: Option<String>,
        /// Comma-separated email domains provisioned as superadmins.
        #[arg(long)]
        admin_domains: Option<String>,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },

    /// Issue a license key for a repository, entitled to specific packages
    /// (seller mode). The buyer authenticates with the key (http-basic password)
    /// and may install only the listed packages.
    LicenseCreate {
        /// Seller repository, as `<org>/<repo>`.
        #[arg(long)]
        repo: String,
        /// Buyer reference (email / order id).
        #[arg(long)]
        buyer: Option<String>,
        /// Packages the buyer purchased (entitled).
        #[arg(required = true)]
        packages: Vec<String>,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },

    /// Issue a license key against an **edition** (SKU): resolves the edition's
    /// packages, update bound, and policy onto the key in one step.
    LicenseIssue {
        /// Seller repository, as `<org>/<repo>`.
        #[arg(long)]
        repo: String,
        /// Edition to issue against (its name or slug).
        #[arg(long)]
        edition: String,
        /// Buyer reference (email / order id).
        #[arg(long)]
        buyer: Option<String>,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },

    /// Manage editions (SKUs): reusable sellable units that license keys are
    /// issued against (a package set + an update-bound template).
    Edition {
        #[command(subcommand)]
        action: EditionAction,
    },

    /// Manage management-API service tokens: repo-scoped bearer credentials a
    /// commerce front-end (e.g. the Magento module) uses to provision keys.
    ServiceToken {
        #[command(subcommand)]
        action: ServiceTokenAction,
    },

    /// Inspect and prune database snapshots (datasets) uploaded to a repository.
    Snapshot {
        #[command(subcommand)]
        action: SnapshotAction,
    },

    /// Grant a package from one repository into another (agency curation).
    ///
    /// The target repo then exposes the package without owning it — mirror a
    /// public/purchased package once into a shared repo, grant the curated
    /// subset into each client repo.
    Grant {
        /// Target repository (gains the package), as `<org>/<repo>`.
        #[arg(long)]
        repo: String,
        /// Source repository that owns the package, as `<org>/<repo>`.
        #[arg(long)]
        from: String,
        /// Package name, e.g. `monolog/monolog`.
        package: String,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },

    /// Serve the Composer v2 wire API (packages.json, p2 metadata, dist) over HTTP.
    Serve {
        /// Directory of the filesystem CAS. Omit when the S3 backend is
        /// configured via the `SCONCE_S3`_* environment variables.
        #[arg(long)]
        cas: Option<PathBuf>,
        /// Postgres connection string.
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
        /// Address to listen on (the Composer wire API).
        #[arg(long, default_value = "127.0.0.1:8080")]
        listen: std::net::SocketAddr,
        /// Public base URL emitted in metadata/dist URLs.
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        base_url: String,
        /// Don't run the in-process mirror worker (run a separate `sconce
        /// worker` instead).
        #[arg(long)]
        no_worker: bool,
        /// Also serve the admin UI on this address (single-binary deploy).
        #[arg(long)]
        ui_listen: Option<std::net::SocketAddr>,
        /// Admin UI: single-tenant mode (no accounts; gated by --admin-password).
        #[arg(long)]
        single_tenant: bool,
        /// Admin UI password for single-tenant mode.
        #[arg(long, env = "SCONCE_ADMIN_PASSWORD")]
        admin_password: Option<String>,
    },

    /// Serve the admin web UI (operator dashboard). Set `--admin-password` to
    /// require HTTP basic auth; otherwise it's open — bind to localhost only.
    Ui {
        /// Postgres connection string.
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
        /// Address to listen on.
        #[arg(long, default_value = "127.0.0.1:8081")]
        listen: std::net::SocketAddr,
        /// Public base URL of the Composer endpoint (for install snippets).
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        public_base_url: String,
        /// Single-tenant mode: no user accounts; gate with `--admin-password`.
        #[arg(long)]
        single_tenant: bool,
        /// Single-tenant only: require HTTP basic auth with this password.
        #[arg(long, env = "SCONCE_ADMIN_PASSWORD")]
        admin_password: Option<String>,
    },

    /// Manage read tokens (the repo is private; clients authenticate with one).
    Token {
        #[command(subcommand)]
        action: TokenAction,
    },

    /// View or set the update policy (supply-chain controls).
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },

    /// Place a security hold on a version (hides it from clients immediately).
    Hold {
        /// Repository, as `<org>/<repo>`.
        #[arg(long)]
        repo: String,
        /// Package name, e.g. `acme/widget`.
        package: String,
        /// Version/tag, e.g. `v1.2.0`.
        version: String,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },

    /// Release a hold on a version.
    Unhold {
        #[arg(long)]
        repo: String,
        package: String,
        version: String,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },

    /// Approve a version (reveal it under `manual`, or early under `delayed`).
    Approve {
        #[arg(long)]
        repo: String,
        package: String,
        version: String,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },
}

#[derive(Subcommand, Debug)]
enum PolicyAction {
    /// Show a repository's update policy.
    Show {
        #[arg(long)]
        repo: String,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },
    /// Set a repository's update policy.
    Set {
        #[arg(long)]
        repo: String,
        /// `auto` (everything visible), `manual` (only approved), or `delayed`
        /// (visible after the cooldown).
        #[arg(long)]
        mode: String,
        /// Days a release must age before becoming visible under `delayed`.
        #[arg(long, default_value_t = 0)]
        cooldown_days: i32,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },
}

#[derive(Subcommand, Debug)]
enum UpstreamAction {
    /// Register an upstream for a repository.
    Add {
        /// Repository, as `<org>/<repo>`.
        #[arg(long)]
        repo: String,
        /// `git` (clone URL) or `composer` (registry URL; mirroring TBD).
        #[arg(long, default_value = "git")]
        kind: String,
        /// Clone/registry URL.
        #[arg(long)]
        base: String,
        /// `public` or `private` — drives mirrored package visibility.
        #[arg(long)]
        visibility: Visib,
        /// Optional human label.
        #[arg(long)]
        label: Option<String>,
        /// Credential secret to use when cloning (a token, or `user:pass` for
        /// `--credential-type basic`). Ignored for public upstreams. Stored
        /// encrypted; needs `SCONCE_SECRET_KEY`.
        #[arg(long)]
        credential: Option<String>,
        /// How to present the credential: basic | github | gitlab | bearer.
        #[arg(long, default_value = "basic")]
        credential_type: CredType,
        /// Mirror subscription entry, repeatable (OR-union). Forms:
        /// `vendor/*` or `vendor/` (a vendor prefix), `vendor/pkg` (one package),
        /// `*` (the whole registry — require-all), `re:<regex>` (advanced). Append
        /// `@<version>` for a version floor, e.g. `mage-os/*@2.4`. Required for a
        /// composer upstream; optional floor for a git one (use `*@<version>`).
        #[arg(long = "require")]
        require: Vec<String>,
        /// git-only: a monorepo subdirectory to mirror as its own package
        /// (the dir holding that package's composer.json), repeatable. Omit to
        /// mirror the repo root as a single package.
        #[arg(long = "source-path")]
        source_path: Vec<String>,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },
    /// List a repository's upstreams (never the secret).
    List {
        /// Repository, as `<org>/<repo>`.
        #[arg(long)]
        repo: String,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },
    /// Remove an upstream by id.
    Remove {
        /// Repository, as `<org>/<repo>`.
        #[arg(long)]
        repo: String,
        /// Upstream id to remove.
        id: uuid::Uuid,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },
}

#[derive(Subcommand, Debug)]
enum CiPolicyAction {
    /// Add a CI OIDC policy: a workflow whose JWT validates and matches the
    /// given claims gets a short-lived token for the repo.
    Add {
        /// Repository, as `<org>/<repo>`.
        #[arg(long)]
        repo: String,
        /// Provider label (`github`, `gitlab`, …).
        #[arg(long)]
        provider: String,
        /// OIDC issuer URL (e.g. `https://token.actions.githubusercontent.com`).
        #[arg(long)]
        issuer: String,
        /// Expected `aud` claim (what the workflow sets as the audience).
        #[arg(long)]
        audience: String,
        /// Required claim, `key=value` (repeatable; e.g. `repository=acme/app`).
        #[arg(long = "claim", value_parser = parse_kv)]
        claims: Vec<(String, String)>,
        /// Minted token lifetime in seconds.
        #[arg(long, default_value_t = 900)]
        ttl_secs: i64,
        /// What the minted token may do: `read` (Composer serving, default) or
        /// `publish` (upload package versions via the publish API).
        #[arg(long, default_value = "read")]
        capability: String,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },
    /// List a repo's CI OIDC policies.
    List {
        /// Repository, as `<org>/<repo>`.
        #[arg(long)]
        repo: String,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },
}

#[derive(Subcommand, Debug)]
enum DepsAction {
    /// Enqueue a job to resolve the repo's full dependency closure (the worker
    /// computes it). Review with `deps plan`.
    Resolve {
        /// Repository, as `<org>/<repo>`.
        #[arg(long)]
        repo: String,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },
    /// Show the computed dependency plan (the proposal to review).
    Plan {
        /// Repository, as `<org>/<repo>`.
        #[arg(long)]
        repo: String,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },
    /// Add a resolvable dependency: enqueue mirroring it from its resolver.
    Add {
        /// Repository, as `<org>/<repo>`.
        #[arg(long)]
        repo: String,
        /// Package name from the plan, e.g. `mage-os/framework`.
        package: String,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },
}

#[derive(Subcommand, Debug)]
enum EntitlementsAction {
    /// Show an org's effective entitlements (and whether they're the unlimited
    /// self-host default or an explicit control-plane row).
    Show {
        #[arg(long)]
        org: String,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },
    /// Set an org's entitlements. `--features` is the *complete* set of enabled
    /// features (comma-separated machine names); any not listed are disabled.
    /// Omit a cap flag to leave it unlimited.
    Set {
        #[arg(long)]
        org: String,
        /// Enabled features, comma-separated (e.g. `agency,sso,scim`). Empty
        /// disables all. Known: `agency`, `sso`, `multi_oidc`, `repo_access`,
        /// `scim`, `audit_log`, `custom_hostname`, `white_label`.
        #[arg(long, default_value = "")]
        features: String,
        /// Hard SKU cap (sellable editions). Omit for unlimited.
        #[arg(long)]
        max_skus: Option<i32>,
        /// Advisory storage limit in GB (drives a UI warning; never blocks).
        #[arg(long)]
        storage_soft_gb: Option<i64>,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },
    /// Remove an org's entitlements row → back to the unlimited default.
    Clear {
        #[arg(long)]
        org: String,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },
}

#[derive(Subcommand, Debug)]
enum EditionAction {
    /// Create an edition. Its target is either an existing package set
    /// (`--set <name>`) or a single package (`--package <name>`, which reuses a
    /// singleton set). Gated on the org's `max_skus` cap.
    Create {
        /// Seller repository, as `<org>/<repo>`.
        #[arg(long)]
        repo: String,
        /// Edition name (unique within the repo), e.g. `Pro`.
        #[arg(long)]
        name: String,
        /// Stable external id for product/API mapping (defaults to none).
        #[arg(long)]
        slug: Option<String>,
        /// Target: an existing org package set, by name.
        #[arg(long, conflicts_with = "package")]
        set: Option<String>,
        /// Target: a single package (a singleton set is created/reused).
        #[arg(long, conflicts_with = "set")]
        package: Option<String>,
        /// Update-bound template: `perpetual`, `time:<months>` (e.g. `time:12`),
        /// or `version:<major>` (e.g. `version:3`).
        #[arg(long, default_value = "perpetual")]
        bound: String,
        /// Freeze set membership at issue (snapshot) instead of by-reference.
        #[arg(long)]
        snapshot: bool,
        /// Optional policy stamped on issued keys: update mode
        /// (`auto`|`delayed`|`manual`).
        #[arg(long)]
        mode: Option<String>,
        /// Optional policy stamped on issued keys: cooldown days.
        #[arg(long)]
        cooldown_days: Option<i32>,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },
    /// List a repo's editions.
    List {
        /// Seller repository, as `<org>/<repo>`.
        #[arg(long)]
        repo: String,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },
    /// Deactivate an edition (stops new sales and frees a SKU slot; already-
    /// issued keys keep working). By name or slug.
    Deactivate {
        /// Seller repository, as `<org>/<repo>`.
        #[arg(long)]
        repo: String,
        /// Edition name or slug.
        edition: String,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },
}

#[derive(Subcommand, Debug)]
enum ServiceTokenAction {
    /// Mint a service token for a repository and print it once.
    Create {
        /// Seller repository, as `<org>/<repo>`.
        #[arg(long)]
        repo: String,
        /// Optional human label (so it can be identified and revoked).
        #[arg(long)]
        label: Option<String>,
        /// Days until expiry; omit for a non-expiring token.
        #[arg(long)]
        expires_days: Option<i64>,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },
    /// List a repository's service tokens (never the tokens themselves).
    List {
        #[arg(long)]
        repo: String,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },
    /// Revoke a service token by id.
    Revoke {
        #[arg(long)]
        repo: String,
        /// Service-token id (from `service-token list`).
        id: String,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },
}

#[derive(Subcommand, Debug)]
enum SnapshotAction {
    /// List a repository+environment's snapshots, newest first (`*` = latest).
    List {
        /// Repository, as `<org>/<repo>`.
        #[arg(long)]
        repo: String,
        /// Environment label (e.g. production, staging).
        #[arg(long)]
        env: String,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },
    /// Retention: keep the newest `--keep` snapshots in a repo+environment+
    /// profile, deleting the rest. Never deletes the current `latest`; freed
    /// blobs are reclaimed by `sconce gc`.
    Prune {
        /// Repository, as `<org>/<repo>`.
        #[arg(long)]
        repo: String,
        /// Environment label (e.g. production, staging).
        #[arg(long)]
        env: String,
        /// Data profile whose history to prune.
        #[arg(long, default_value = "full")]
        profile: String,
        /// How many of the newest snapshots to keep.
        #[arg(long)]
        keep: i64,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },
    /// Upload a database snapshot file as the environment's new `latest`, from CI.
    /// Unlike `list`/`prune`, this talks to the running server over HTTP (like
    /// `publish`), authenticated by a publish token or a GitHub OIDC exchange —
    /// no database access. The file is stored verbatim (small ones in a single
    /// request, larger ones in resumable chunks).
    Push {
        /// Snapshot file to upload (e.g. a `.jibsdump`).
        file: PathBuf,
        /// Target repository, as `<org>/<repo>`.
        #[arg(long)]
        repo: String,
        /// Base URL of the sconce wire server, e.g. `https://repo.example.com`.
        #[arg(long, env = "SCONCE_URL")]
        url: String,
        /// Environment label the snapshot belongs to (e.g. production, staging).
        #[arg(long)]
        env: String,
        /// Data profile this dump is a variant of (e.g. small, perf). Each
        /// profile is a separately produced dump with its own `latest`.
        #[arg(long, default_value = "full")]
        profile: String,
        /// OIDC audience the repo's publish policy expects.
        #[arg(long, default_value = "sconce")]
        audience: String,
        /// A publish token to use directly (otherwise obtained via GitHub OIDC).
        #[arg(long, env = "SCONCE_PUBLISH_TOKEN")]
        token: Option<String>,
        /// Upload as chunks of at most this many bytes (also the single-shot
        /// threshold). Defaults to 32 MiB.
        #[arg(long)]
        part_size: Option<u64>,
    },
}

#[derive(Subcommand, Debug)]
enum PackageAction {
    /// List packages with their lifecycle (healthy / broken / archived / stale).
    List {
        /// Repository, as `<org>/<repo>`.
        #[arg(long)]
        repo: String,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },
    /// Archive a package: freeze it and silence its broken flag. Its already-
    /// mirrored versions keep serving; no new versions are pulled.
    Archive {
        /// Repository, as `<org>/<repo>`.
        #[arg(long)]
        repo: String,
        /// Package name, e.g. `vendor/abandoned`.
        package: String,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },
    /// Un-archive a package: resume syncing (health is re-detected).
    Unarchive {
        /// Repository, as `<org>/<repo>`.
        #[arg(long)]
        repo: String,
        /// Package name.
        package: String,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },
}

#[derive(Subcommand, Debug)]
enum TokenAction {
    /// Create a new token for a repository and print it once.
    Create {
        /// Repository, as `<org>/<repo>`.
        #[arg(long)]
        repo: String,
        /// Optional human label (so the token can be identified and revoked).
        #[arg(long)]
        label: Option<String>,
        /// Optional expiry, in days from now. Omit for a token that never
        /// expires.
        #[arg(long)]
        expires_days: Option<i64>,
        /// Postgres connection string.
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },
    /// List a repository's tokens (id, label, expiry) — never the secret.
    List {
        /// Repository, as `<org>/<repo>`.
        #[arg(long)]
        repo: String,
        /// Postgres connection string.
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },
    /// Revoke a token by id (see `token list`).
    Revoke {
        /// Repository, as `<org>/<repo>`.
        #[arg(long)]
        repo: String,
        /// Token id to revoke.
        id: uuid::Uuid,
        /// Postgres connection string.
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },
    /// Set (or clear) a token's per-credential supply-chain policy override. Omit
    /// both `--mode` and `--cooldown-days` to clear it (inherit the repo). The
    /// override can only *tighten* the repo policy at serve time.
    Policy {
        /// Repository, as `<org>/<repo>`.
        #[arg(long)]
        repo: String,
        /// Token label to target (see `token list`).
        #[arg(long)]
        label: String,
        /// Update mode override: `auto`, `manual`, or `delayed`. Omit to leave
        /// the mode inherited.
        #[arg(long)]
        mode: Option<String>,
        /// Cooldown-days override (a positive value implies `delayed`).
        #[arg(long)]
        cooldown_days: Option<i32>,
        /// Postgres connection string.
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },
}

// A flat command dispatcher; its length is just the number of subcommands.
#[allow(clippy::too_many_lines)]
fn main() -> Result<()> {
    // Load a local `.env` (e.g. DATABASE_URL) if present — searched from the
    // working directory upward — before clap reads env-backed args. A missing
    // file is not an error; an existing-but-unreadable one is surfaced.
    match dotenvy::dotenv() {
        Ok(_) => {}
        Err(e) if e.not_found() => {} // no .env file is fine
        Err(e) => return Err(e).context("loading .env"),
    }
    // Logs (server/worker events) go to stderr through tracing, filtered by
    // RUST_LOG (default `info`). CLI command *output* stays on stdout, so
    // `sconce token create | pbcopy` and friends are unaffected.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    match cli.command {
        Command::Archive { src, out } => archive(&src, &out),
        Command::ArchiveRef { repo, r#ref, out } => archive_ref(&repo, &r#ref, &out),
        Command::Ingest { repo, r#ref, cas } => ingest(&repo, &r#ref, cas.as_deref()),
        Command::Mirror {
            source,
            repo,
            git_url,
            cas,
            database_url,
        } => mirror(&source, &repo, &git_url, cas.as_deref(), &database_url),
        Command::Serve {
            cas,
            database_url,
            listen,
            base_url,
            no_worker,
            ui_listen,
            single_tenant,
            admin_password,
        } => serve(
            cas.as_deref(),
            &database_url,
            listen,
            base_url,
            no_worker,
            ui_listen,
            single_tenant,
            admin_password,
        ),
        Command::Ui {
            database_url,
            listen,
            public_base_url,
            single_tenant,
            admin_password,
        } => ui(
            &database_url,
            listen,
            public_base_url,
            single_tenant,
            admin_password,
        ),
        Command::OrgCreate {
            slug,
            name,
            database_url,
        } => org_create(&slug, name.as_deref(), &database_url),
        Command::OrgSettings {
            org,
            allow_raw_tokens,
            max_token_ttl_days,
            database_url,
        } => org_settings(&org, allow_raw_tokens, max_token_ttl_days, &database_url),
        Command::Upstream { action } => match action {
            UpstreamAction::Add {
                repo,
                kind,
                base,
                visibility,
                label,
                credential,
                credential_type,
                require,
                source_path,
                database_url,
            } => upstream_add(
                &repo,
                &kind,
                &base,
                visibility.into(),
                label.as_deref(),
                credential.as_deref(),
                credential_type.as_str(),
                &require,
                &source_path,
                &database_url,
            ),
            UpstreamAction::List { repo, database_url } => upstream_list(&repo, &database_url),
            UpstreamAction::Remove {
                repo,
                id,
                database_url,
            } => upstream_remove(&repo, id, &database_url),
        },
        Command::MirrorUpstream {
            id,
            cas,
            database_url,
        } => mirror_upstream(id, cas.as_deref(), &database_url),
        Command::MirrorPackage {
            upstream,
            package,
            cas,
            database_url,
        } => mirror_package(upstream, &package, cas.as_deref(), &database_url),
        Command::MirrorRegistry {
            upstream,
            cas,
            database_url,
        } => mirror_registry(upstream, cas.as_deref(), &database_url),
        Command::Deps { action } => match action {
            DepsAction::Resolve { repo, database_url } => deps_resolve(&repo, &database_url),
            DepsAction::Plan { repo, database_url } => deps_plan(&repo, &database_url),
            DepsAction::Add {
                repo,
                package,
                database_url,
            } => deps_add(&repo, &package, &database_url),
        },
        Command::Package { action } => match action {
            PackageAction::List { repo, database_url } => package_list(&repo, &database_url),
            PackageAction::Archive {
                repo,
                package,
                database_url,
            } => package_set_archived(&repo, &package, true, &database_url),
            PackageAction::Unarchive {
                repo,
                package,
                database_url,
            } => package_set_archived(&repo, &package, false, &database_url),
        },
        Command::Worker { cas, database_url } => worker(cas.as_deref(), &database_url),
        Command::Gc {
            cas,
            grace_hours,
            dry_run,
            database_url,
        } => gc(cas.as_deref(), grace_hours, dry_run, &database_url),
        Command::Usage { org, database_url } => usage(org.as_deref(), &database_url),
        Command::Entitlements { action } => entitlements(action),
        Command::RepoSettings {
            repo,
            allow_raw_tokens,
            max_token_ttl_days,
            allow_private_packages,
            database_url,
        } => repo_settings(
            &repo,
            allow_raw_tokens,
            max_token_ttl_days,
            allow_private_packages,
            &database_url,
        ),
        Command::RepoCreate {
            org,
            repo,
            database_url,
        } => repo_create(&org, &repo, &database_url),
        Command::RemoteAdd {
            org,
            remote,
            database_url,
        } => remote_add(&org, &remote, &database_url),
        Command::RemoteList { org, database_url } => remote_list(&org, &database_url),
        Command::RemoteRemove {
            remote,
            database_url,
        } => remote_remove(&remote, &database_url),
        Command::RemoteSnapshot {
            remote,
            repo,
            env,
            profile,
            clear,
            database_url,
        } => remote_snapshot(
            &remote,
            repo.as_deref(),
            &env,
            profile.as_deref(),
            clear,
            &database_url,
        ),
        Command::RemoteSource {
            remote,
            name,
            host,
            remote_mysql,
            identity,
            port,
            clear,
            database_url,
        } => remote_source(
            &remote,
            &name,
            host.as_deref(),
            remote_mysql.as_deref(),
            identity.as_deref(),
            port,
            clear,
            &database_url,
        ),
        Command::OrgRename {
            org,
            new_slug,
            database_url,
        } => org_rename(&org, &new_slug, &database_url),
        Command::RepoRename {
            repo,
            new_slug,
            database_url,
        } => repo_rename(&repo, &new_slug, &database_url),
        Command::UserCreate {
            email,
            password,
            superadmin,
            database_url,
        } => user_create(&email, &password, superadmin, &database_url),
        Command::UserGrant {
            email,
            tenant,
            role,
            database_url,
        } => user_grant(&email, &tenant, &role, &database_url),
        Command::CiPolicy { action } => match action {
            CiPolicyAction::Add {
                repo,
                provider,
                issuer,
                audience,
                claims,
                ttl_secs,
                capability,
                database_url,
            } => ci_policy_add(
                &repo,
                &provider,
                &issuer,
                &audience,
                &claims,
                ttl_secs,
                &capability,
                &database_url,
            ),
            CiPolicyAction::List { repo, database_url } => ci_policy_list(&repo, &database_url),
        },
        Command::Publish {
            dir,
            repo,
            url,
            version,
            audience,
            token,
            part_size,
        } => publish(
            &dir,
            &repo,
            &url,
            version.as_deref(),
            &audience,
            token.as_deref(),
            part_size,
        ),
        Command::ScimToken { org, database_url } => scim_token(&org, &database_url),
        Command::OidcConfig {
            org,
            issuer,
            client_id,
            client_secret,
            redirect_url,
            scopes,
            allowed_domains,
            admin_domains,
            database_url,
        } => oidc_config(
            org.as_deref(),
            &issuer,
            &client_id,
            client_secret.as_deref(),
            &redirect_url,
            &scopes,
            allowed_domains.as_deref(),
            admin_domains.as_deref(),
            &database_url,
        ),
        Command::LicenseCreate {
            repo,
            buyer,
            packages,
            database_url,
        } => license_create(&repo, buyer.as_deref(), &packages, &database_url),
        Command::LicenseIssue {
            repo,
            edition,
            buyer,
            database_url,
        } => license_issue(&repo, &edition, buyer.as_deref(), &database_url),
        Command::Edition { action } => match action {
            EditionAction::Create {
                repo,
                name,
                slug,
                set,
                package,
                bound,
                snapshot,
                mode,
                cooldown_days,
                database_url,
            } => edition_create(
                &repo,
                &name,
                slug.as_deref(),
                set.as_deref(),
                package.as_deref(),
                &bound,
                snapshot,
                mode.as_deref(),
                cooldown_days,
                &database_url,
            ),
            EditionAction::List { repo, database_url } => edition_list(&repo, &database_url),
            EditionAction::Deactivate {
                repo,
                edition,
                database_url,
            } => edition_deactivate(&repo, &edition, &database_url),
        },
        Command::ServiceToken { action } => match action {
            ServiceTokenAction::Create {
                repo,
                label,
                expires_days,
                database_url,
            } => service_token_create(&repo, label.as_deref(), expires_days, &database_url),
            ServiceTokenAction::List { repo, database_url } => {
                service_token_list(&repo, &database_url)
            }
            ServiceTokenAction::Revoke {
                repo,
                id,
                database_url,
            } => service_token_revoke(&repo, &id, &database_url),
        },
        Command::Snapshot { action } => match action {
            SnapshotAction::List {
                repo,
                env,
                database_url,
            } => snapshot_list(&repo, &env, &database_url),
            SnapshotAction::Prune {
                repo,
                env,
                profile,
                keep,
                database_url,
            } => snapshot_prune(&repo, &env, &profile, keep, &database_url),
            SnapshotAction::Push {
                file,
                repo,
                url,
                env,
                profile,
                audience,
                token,
                part_size,
            } => snapshot_push(
                &file,
                &repo,
                &url,
                &env,
                &profile,
                &audience,
                token.as_deref(),
                part_size,
            ),
        },
        Command::Grant {
            repo,
            from,
            package,
            database_url,
        } => grant(&repo, &from, &package, &database_url),
        Command::Token { action } => match action {
            TokenAction::Create {
                repo,
                label,
                expires_days,
                database_url,
            } => token_create(&repo, label.as_deref(), expires_days, &database_url),
            TokenAction::List { repo, database_url } => token_list(&repo, &database_url),
            TokenAction::Revoke {
                repo,
                id,
                database_url,
            } => token_revoke(&repo, id, &database_url),
            TokenAction::Policy {
                repo,
                label,
                mode,
                cooldown_days,
                database_url,
            } => token_policy(&repo, &label, mode.as_deref(), cooldown_days, &database_url),
        },
        Command::Policy { action } => match action {
            PolicyAction::Show { repo, database_url } => policy_show(&repo, &database_url),
            PolicyAction::Set {
                repo,
                mode,
                cooldown_days,
                database_url,
            } => policy_set(&repo, &mode, cooldown_days, &database_url),
        },
        Command::Hold {
            repo,
            package,
            version,
            database_url,
        } => version_action("hold", &repo, &package, &version, &database_url),
        Command::Unhold {
            repo,
            package,
            version,
            database_url,
        } => version_action("unhold", &repo, &package, &version, &database_url),
        Command::Approve {
            repo,
            package,
            version,
            database_url,
        } => version_action("approve", &repo, &package, &version, &database_url),
    }
}

#[allow(clippy::too_many_arguments)]
fn upstream_add(
    repo: &str,
    kind: &str,
    base: &str,
    visibility: sconce_catalog::Visibility,
    label: Option<&str>,
    credential: Option<&str>,
    credential_type: &str,
    require: &[String],
    source_path: &[String],
    database_url: &str,
) -> Result<()> {
    let requires = require
        .iter()
        .map(|r| sconce_catalog::UpstreamRequire::parse(r).map_err(|e| anyhow::anyhow!(e)))
        .collect::<Result<Vec<_>>>()?;
    if kind != "git" && !source_path.is_empty() {
        anyhow::bail!("--source-path is only valid for a git upstream");
    }
    // A composer upstream must be scoped — an empty require-list would mirror the
    // whole registry. (Use `--require '*'` to opt into a require-all explicitly.)
    if kind == "composer" && requires.is_empty() {
        anyhow::bail!(
            "composer upstreams require at least one --require entry \
             (e.g. --require 'mage-os/*'; use --require '*' to mirror everything)"
        );
    }
    // Public upstreams are unauthenticated — drop any credential rather than
    // encrypting (and needlessly requiring the key) for one.
    let credential = match visibility {
        sconce_catalog::Visibility::Public => None,
        sconce_catalog::Visibility::Private => credential,
    };
    // Encrypt the credential (if any) before it touches the catalog.
    let ciphertext = match credential {
        None => None,
        Some(c) => {
            let key = sconce_catalog::secret::SecretKey::from_env()
                .context("a credential was given but SCONCE_SECRET_KEY is not set")?;
            Some(key.encrypt(c.as_bytes()))
        }
    };
    with_catalog(database_url, async |catalog| {
        let repo_id = resolve_repo(&catalog, repo).await?;
        let id = catalog
            .create_upstream(
                repo_id,
                kind,
                base,
                visibility,
                label,
                ciphertext.as_deref(),
                credential_type,
            )
            .await
            .context("creating upstream")?;
        if !requires.is_empty() {
            catalog
                .set_upstream_requires(repo_id, id, &requires)
                .await
                .context("setting mirror subscription")?;
        }
        if !source_path.is_empty() {
            catalog
                .set_upstream_source_paths(repo_id, id, source_path)
                .await
                .context("setting source paths")?;
        }
        println!("upstream added: {id}");
        Ok(())
    })
}

fn upstream_list(repo: &str, database_url: &str) -> Result<()> {
    with_catalog(database_url, async |catalog| {
        let repo_id = resolve_repo(&catalog, repo).await?;
        let ups = catalog
            .list_upstreams(repo_id)
            .await
            .context("listing upstreams")?;
        if ups.is_empty() {
            eprintln!("No upstreams for {repo}.");
        }
        for u in ups {
            let label = u.label.as_deref().unwrap_or("-");
            let cred = if u.has_credential { "auth" } else { "no-auth" };
            let reqs = if u.requires.is_empty() {
                String::new()
            } else {
                let entries: Vec<String> = u
                    .requires
                    .iter()
                    .map(sconce_catalog::UpstreamRequire::to_spec)
                    .collect();
                format!("  require=[{}]", entries.join(", "))
            };
            let paths = if u.source_paths.is_empty() {
                String::new()
            } else {
                format!("  paths=[{}]", u.source_paths.join(", "))
            };
            println!(
                "{}  [{}/{}]  {label}  ({cred})  {}{reqs}{paths}",
                u.id, u.kind, u.visibility, u.base
            );
        }
        Ok(())
    })
}

fn upstream_remove(repo: &str, id: uuid::Uuid, database_url: &str) -> Result<()> {
    with_catalog(database_url, async |catalog| {
        let repo_id = resolve_repo(&catalog, repo).await?;
        if catalog
            .delete_upstream(repo_id, id)
            .await
            .context("removing upstream")?
        {
            eprintln!("Removed upstream {id} from {repo}.");
            Ok(())
        } else {
            anyhow::bail!("no such upstream {id} in {repo}")
        }
    })
}

fn mirror_upstream(id: uuid::Uuid, cas: Option<&Path>, database_url: &str) -> Result<()> {
    use sconce_catalog::Catalog;

    // The key is only needed if the upstream stores a credential; load it
    // best-effort and let the mirror error clearly if it turns out to be needed.
    let key = sconce_catalog::secret::SecretKey::from_env().ok();
    let runtime = tokio::runtime::Runtime::new().context("starting async runtime")?;
    runtime.block_on(async {
        let store = open_store(cas)?;
        let catalog = Catalog::connect(database_url)
            .await
            .context("connecting to Postgres")?;
        catalog.migrate().await.context("applying migrations")?;

        let report = sconce_mirror::mirror_upstream(&catalog, &store, id, key.as_ref())
            .await
            .with_context(|| format!("mirroring upstream {id}"))?;
        for m in &report.mirrored {
            println!(
                "  + {} {} ({}, {})",
                m.package, m.tag, m.normalized, m.stability
            );
        }
        for (tag, reason) in &report.skipped {
            println!("  - {tag}: {reason}");
        }
        println!(
            "mirrored {} version(s), skipped {}",
            report.mirrored.len(),
            report.skipped.len()
        );
        Ok::<_, anyhow::Error>(())
    })
}

fn mirror_package(
    upstream: uuid::Uuid,
    package: &str,
    cas: Option<&Path>,
    database_url: &str,
) -> Result<()> {
    use sconce_catalog::Catalog;

    let runtime = tokio::runtime::Runtime::new().context("starting async runtime")?;
    runtime.block_on(async {
        let store = open_store(cas)?;
        let catalog = Catalog::connect(database_url)
            .await
            .context("connecting to Postgres")?;
        catalog.migrate().await.context("applying migrations")?;

        let report = sconce_mirror::mirror_composer_package(&catalog, &store, upstream, package)
            .await
            .with_context(|| format!("mirroring {package} from upstream {upstream}"))?;
        for m in &report.mirrored {
            println!("  + {} {} ({})", m.package, m.tag, m.stability);
        }
        for (ver, reason) in &report.skipped {
            println!("  - {ver}: {reason}");
        }
        println!(
            "mirrored {} version(s), skipped {}",
            report.mirrored.len(),
            report.skipped.len()
        );
        Ok::<_, anyhow::Error>(())
    })
}

fn mirror_registry(upstream: uuid::Uuid, cas: Option<&Path>, database_url: &str) -> Result<()> {
    use sconce_catalog::Catalog;

    let runtime = tokio::runtime::Runtime::new().context("starting async runtime")?;
    runtime.block_on(async {
        let store = open_store(cas)?;
        let catalog = Catalog::connect(database_url)
            .await
            .context("connecting to Postgres")?;
        catalog.migrate().await.context("applying migrations")?;

        let report = sconce_mirror::mirror_composer_upstream(&catalog, &store, upstream)
            .await
            .with_context(|| format!("mirroring registry upstream {upstream}"))?;
        // Summarize per package so a big run is readable.
        let mut by_pkg: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
        for m in &report.mirrored {
            *by_pkg.entry(m.package.as_str()).or_default() += 1;
        }
        for (pkg, n) in &by_pkg {
            println!("  + {pkg}: {n} version(s)");
        }
        for (item, reason) in &report.skipped {
            println!("  - {item}: {reason}");
        }
        println!(
            "mirrored {} version(s) across {} package(s); {} skipped",
            report.mirrored.len(),
            by_pkg.len(),
            report.skipped.len()
        );
        Ok::<_, anyhow::Error>(())
    })
}

fn deps_resolve(repo: &str, database_url: &str) -> Result<()> {
    with_catalog(database_url, async |catalog| {
        let repo_id = resolve_repo(&catalog, repo).await?;
        catalog
            .enqueue_resolve_closure_job(repo_id)
            .await
            .context("enqueueing resolve job")?;
        println!(
            "queued dependency resolution for {repo} — run `sconce worker` to compute it, then `sconce deps plan --repo {repo}`."
        );
        Ok(())
    })
}

fn package_list(repo: &str, database_url: &str) -> Result<()> {
    with_catalog(database_url, async |catalog| {
        let repo_id = resolve_repo(&catalog, repo).await?;
        let packages = catalog
            .list_packages(repo_id)
            .await
            .context("listing packages")?;
        if packages.is_empty() {
            eprintln!("No packages yet.");
        }
        for p in &packages {
            // archived masks broken; a long-stale healthy package is informational.
            let state = if p.archived {
                "archived".to_owned()
            } else if p.sync_health == "broken" {
                format!("BROKEN ({})", p.broken_reason.as_deref().unwrap_or("?"))
            } else {
                "ok".to_owned()
            };
            let last = p.last_success_at.as_deref().unwrap_or("never");
            println!(
                "{:<22} {:<8} {:<22} last-sync {last}",
                state, p.visibility, p.name
            );
        }
        Ok(())
    })
}

fn package_set_archived(
    repo: &str,
    package: &str,
    archived: bool,
    database_url: &str,
) -> Result<()> {
    with_catalog(database_url, async |catalog| {
        let repo_id = resolve_repo(&catalog, repo).await?;
        let changed = if archived {
            catalog.archive_package(repo_id, package).await
        } else {
            catalog.unarchive_package(repo_id, package).await
        }
        .context("updating archive state")?;
        if !changed {
            anyhow::bail!("no such package `{package}` in {repo}");
        }
        println!(
            "{package}: {}",
            if archived {
                "archived (frozen)"
            } else {
                "un-archived (syncing resumes)"
            }
        );
        Ok(())
    })
}

fn deps_plan(repo: &str, database_url: &str) -> Result<()> {
    with_catalog(database_url, async |catalog| {
        let repo_id = resolve_repo(&catalog, repo).await?;
        let plan = catalog
            .list_dependency_plan(repo_id)
            .await
            .context("loading plan")?;
        if plan.is_empty() {
            eprintln!("No plan yet — run `sconce deps resolve --repo {repo}` first.");
        }
        for e in &plan {
            let by = e.required_by.as_deref().unwrap_or("-");
            println!("{:<20} {:<28} (required by {by})", e.status, e.name);
        }
        Ok(())
    })
}

fn deps_add(repo: &str, package: &str, database_url: &str) -> Result<()> {
    with_catalog(database_url, async |catalog| {
        let repo_id = resolve_repo(&catalog, repo).await?;
        let entry = catalog
            .dependency_plan_entry(repo_id, package)
            .await
            .context("looking up plan entry")?
            .with_context(|| format!("'{package}' is not in the plan (run `deps resolve`)"))?;
        let upstream = entry.resolver_upstream_id.with_context(|| {
            format!(
                "'{package}' is {} — nothing to add (no resolver)",
                entry.status
            )
        })?;
        catalog
            .enqueue_mirror_package_job(upstream, package)
            .await
            .context("enqueueing mirror")?;
        println!("queued mirror of {package} — the worker will fetch it.");
        Ok(())
    })
}

/// Execute one claimed job by kind, returning a one-line summary on success or
/// a message on failure (the worker handles retry/fail uniformly).
/// A failed job, carrying whether the failure is **terminal** (stop) or should
/// be retried with backoff.
struct JobFailure {
    message: String,
    terminal: bool,
}

impl From<sconce_mirror::Error> for JobFailure {
    fn from(e: sconce_mirror::Error) -> Self {
        JobFailure {
            terminal: e.is_terminal(),
            message: e.to_string(),
        }
    }
}

/// A malformed/unroutable job: deterministic, so terminal.
fn bad_job(message: impl Into<String>) -> JobFailure {
    JobFailure {
        message: message.into(),
        terminal: true,
    }
}

async fn run_job(
    catalog: &sconce_catalog::Catalog,
    store: &sconce_cas::AnyBlobStore,
    key: Option<&sconce_catalog::secret::SecretKey>,
    job: &sconce_catalog::MirrorJob,
) -> std::result::Result<String, JobFailure> {
    match job.kind.as_str() {
        "mirror_upstream" => {
            let uid = job
                .upstream_id
                .ok_or_else(|| bad_job("job missing upstream_id"))?;
            let r = sconce_mirror::mirror_upstream(catalog, store, uid, key).await?;
            Ok(format!(
                "{} mirrored, {} skipped",
                r.mirrored.len(),
                r.skipped.len()
            ))
        }
        "mirror_package" => {
            let uid = job
                .upstream_id
                .ok_or_else(|| bad_job("job missing upstream_id"))?;
            let pkg = job
                .package
                .as_deref()
                .ok_or_else(|| bad_job("job missing package"))?;
            let r = sconce_mirror::mirror_composer_package(catalog, store, uid, pkg).await?;
            Ok(format!("{pkg}: {} version(s)", r.mirrored.len()))
        }
        "resolve_closure" => {
            let rid = job.repo_id.ok_or_else(|| bad_job("job missing repo_id"))?;
            let plan = sconce_mirror::resolve_closure(catalog, rid).await?;
            // A DB write failure here is transient — retry, don't give up.
            catalog
                .replace_dependency_plan(rid, &plan)
                .await
                .map_err(|e| JobFailure {
                    message: e.to_string(),
                    terminal: false,
                })?;
            Ok(format!("resolved {} dependencies", plan.len()))
        }
        other => Err(bad_job(format!("unknown job kind: {other}"))),
    }
}

/// Exponential backoff with ±50% jitter for a non-terminal retry: `10·2^(n-1)`
/// seconds capped at one hour, jittered so jobs sharing a downed upstream don't
/// retry in lockstep. Never gives up — the caller retries indefinitely.
fn retry_backoff_secs(attempts: i32) -> f64 {
    let base = (10.0 * 2f64.powi((attempts - 1).clamp(0, 12))).min(3600.0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let jitter = 0.5 + f64::from(nanos % 1000) / 1000.0; // [0.5, 1.5)
    base * jitter
}

fn worker(cas: Option<&Path>, database_url: &str) -> Result<()> {
    use sconce_catalog::Catalog;

    let runtime = tokio::runtime::Runtime::new().context("starting async runtime")?;
    runtime.block_on(async {
        let store = open_store(cas)?;
        let catalog = Catalog::connect(database_url)
            .await
            .context("connecting to Postgres")?;
        catalog.migrate().await.context("applying migrations")?;
        let key = sconce_catalog::secret::SecretKey::from_env().ok();
        run_worker_loop(catalog, store, key, database_url.to_owned()).await
    })
}

/// Human-readable byte count (base-1024) for GC reporting.
fn human_bytes(bytes: i64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    #[allow(clippy::cast_precision_loss)]
    let mut size = bytes.max(0) as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}

fn gc(cas: Option<&Path>, grace_hours: u64, dry_run: bool, database_url: &str) -> Result<()> {
    use sconce_cas::BlobStore;
    use sconce_catalog::Catalog;

    let grace = std::time::Duration::from_secs(grace_hours * 3600);
    let runtime = tokio::runtime::Runtime::new().context("starting async runtime")?;
    runtime.block_on(async {
        let store = open_store(cas)?;
        let catalog = Catalog::connect(database_url)
            .await
            .context("connecting to Postgres")?;
        catalog.migrate().await.context("applying migrations")?;

        let stats = catalog.storage_stats().await.context("reading storage stats")?;
        println!(
            "store: {} — {} blobs, {} total; {} orphaned ({} blobs)",
            store.describe(),
            stats.blob_count,
            human_bytes(stats.total_bytes),
            human_bytes(stats.orphan_bytes),
            stats.orphan_count,
        );

        let orphans = catalog
            .orphan_blobs(grace)
            .await
            .context("scanning for orphan blobs")?;
        if orphans.is_empty() {
            println!("nothing to collect (grace {grace_hours}h).");
            return Ok(());
        }
        if dry_run {
            println!(
                "would collect {} blob(s), {} (grace {grace_hours}h) — dry run, nothing deleted.",
                orphans.len(),
                human_bytes(orphans.iter().map(|b| b.size_bytes).sum()),
            );
            return Ok(());
        }

        // Per blob: delete the store object, then the row under a re-checked
        // guard (a blob re-referenced since the scan keeps its row and is
        // skipped). Object delete is idempotent, so a crash mid-run is safe to
        // re-run. A store error on one blob is logged and skipped, not fatal.
        let (mut freed_blobs, mut freed_bytes, mut skipped) = (0i64, 0i64, 0i64);
        for blob in &orphans {
            let id = sconce_cas::BlobId::from_bytes(blob.sha256);
            if !catalog
                .delete_blob_if_orphan(&blob.sha256, grace)
                .await
                .context("deleting blob row")?
            {
                skipped += 1; // re-referenced since the scan — leave it
                continue;
            }
            if let Err(e) = store.delete(&id) {
                // Row already gone; the object lingers as a leak. The next GC
                // finds nothing (no row), so surface it rather than swallow.
                tracing::error!(blob = %id, error = %e, "blob row removed but object delete failed");
            }
            freed_blobs += 1;
            freed_bytes += blob.size_bytes;
        }
        println!(
            "collected {freed_blobs} blob(s), freed {}{}.",
            human_bytes(freed_bytes),
            if skipped > 0 {
                format!(" ({skipped} re-referenced since scan, kept)")
            } else {
                String::new()
            },
        );
        Ok::<_, anyhow::Error>(())
    })
}

fn usage(org: Option<&str>, database_url: &str) -> Result<()> {
    use sconce_catalog::Catalog;

    let runtime = tokio::runtime::Runtime::new().context("starting async runtime")?;
    runtime.block_on(async {
        let catalog = Catalog::connect(database_url)
            .await
            .context("connecting to Postgres")?;
        catalog.migrate().await.context("applying migrations")?;

        if let Some(slug) = org {
            let org_id = catalog
                .org_id_by_slug(slug)
                .await?
                .with_context(|| format!("no such org: {slug}"))?;
            let u = catalog.org_storage(org_id).await.context("metering org")?;
            println!(
                "{slug}: {} across {} blob(s)",
                human_bytes(u.bytes),
                u.blob_count
            );
        } else {
            let rows = catalog.storage_by_org().await.context("metering orgs")?;
            let total: i64 = rows.iter().map(|o| o.usage.bytes).sum();
            for o in &rows {
                println!(
                    "{:<24} {:>10}  ({} blobs)",
                    o.org_slug,
                    human_bytes(o.usage.bytes),
                    o.usage.blob_count
                );
            }
            println!(
                "{:<24} {:>10}  (metered, dedup not credited)",
                "TOTAL",
                human_bytes(total)
            );
        }
        Ok::<_, anyhow::Error>(())
    })
}

fn entitlements(action: EntitlementsAction) -> Result<()> {
    use sconce_catalog::{Catalog, Entitlements, Feature};

    let runtime = tokio::runtime::Runtime::new().context("starting async runtime")?;
    runtime.block_on(async {
        let (org, database_url) = match &action {
            EntitlementsAction::Show { org, database_url }
            | EntitlementsAction::Set {
                org, database_url, ..
            }
            | EntitlementsAction::Clear { org, database_url } => {
                (org.clone(), database_url.clone())
            }
        };
        let catalog = Catalog::connect(&database_url)
            .await
            .context("connecting to Postgres")?;
        catalog.migrate().await.context("applying migrations")?;
        let org_id = catalog
            .org_id_by_slug(&org)
            .await?
            .with_context(|| format!("no such org: {org}"))?;

        match action {
            EntitlementsAction::Show { .. } => {
                let e = catalog.entitlements(org_id).await?;
                let explicit = catalog.has_entitlements(org_id).await?;
                println!(
                    "{org}: {}",
                    if explicit {
                        "explicit entitlements (control-plane set)"
                    } else {
                        "unlimited (no row — self-host default)"
                    }
                );
                for f in Feature::all() {
                    println!(
                        "  {:<16} {}",
                        f.as_str(),
                        if e.allows(f) { "on" } else { "off" }
                    );
                }
                println!(
                    "  {:<16} {}",
                    "max_skus",
                    e.max_skus
                        .map_or_else(|| "unlimited".to_owned(), |n| n.to_string())
                );
                println!(
                    "  {:<16} {}",
                    "storage_soft",
                    e.storage_soft_bytes
                        .map_or_else(|| "none".to_owned(), human_bytes)
                );
            }
            EntitlementsAction::Set {
                features,
                max_skus,
                storage_soft_gb,
                ..
            } => {
                let mut e = Entitlements::unlimited();
                // --features is the complete enabled set; everything else off.
                for f in Feature::all() {
                    let on = false;
                    set_feature(&mut e, f, on);
                }
                for name in features.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    let f =
                        Feature::parse(name).with_context(|| format!("unknown feature: {name}"))?;
                    set_feature(&mut e, f, true);
                }
                e.max_skus = max_skus;
                e.storage_soft_bytes =
                    storage_soft_gb.map(|gb| gb.saturating_mul(1024 * 1024 * 1024));
                catalog.set_org_entitlements(org_id, &e).await?;
                println!("entitlements set for {org}.");
            }
            EntitlementsAction::Clear { .. } => {
                let removed = catalog.clear_org_entitlements(org_id).await?;
                println!(
                    "{org}: {}",
                    if removed {
                        "entitlements cleared → unlimited"
                    } else {
                        "no entitlements row (already unlimited)"
                    }
                );
            }
        }
        Ok::<_, anyhow::Error>(())
    })
}

/// Toggle one feature flag on an [`Entitlements`] in place.
fn set_feature(e: &mut sconce_catalog::Entitlements, f: sconce_catalog::Feature, on: bool) {
    use sconce_catalog::Feature;
    match f {
        Feature::Agency => e.agency = on,
        Feature::Sso => e.sso = on,
        Feature::MultiOidc => e.multi_oidc = on,
        Feature::RepoAccess => e.repo_access = on,
        Feature::Scim => e.scim = on,
        Feature::AuditLog => e.audit_log = on,
        Feature::CustomHostname => e.custom_hostname = on,
        Feature::WhiteLabel => e.white_label = on,
    }
}

/// The worker loop: claim and run jobs, then wait on NOTIFY (with a poll
/// backstop). Runs forever; usable standalone (`sconce worker`) or spawned
/// in-process by `sconce serve`.
async fn run_worker_loop(
    catalog: sconce_catalog::Catalog,
    store: sconce_cas::AnyBlobStore,
    key: Option<sconce_catalog::secret::SecretKey>,
    database_url: String,
) -> Result<()> {
    use std::time::Duration;

    /// Re-scan even without a NOTIFY, to catch retries whose backoff elapsed and
    /// any missed notifications.
    const POLL: Duration = Duration::from_secs(30);

    {
        let mut listener = sqlx::postgres::PgListener::connect(&database_url)
            .await
            .context("opening LISTEN connection")?;
        listener
            .listen("mirror_jobs")
            .await
            .context("LISTEN mirror_jobs")?;
        tracing::info!(poll = ?POLL, "worker ready (LISTEN mirror_jobs)");

        loop {
            // Drain everything currently claimable before going back to sleep.
            while let Some(job) = catalog.claim_mirror_job().await.context("claiming job")? {
                tracing::info!(kind = %job.kind, attempt = job.attempts, "job claimed");
                let outcome = run_job(&catalog, &store, key.as_ref(), &job).await;
                match outcome {
                    Ok(summary) => {
                        catalog
                            .complete_mirror_job(job.id)
                            .await
                            .context("complete")?;
                        tracing::info!(kind = %job.kind, %summary, "job ready");
                    }
                    // Terminal: retrying won't help (source gone / access refused
                    // / bad content). Stop — the package (if any) is already
                    // flagged broken by the mirror layer.
                    Err(fail) if fail.terminal => {
                        catalog
                            .fail_mirror_job(job.id, &fail.message)
                            .await
                            .context("fail")?;
                        tracing::error!(kind = %job.kind, error = %fail.message, "job failed terminally");
                    }
                    // Non-terminal (transport / 5xx / our own infra): never give
                    // up — the upstream may recover. Back off exponentially with
                    // jitter and retry indefinitely.
                    Err(fail) => {
                        let backoff = retry_backoff_secs(job.attempts);
                        catalog
                            .retry_mirror_job(job.id, backoff, &fail.message)
                            .await
                            .context("reschedule")?;
                        tracing::warn!(
                            kind = %job.kind,
                            attempt = job.attempts,
                            retry_in_secs = backoff.round(),
                            error = %fail.message,
                            "job failed, will retry"
                        );
                    }
                }
            }
            // Idle: wake on the next NOTIFY or after the poll interval.
            tokio::select! {
                res = listener.recv() => {
                    if let Err(e) = res {
                        tracing::warn!(error = %e, "LISTEN connection error, backing off");
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
                () = tokio::time::sleep(POLL) => {}
            }
        }
    }
}

/// Open the configured blob store: S3-compatible when the `SCONCE_S3_*`
/// environment variables are set (any `--cas` directory is then ignored),
/// else the filesystem store at `--cas`.
fn open_store(cas: Option<&Path>) -> Result<sconce_cas::AnyBlobStore> {
    sconce_cas::AnyBlobStore::open(cas).context("opening blob store")
}

fn with_catalog<F>(database_url: &str, f: F) -> Result<()>
where
    F: AsyncFnOnce(sconce_catalog::Catalog) -> Result<()>,
{
    use sconce_catalog::Catalog;
    let runtime = tokio::runtime::Runtime::new().context("starting async runtime")?;
    runtime.block_on(async {
        let catalog = Catalog::connect(database_url)
            .await
            .context("connecting to Postgres")?;
        catalog.migrate().await.context("applying migrations")?;
        f(catalog).await
    })
}

/// Resolve a `<org>/<repo>` spec to a repository id, erroring if unknown.
async fn resolve_repo(catalog: &sconce_catalog::Catalog, spec: &str) -> Result<uuid::Uuid> {
    let (org, repo) = spec
        .split_once('/')
        .with_context(|| format!("--repo must be <org>/<repo>, got '{spec}'"))?;
    catalog.resolve_repo(org, repo).await?.with_context(|| {
        format!("no such repository: {spec} (create it with `sconce repo-create`)")
    })
}

fn org_create(slug: &str, name: Option<&str>, database_url: &str) -> Result<()> {
    with_catalog(database_url, async |catalog| {
        if catalog.org_slug_retired(slug).await? {
            anyhow::bail!("'{slug}' was previously used and is retired");
        }
        catalog
            .create_org(slug, name)
            .await
            .context("creating org")?;
        println!("org created: {slug}");
        Ok(())
    })
}

fn org_rename(org: &str, new_slug: &str, database_url: &str) -> Result<()> {
    with_catalog(database_url, async |catalog| {
        let org_id = catalog
            .list_organizations()
            .await
            .context("listing orgs")?
            .into_iter()
            .find(|o| o.slug == org)
            .with_context(|| format!("no such org: {org}"))?
            .id;
        catalog.rename_org(org_id, new_slug).await?;
        println!("org renamed: {org} → {new_slug} (old slug retired; still redirects)");
        Ok(())
    })
}

fn repo_rename(repo: &str, new_slug: &str, database_url: &str) -> Result<()> {
    with_catalog(database_url, async |catalog| {
        let repo_id = resolve_repo(&catalog, repo).await?;
        catalog.rename_repo(repo_id, new_slug).await?;
        println!("repo renamed to {new_slug} (old name retired; still redirects)");
        Ok(())
    })
}

fn org_settings(
    org: &str,
    allow_raw_tokens: Option<bool>,
    max_token_ttl_days: Option<i64>,
    database_url: &str,
) -> Result<()> {
    with_catalog(database_url, async |catalog| {
        let org_id = catalog
            .list_organizations()
            .await
            .context("listing orgs")?
            .into_iter()
            .find(|o| o.slug == org)
            .with_context(|| format!("no such org: {org}"))?
            .id;
        let mut cfg = catalog
            .org_settings(org_id)
            .await
            .context("loading settings")?;
        // Apply only the flags that were given; otherwise show/leave current.
        let changed = allow_raw_tokens.is_some() || max_token_ttl_days.is_some();
        if let Some(v) = allow_raw_tokens {
            cfg.allow_raw_tokens = v;
        }
        if let Some(d) = max_token_ttl_days {
            // 0 clears the cap; any positive value sets it.
            cfg.max_token_ttl_days = (d > 0).then_some(d);
        }
        if changed {
            catalog
                .set_org_settings(org_id, cfg)
                .await
                .context("saving settings")?;
        }
        let ttl = cfg
            .max_token_ttl_days
            .map_or_else(|| "no limit".to_owned(), |d| format!("{d} day(s)"));
        println!("org {org} settings:");
        println!("  allow_raw_tokens   = {}", cfg.allow_raw_tokens);
        println!("  max_token_ttl_days = {ttl}");
        Ok(())
    })
}

fn repo_settings(
    repo: &str,
    allow_raw_tokens: Option<RawTokenOverride>,
    max_token_ttl_days: Option<i64>,
    allow_private_packages: Option<bool>,
    database_url: &str,
) -> Result<()> {
    with_catalog(database_url, async |catalog| {
        let repo_id = resolve_repo(&catalog, repo).await?;
        let mut cfg = catalog
            .repo_settings(repo_id)
            .await
            .context("loading repo settings")?;
        let changed = allow_raw_tokens.is_some()
            || max_token_ttl_days.is_some()
            || allow_private_packages.is_some();
        if let Some(ov) = allow_raw_tokens {
            cfg.allow_raw_tokens = match ov {
                RawTokenOverride::Inherit => None,
                RawTokenOverride::Allow => Some(true),
                RawTokenOverride::Deny => Some(false),
            };
        }
        if let Some(d) = max_token_ttl_days {
            // 0 clears the override (inherit); positive sets it.
            cfg.max_token_ttl_days = (d > 0).then_some(d);
        }
        if let Some(v) = allow_private_packages {
            cfg.allow_private_packages = v;
        }
        if changed {
            catalog
                .set_repo_settings(repo_id, cfg)
                .await
                .context("saving repo settings")?;
        }
        // Show both the override and the effective (combined) policy.
        let effective = catalog
            .effective_token_policy(repo_id)
            .await
            .context("computing effective policy")?;
        let show_bool = |b: Option<bool>| match b {
            None => "inherit".to_owned(),
            Some(true) => "allow".to_owned(),
            Some(false) => "deny".to_owned(),
        };
        let show_ttl = |d: Option<i64>| d.map_or_else(|| "inherit".to_owned(), |d| format!("{d}"));
        let eff_ttl = effective
            .max_token_ttl_days
            .map_or_else(|| "no limit".to_owned(), |d| format!("{d} day(s)"));
        println!("repo {repo} overrides:");
        println!(
            "  allow_raw_tokens       = {}",
            show_bool(cfg.allow_raw_tokens)
        );
        println!(
            "  max_token_ttl_days     = {}",
            show_ttl(cfg.max_token_ttl_days)
        );
        println!("  allow_private_packages = {}", cfg.allow_private_packages);
        println!("effective policy:");
        println!("  allow_raw_tokens   = {}", effective.allow_raw_tokens);
        println!("  max_token_ttl_days = {eff_ttl}");
        Ok(())
    })
}

fn repo_create(org: &str, repo: &str, database_url: &str) -> Result<()> {
    with_catalog(database_url, async |catalog| {
        // A retired repo slug can't be reused (it still redirects).
        if let Some(org_id) = catalog
            .list_organizations()
            .await
            .context("listing orgs")?
            .into_iter()
            .find(|o| o.slug == org)
            .map(|o| o.id)
            && catalog.repo_slug_retired(org_id, repo).await?
        {
            anyhow::bail!("'{repo}' was previously used in {org} and is retired");
        }
        catalog
            .create_repo(org, repo)
            .await
            .with_context(|| format!("creating repo (does org '{org}' exist?)"))?;
        println!("repo created: {org}/{repo}");
        Ok(())
    })
}

fn remote_add(org: &str, remote: &str, database_url: &str) -> Result<()> {
    let normalized = sconce_catalog::normalize_git_remote(remote);
    if normalized.is_empty() {
        anyhow::bail!("'{remote}' does not look like a git remote URL");
    }
    with_catalog(database_url, async |catalog| {
        catalog
            .set_org_remote(org, &normalized)
            .await
            .with_context(|| format!("registering remote (does org '{org}' exist?)"))?;
        println!("remote registered: {normalized} -> {org}");
        Ok(())
    })
}

fn remote_list(org: &str, database_url: &str) -> Result<()> {
    with_catalog(database_url, async |catalog| {
        let org_id = catalog
            .org_id_by_slug(org)
            .await
            .context("looking up org")?
            .with_context(|| format!("no such org: {org}"))?;
        let remotes = catalog
            .remotes_for_org(org_id)
            .await
            .context("listing remotes")?;
        if remotes.is_empty() {
            println!("(no remotes registered for {org})");
        }
        for r in remotes {
            println!("{r}");
        }
        Ok(())
    })
}

fn remote_remove(remote: &str, database_url: &str) -> Result<()> {
    let normalized = sconce_catalog::normalize_git_remote(remote);
    with_catalog(database_url, async |catalog| {
        if catalog
            .delete_org_remote(&normalized)
            .await
            .context("removing remote")?
        {
            println!("remote unregistered: {normalized}");
        } else {
            println!("no such remote: {normalized}");
        }
        Ok(())
    })
}

fn remote_snapshot(
    remote: &str,
    repo: Option<&str>,
    env: &str,
    profile: Option<&str>,
    clear: bool,
    database_url: &str,
) -> Result<()> {
    let normalized = sconce_catalog::normalize_git_remote(remote);
    if normalized.is_empty() {
        anyhow::bail!("'{remote}' does not look like a git remote URL");
    }
    with_catalog(database_url, async |catalog| {
        if clear {
            if catalog
                .clear_remote_snapshot(&normalized)
                .await
                .context("clearing snapshot config")?
            {
                println!("snapshot source cleared for {normalized}");
            } else {
                println!("no such remote: {normalized}");
            }
            return Ok(());
        }
        let Some(repo) = repo else {
            anyhow::bail!(
                "pass --repo <org/repo> to set the snapshot source (or --clear to remove it)"
            );
        };
        // Resolve the dataset repo up front so an unknown repo is a clean error.
        let repo_id = resolve_repo(&catalog, repo).await?;
        if catalog
            .set_remote_snapshot(&normalized, repo_id, env, profile)
            .await
            .context("setting snapshot config")?
        {
            let profile = profile.unwrap_or("full");
            println!("snapshot source for {normalized}: {repo} ({env}/{profile})");
        } else {
            anyhow::bail!(
                "remote '{normalized}' is not registered — run `sconce remote-add <org> {remote}` first"
            );
        }
        Ok(())
    })
}

#[allow(clippy::too_many_arguments)]
fn remote_source(
    remote: &str,
    name: &str,
    host: Option<&str>,
    remote_mysql: Option<&str>,
    identity: Option<&str>,
    port: Option<u16>,
    clear: bool,
    database_url: &str,
) -> Result<()> {
    let normalized = sconce_catalog::normalize_git_remote(remote);
    if normalized.is_empty() {
        anyhow::bail!("'{remote}' does not look like a git remote URL");
    }
    with_catalog(database_url, async |catalog| {
        if clear {
            if catalog
                .clear_remote_source(&normalized, name)
                .await
                .context("clearing source")?
            {
                println!("source '{name}' cleared for {normalized}");
            } else {
                println!("no such source '{name}' on {normalized}");
            }
            return Ok(());
        }
        let Some(host) = host else {
            anyhow::bail!("pass --host <user@host> to set the source (or --clear to remove it)");
        };
        if catalog
            .set_remote_source(
                &normalized,
                name,
                host,
                remote_mysql,
                identity,
                port.map(i32::from),
            )
            .await
            .context("setting source")?
        {
            println!("source '{name}' for {normalized}: {host}");
        } else {
            anyhow::bail!(
                "remote '{normalized}' is not registered — run `sconce remote-add <org> {remote}` first"
            );
        }
        Ok(())
    })
}

fn user_create(email: &str, password: &str, superadmin: bool, database_url: &str) -> Result<()> {
    with_catalog(database_url, async |catalog| {
        catalog
            .create_user(email, password, superadmin)
            .await
            .context("creating user")?;
        println!(
            "user {email} created{}",
            if superadmin { " (superadmin)" } else { "" }
        );
        Ok(())
    })
}

#[allow(clippy::too_many_arguments)]
/// Default chunk size (and single-shot threshold) for `sconce publish`.
const DEFAULT_PART_SIZE: u64 = 32 * 1024 * 1024;

fn publish(
    dir: &Path,
    repo_path: &str,
    url: &str,
    version: Option<&str>,
    audience: &str,
    token: Option<&str>,
    part_size: Option<u64>,
) -> Result<()> {
    let base = url.trim_end_matches('/');
    let (org, repo) = repo_path
        .split_once('/')
        .context("--repo must be <org>/<repo>")?;

    // Package name from composer.json (must sit at the directory root).
    let cj_path = dir.join("composer.json");
    let cj_bytes =
        std::fs::read(&cj_path).with_context(|| format!("reading {}", cj_path.display()))?;
    let cj: serde_json::Value =
        serde_json::from_slice(&cj_bytes).context("composer.json is not valid JSON")?;
    let name = cj
        .get("name")
        .and_then(serde_json::Value::as_str)
        .context("composer.json has no \"name\" field")?;
    let (vendor, pkg) = name
        .split_once('/')
        .context("composer.json \"name\" must be vendor/name")?;

    // Version from --version or the pushed git tag.
    let version = match version {
        Some(v) => v.to_owned(),
        None => std::env::var("GITHUB_REF_NAME")
            .ok()
            .filter(|s| !s.is_empty())
            .context("no --version given and $GITHUB_REF_NAME is unset")?,
    };

    // A publish token: an explicit one, else exchange a GitHub Actions OIDC token.
    let token = match token {
        Some(t) => t.to_owned(),
        None => obtain_publish_token(base, repo_path, audience)?,
    };

    let tarball = build_targz(dir)?;
    let part_size = part_size.unwrap_or(DEFAULT_PART_SIZE).max(1);
    println!(
        "Publishing {name} {version} ({} bytes gzip) → {base}/{org}/{repo}",
        tarball.len()
    );

    let pkg_path = format!("packages/{vendor}/{pkg}/{version}");
    if u64::try_from(tarball.len()).unwrap_or(u64::MAX) <= part_size {
        let single_url = format!("{base}/{org}/{repo}/{pkg_path}");
        upload_single(&single_url, "application/tar+gzip", &token, &tarball)
    } else {
        let init_url = format!("{base}/{org}/{repo}/{pkg_path}/uploads");
        upload_chunked(base, org, repo, &init_url, &token, &tarball, part_size)
    }
}

/// `sconce snapshot push` — upload a database snapshot file as a repo+environment's
/// new `latest`, from CI. Mirrors `publish` (HTTP + OIDC), but the file is stored
/// verbatim (no tar/gzip) and it targets the `snapshots/{env}` routes.
#[allow(clippy::too_many_arguments)]
fn snapshot_push(
    file: &Path,
    repo_path: &str,
    url: &str,
    environment: &str,
    profile: &str,
    audience: &str,
    token: Option<&str>,
    part_size: Option<u64>,
) -> Result<()> {
    let base = url.trim_end_matches('/');
    let (org, repo) = repo_path
        .split_once('/')
        .context("--repo must be <org>/<repo>")?;

    let body = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;

    // A publish token: an explicit one, else exchange a GitHub Actions OIDC token.
    let token = match token {
        Some(t) => t.to_owned(),
        None => obtain_publish_token(base, repo_path, audience)?,
    };

    // The default profile stays off the URL so it keeps working against a
    // server predating profiles.
    let query = if profile == "full" {
        String::new()
    } else {
        format!("?profile={profile}")
    };
    let part_size = part_size.unwrap_or(DEFAULT_PART_SIZE).max(1);
    println!(
        "Uploading snapshot {} ({} bytes) → {base}/{org}/{repo} [{environment}/{profile}]",
        file.display(),
        body.len()
    );

    if u64::try_from(body.len()).unwrap_or(u64::MAX) <= part_size {
        let single_url = format!("{base}/{org}/{repo}/snapshots/{environment}{query}");
        upload_single(&single_url, "application/octet-stream", &token, &body)
    } else {
        let init_url = format!("{base}/{org}/{repo}/snapshots/{environment}/uploads{query}");
        upload_chunked(base, org, repo, &init_url, &token, &body, part_size)
    }
}

/// Obtain a short-lived publish token by exchanging a GitHub Actions OIDC JWT.
fn obtain_publish_token(base: &str, repo_path: &str, audience: &str) -> Result<String> {
    let req_url = std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL").unwrap_or_default();
    let req_token = std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN").unwrap_or_default();
    if req_url.is_empty() || req_token.is_empty() {
        anyhow::bail!(
            "no --token / $SCONCE_PUBLISH_TOKEN, and no GitHub Actions OIDC available \
             (the workflow needs `permissions: id-token: write`). Publishing needs a token."
        );
    }
    // 1. Ask GitHub Actions for an OIDC JWT with the audience the policy expects.
    let jwt_body = ureq::get(&req_url)
        .query("audience", audience)
        .set("Authorization", &format!("Bearer {req_token}"))
        .call()
        .map_err(publish_http_err)
        .context("requesting a GitHub OIDC token")?
        .into_string()
        .context("reading the OIDC token response")?;
    let jwt_json: serde_json::Value =
        serde_json::from_str(&jwt_body).context("parsing the OIDC token response")?;
    let jwt = jwt_json
        .get("value")
        .and_then(serde_json::Value::as_str)
        .context("OIDC token response has no \"value\"")?;

    // 2. Exchange it for a publish token.
    let exch_url = format!("{base}/oauth/ci-publish");
    let body = serde_json::to_vec(&serde_json::json!({ "repository": repo_path, "jwt": jwt }))?;
    let text = ureq::post(&exch_url)
        .set("Content-Type", "application/json")
        .send_bytes(&body)
        .map_err(publish_http_err)
        .context("exchanging the OIDC token for a publish token")?
        .into_string()
        .context("reading the exchange response")?;
    let json: serde_json::Value =
        serde_json::from_str(&text).context("parsing the exchange response")?;
    json.get("access_token")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .context("exchange response has no \"access_token\"")
}

/// Tar + gzip a package directory (contents at the archive root, symlinks preserved).
fn build_targz(dir: &Path) -> Result<Vec<u8>> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut builder = tar::Builder::new(&mut enc);
        builder.follow_symlinks(false);
        builder
            .append_dir_all(".", dir)
            .with_context(|| format!("archiving {}", dir.display()))?;
        builder.finish().context("finalizing tar")?;
    }
    enc.finish().context("finalizing gzip")
}

/// Single-shot upload: PUT the whole `body` to `single_url` with `content_type`
/// (`application/tar+gzip` for a package, `application/octet-stream` for a snapshot).
fn upload_single(single_url: &str, content_type: &str, token: &str, body: &[u8]) -> Result<()> {
    let resp = ureq::put(single_url)
        .set("Authorization", &format!("Bearer {token}"))
        .set("Content-Type", content_type)
        .send_bytes(body);
    report_publish(resp)
}

/// Resumable chunked upload: open a session at `init_url`, PUT each part to the
/// shared `…/uploads/{id}/parts/{n}` routes, and complete with the whole-file
/// sha256. `init_url` is the only endpoint-specific piece (package vs snapshot);
/// the part / status / complete routes are shared.
fn upload_chunked(
    base: &str,
    org: &str,
    repo: &str,
    init_url: &str,
    token: &str,
    body: &[u8],
    part_size: u64,
) -> Result<()> {
    let auth = format!("Bearer {token}");

    // 1. Open a session and learn the server's per-request cap.
    let init_text = ureq::post(init_url)
        .set("Authorization", &auth)
        .call()
        .map_err(publish_http_err)
        .context("opening an upload session")?
        .into_string()?;
    let init: serde_json::Value = serde_json::from_str(&init_text)?;
    let upload_id = init
        .get("upload_id")
        .and_then(serde_json::Value::as_str)
        .context("session response has no upload_id")?
        .to_owned();
    let server_limit = init
        .get("part_size_limit")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(part_size);
    let chunk = usize::try_from(part_size.min(server_limit).max(1)).unwrap_or(usize::MAX);

    // 2. Which parts are already staged (so a resumed run skips them)?
    let status_url = format!("{base}/{org}/{repo}/uploads/{upload_id}");
    let status_text = ureq::get(&status_url)
        .set("Authorization", &auth)
        .call()
        .map_err(publish_http_err)
        .context("reading session status")?
        .into_string()?;
    let status: serde_json::Value = serde_json::from_str(&status_text)?;
    let existing: std::collections::HashSet<i64> = status
        .get("parts")
        .and_then(serde_json::Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|p| p.get("part_number").and_then(serde_json::Value::as_i64))
                .collect()
        })
        .unwrap_or_default();

    // 3. Upload each part (1-based), skipping any already staged.
    let mut part_number: i64 = 0;
    for slice in body.chunks(chunk) {
        part_number += 1;
        if existing.contains(&part_number) {
            println!("  part {part_number}: already uploaded, skipping");
            continue;
        }
        let part_url = format!("{base}/{org}/{repo}/uploads/{upload_id}/parts/{part_number}");
        ureq::put(&part_url)
            .set("Authorization", &auth)
            .set("Content-Type", "application/octet-stream")
            .send_bytes(slice)
            .map_err(publish_http_err)
            .with_context(|| format!("uploading part {part_number}"))?;
        println!("  part {part_number}: {} bytes", slice.len());
    }

    // 4. Complete: the server assembles and verifies against this sha256.
    let complete_url = format!("{base}/{org}/{repo}/uploads/{upload_id}/complete");
    let cbody = serde_json::to_vec(
        &serde_json::json!({ "parts": part_number, "sha256": sha256_hex(body) }),
    )?;
    let resp = ureq::post(&complete_url)
        .set("Authorization", &auth)
        .set("Content-Type", "application/json")
        .send_bytes(&cbody);
    report_publish(resp)
}

/// Turn a publish/complete response into a success line or a friendly error.
fn report_publish(result: Result<ureq::Response, ureq::Error>) -> Result<()> {
    match result {
        Ok(r) => {
            let code = r.status();
            let body = r.into_string().unwrap_or_default();
            println!("✓ {code} {}", body.trim());
            Ok(())
        }
        Err(ureq::Error::Status(409, r)) => anyhow::bail!(
            "version already published with different contents (409): {}",
            r.into_string().unwrap_or_default().trim()
        ),
        Err(ureq::Error::Status(code, r)) => anyhow::bail!(
            "publish failed ({code}): {}",
            r.into_string().unwrap_or_default().trim()
        ),
        Err(e) => Err(anyhow::Error::new(e).context("publish request failed")),
    }
}

/// Collapse a ureq error into an anyhow error carrying the server's status + body.
fn publish_http_err(e: ureq::Error) -> anyhow::Error {
    match e {
        ureq::Error::Status(code, r) => anyhow::anyhow!(
            "server returned {code}: {}",
            r.into_string().unwrap_or_default().trim()
        ),
        err @ ureq::Error::Transport(_) => anyhow::Error::new(err),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    let digest = Sha256::digest(bytes);
    let mut s = String::with_capacity(64);
    for b in digest {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[allow(clippy::too_many_arguments)]
fn ci_policy_add(
    repo: &str,
    provider: &str,
    issuer: &str,
    audience: &str,
    claims: &[(String, String)],
    ttl_secs: i64,
    capability: &str,
    database_url: &str,
) -> Result<()> {
    if !matches!(capability, "read" | "publish") {
        anyhow::bail!("--capability must be 'read' or 'publish'");
    }
    let claims_json = serde_json::Value::Object(
        claims
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
            .collect(),
    );
    with_catalog(database_url, async |catalog| {
        let repo_id = resolve_repo(&catalog, repo).await?;
        let id = catalog
            .add_ci_policy(
                repo_id,
                provider,
                issuer,
                audience,
                &claims_json,
                ttl_secs,
                capability,
            )
            .await
            .context("adding CI policy")?;
        println!("CI policy added: {id}");
        Ok(())
    })
}

fn ci_policy_list(repo: &str, database_url: &str) -> Result<()> {
    with_catalog(database_url, async |catalog| {
        let repo_id = resolve_repo(&catalog, repo).await?;
        for p in catalog
            .ci_policies(repo_id)
            .await
            .context("listing CI policies")?
        {
            println!(
                "{}  [{}]  iss={} aud={} ttl={}s  claims={}",
                p.id, p.provider, p.issuer, p.audience, p.token_ttl_secs, p.claims
            );
        }
        Ok(())
    })
}

fn scim_token(org: &str, database_url: &str) -> Result<()> {
    with_catalog(database_url, async |catalog| {
        match catalog
            .create_scim_token(org)
            .await
            .context("creating SCIM token")?
        {
            Some(token) => {
                println!("{token}");
                eprintln!(
                    "SCIM token for org {org} — store it now (shown once). SCIM base URL: \
                     <ui-base>/scim/v2"
                );
                Ok(())
            }
            None => anyhow::bail!("no such org: {org}"),
        }
    })
}

#[allow(clippy::too_many_arguments)]
fn oidc_config(
    org: Option<&str>,
    issuer: &str,
    client_id: &str,
    client_secret: Option<&str>,
    redirect_url: &str,
    scopes: &str,
    allowed_domains: Option<&str>,
    admin_domains: Option<&str>,
    database_url: &str,
) -> Result<()> {
    // Encrypt the client secret (if any) before storing.
    let ciphertext = match client_secret {
        None => None,
        Some(s) => {
            let key = sconce_catalog::secret::SecretKey::from_env()
                .context("a client secret was given but SCONCE_SECRET_KEY is not set")?;
            Some(key.encrypt(s.as_bytes()))
        }
    };
    let split = |s: Option<&str>| {
        s.map(|v| {
            v.split(',')
                .map(str::trim)
                .filter(|x| !x.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
    };
    let conn = sconce_catalog::OidcConnection {
        id: uuid::Uuid::nil(),
        org_slug: org.map(ToOwned::to_owned),
        issuer_url: issuer.to_owned(),
        client_id: client_id.to_owned(),
        client_secret: ciphertext,
        redirect_url: redirect_url.to_owned(),
        scopes: scopes.to_owned(),
        allowed_domains: split(allowed_domains),
        admin_domains: split(admin_domains),
    };
    with_catalog(database_url, async |catalog| {
        catalog
            .set_oidc_connection(org, &conn)
            .await
            .context("saving OIDC connection")?;
        let scope = org.map_or_else(|| "instance default".to_owned(), |o| format!("org {o}"));
        println!("OIDC connection configured ({scope}, issuer {issuer}). Redirect: {redirect_url}");
        Ok(())
    })
}

fn user_grant(email: &str, tenant: &str, role: &str, database_url: &str) -> Result<()> {
    let role = match role {
        "admin" => "admin",
        "member" => "member",
        other => anyhow::bail!("role must be 'member' or 'admin', got '{other}'"),
    };
    with_catalog(database_url, async |catalog| {
        if catalog.add_user_to_tenant(email, tenant, role).await? {
            println!("granted {email} {role} of tenant {tenant}");
            Ok(())
        } else {
            anyhow::bail!("unknown user or tenant ({email} / {tenant})")
        }
    })
}

fn license_create(
    repo: &str,
    buyer: Option<&str>,
    packages: &[String],
    database_url: &str,
) -> Result<()> {
    with_catalog(database_url, async |catalog| {
        let repo_id = resolve_repo(&catalog, repo).await?;
        let pkgs: Vec<&str> = packages.iter().map(String::as_str).collect();
        let key = catalog
            .issue_license(repo_id, buyer, &pkgs)
            .await
            .context("creating license")?
            .with_context(|| format!("a package was not found in {repo} (no license created)"))?;
        // The key goes to stdout (scriptable); the notice to stderr.
        println!("{key}");
        eprintln!(
            "License created for {repo}, entitled to: {}. Store the key — shown once.",
            packages.join(", ")
        );
        Ok(())
    })
}

fn license_issue(repo: &str, edition: &str, buyer: Option<&str>, database_url: &str) -> Result<()> {
    with_catalog(database_url, async |catalog| {
        let repo_id = resolve_repo(&catalog, repo).await?;
        let ed = catalog
            .find_edition(repo_id, edition)
            .await?
            .with_context(|| format!("no edition '{edition}' in {repo}"))?;
        let issued = catalog
            .issue_from_edition(repo_id, ed, buyer, None)
            .await
            .context("issuing license")?
            .with_context(|| format!("edition '{edition}' is inactive"))?;
        let key = issued
            .key
            .context("expected a freshly-minted key (no idempotency replay from the CLI)")?;
        // The key goes to stdout (scriptable); the notice to stderr.
        println!("{key}");
        eprintln!(
            "License issued for {repo} against edition '{edition}'. Store the key — shown once."
        );
        Ok(())
    })
}

// The flags (name, slug, target, bound, snapshot, policy) are independent edition
// attributes; a params struct would just add indirection at the one call site.
#[allow(clippy::too_many_arguments)]
fn edition_create(
    repo: &str,
    name: &str,
    slug: Option<&str>,
    set: Option<&str>,
    package: Option<&str>,
    bound_spec: &str,
    snapshot: bool,
    mode: Option<&str>,
    cooldown_days: Option<i32>,
    database_url: &str,
) -> Result<()> {
    let bound = sconce_catalog::EditionBound::parse(bound_spec).map_err(|e| anyhow::anyhow!(e))?;
    // Validate the policy up front, so an invalid value fails here with a clear
    // message rather than at every later issuance (the license_keys/editions CHECK
    // constraints would otherwise reject it as an opaque DB error).
    if let Some(m) = mode {
        anyhow::ensure!(
            matches!(m, "auto" | "manual" | "delayed"),
            "--mode must be auto, manual, or delayed"
        );
    }
    if let Some(d) = cooldown_days {
        anyhow::ensure!(d >= 0, "--cooldown-days must be >= 0");
    }
    with_catalog(database_url, async |catalog| {
        let repo_id = resolve_repo(&catalog, repo).await?;
        let (org_slug, _) = repo
            .split_once('/')
            .with_context(|| format!("--repo must be <org>/<repo>, got '{repo}'"))?;
        let org_id = catalog
            .org_id_by_slug(org_slug)
            .await?
            .with_context(|| format!("no such org: {org_slug}"))?;
        // Resolve the target set: an existing named set, or a singleton for one
        // package. Exactly one of --set / --package is required.
        let set_id = match (set, package) {
            (Some(s), None) => catalog
                .list_package_sets(org_id)
                .await?
                .into_iter()
                .find(|ps| ps.name == s)
                .map(|ps| ps.id)
                .with_context(|| format!("no package set '{s}' in {org_slug}"))?,
            (None, Some(p)) => match catalog.singleton_set(org_id, p).await? {
                sconce_catalog::SingletonSet::Set(id) => id,
                sconce_catalog::SingletonSet::UnknownPackage => {
                    anyhow::bail!("no package '{p}' in {org_slug}")
                }
                sconce_catalog::SingletonSet::NameCollision => anyhow::bail!(
                    "a package set named '{p}' already exists in {org_slug} and isn't a \
                     singleton — pass --set to sell it, or rename it"
                ),
            },
            _ => anyhow::bail!("specify exactly one of --set or --package"),
        };
        let policy = sconce_catalog::PolicyOverride {
            update_mode: mode.map(str::to_owned),
            cooldown_days,
        };
        match catalog
            .create_edition(repo_id, name, slug, set_id, &bound, snapshot, &policy)
            .await
        {
            Ok(Some(id)) => {
                println!("{id}");
                eprintln!(
                    "Edition '{name}' created in {repo} (bound: {}).",
                    bound.label()
                );
                Ok(())
            }
            Ok(None) => anyhow::bail!("target set does not belong to {org_slug}"),
            Err(e) => Err(e.into()),
        }
    })
}

fn edition_list(repo: &str, database_url: &str) -> Result<()> {
    with_catalog(database_url, async |catalog| {
        let repo_id = resolve_repo(&catalog, repo).await?;
        let editions = catalog.list_editions(repo_id).await?;
        if editions.is_empty() {
            println!("no editions in {repo}");
            return Ok(());
        }
        for e in editions {
            println!(
                "{}{}  set={}  bound={}  {}{}",
                e.name,
                e.slug.map(|s| format!(" ({s})")).unwrap_or_default(),
                e.set_name,
                e.bound.label(),
                if e.snapshot { "snapshot" } else { "by-ref" },
                if e.active { "" } else { "  [inactive]" },
            );
        }
        Ok(())
    })
}

fn edition_deactivate(repo: &str, edition: &str, database_url: &str) -> Result<()> {
    with_catalog(database_url, async |catalog| {
        let repo_id = resolve_repo(&catalog, repo).await?;
        let ed = catalog
            .find_edition(repo_id, edition)
            .await?
            .with_context(|| format!("no edition '{edition}' in {repo}"))?;
        if catalog.set_edition_active(repo_id, ed, false).await? {
            println!("edition '{edition}' deactivated");
            Ok(())
        } else {
            anyhow::bail!("edition '{edition}' not found")
        }
    })
}

fn service_token_create(
    repo: &str,
    label: Option<&str>,
    expires_days: Option<i64>,
    database_url: &str,
) -> Result<()> {
    with_catalog(database_url, async |catalog| {
        let repo_id = resolve_repo(&catalog, repo).await?;
        let (token, _id) = catalog
            .create_service_token(repo_id, label, expires_days)
            .await
            .context("creating service token")?;
        // The token goes to stdout (scriptable); the notice to stderr.
        println!("{token}");
        eprintln!(
            "Service token for {repo} created. Store it — shown once. Use it as the \
             Authorization: Bearer credential for /api/v1."
        );
        Ok(())
    })
}

fn service_token_list(repo: &str, database_url: &str) -> Result<()> {
    with_catalog(database_url, async |catalog| {
        let repo_id = resolve_repo(&catalog, repo).await?;
        let tokens = catalog.list_service_tokens(repo_id).await?;
        if tokens.is_empty() {
            println!("no service tokens for {repo}");
            return Ok(());
        }
        for t in tokens {
            println!(
                "{}  {}  created={}  last_used={}  expires={}",
                t.id,
                t.label.unwrap_or_else(|| "-".to_owned()),
                t.created,
                t.last_used.unwrap_or_else(|| "never".to_owned()),
                t.expires.unwrap_or_else(|| "never".to_owned()),
            );
        }
        Ok(())
    })
}

fn snapshot_list(repo: &str, env: &str, database_url: &str) -> Result<()> {
    with_catalog(database_url, async |catalog| {
        let repo_id = resolve_repo(&catalog, repo).await?;
        let snapshots = catalog.list_snapshots(repo_id, env).await?;
        if snapshots.is_empty() {
            println!("no snapshots for {repo} [{env}]");
            return Ok(());
        }
        // Each profile has its own moving "latest"; mark them all.
        let mut latest = std::collections::HashSet::new();
        let profiles: std::collections::BTreeSet<&str> =
            snapshots.iter().map(|s| s.profile.as_str()).collect();
        for profile in profiles {
            if let Some(s) = catalog.resolve_latest(repo_id, env, profile).await? {
                latest.insert(s.id);
            }
        }
        for s in snapshots {
            let marker = if latest.contains(&s.id) { '*' } else { ' ' };
            println!(
                "{marker} {}  [{}]  {}  {} bytes  {}",
                s.id,
                s.profile,
                sconce_cas::BlobId::from_bytes(s.blob_sha256).to_hex(),
                s.size_bytes,
                s.source_ref.unwrap_or_else(|| "-".to_owned()),
            );
        }
        Ok(())
    })
}

fn snapshot_prune(
    repo: &str,
    env: &str,
    profile: &str,
    keep: i64,
    database_url: &str,
) -> Result<()> {
    with_catalog(database_url, async |catalog| {
        let repo_id = resolve_repo(&catalog, repo).await?;
        let deleted = catalog.prune_snapshots(repo_id, env, profile, keep).await?;
        println!(
            "pruned {deleted} snapshot(s) from {repo} [{env}/{profile}] (kept the newest {keep})"
        );
        eprintln!("run `sconce gc` to reclaim any now-orphaned blobs.");
        Ok(())
    })
}

fn service_token_revoke(repo: &str, id: &str, database_url: &str) -> Result<()> {
    let token_id = id
        .parse::<uuid::Uuid>()
        .with_context(|| format!("'{id}' is not a valid service-token id"))?;
    with_catalog(database_url, async |catalog| {
        let repo_id = resolve_repo(&catalog, repo).await?;
        if catalog.revoke_service_token(repo_id, token_id).await? {
            println!("service token {id} revoked");
            Ok(())
        } else {
            anyhow::bail!("no service token {id} in {repo}")
        }
    })
}

fn grant(target: &str, from: &str, package: &str, database_url: &str) -> Result<()> {
    with_catalog(database_url, async |catalog| {
        let target_id = resolve_repo(&catalog, target).await?;
        let source_id = resolve_repo(&catalog, from).await?;
        if catalog.grant_package(target_id, source_id, package).await? {
            println!("granted {package} from {from} into {target}");
            Ok(())
        } else {
            anyhow::bail!("no package '{package}' in {from}")
        }
    })
}

fn policy_show(repo: &str, database_url: &str) -> Result<()> {
    with_catalog(database_url, async |catalog| {
        let repo_id = resolve_repo(&catalog, repo).await?;
        let (mode, cooldown_days) = catalog.update_policy(repo_id).await?;
        println!("{repo}: mode={mode}, cooldown_days={cooldown_days}");
        Ok(())
    })
}

fn policy_set(repo: &str, mode: &str, cooldown_days: i32, database_url: &str) -> Result<()> {
    with_catalog(database_url, async |catalog| {
        let repo_id = resolve_repo(&catalog, repo).await?;
        catalog
            .set_update_policy(repo_id, mode, cooldown_days)
            .await
            .context("setting policy")?;
        println!("policy set for {repo}: mode={mode}, cooldown_days={cooldown_days}");
        Ok(())
    })
}

fn version_action(
    action: &str,
    repo: &str,
    package: &str,
    version: &str,
    database_url: &str,
) -> Result<()> {
    let normalized = sconce_mirror::normalize_tag(version)
        .map(|p| p.normalized)
        .with_context(|| format!("'{version}' is not a recognizable version"))?;
    with_catalog(database_url, async |catalog| {
        let repo_id = resolve_repo(&catalog, repo).await?;
        let changed = match action {
            "hold" => catalog.hold_version(repo_id, package, &normalized).await?,
            "unhold" => {
                catalog
                    .unhold_version(repo_id, package, &normalized)
                    .await?
            }
            "approve" => {
                catalog
                    .approve_version(repo_id, package, &normalized)
                    .await?
            }
            _ => unreachable!(),
        };
        if changed {
            println!("{action}: {repo} {package} {version} ({normalized})");
            Ok(())
        } else {
            anyhow::bail!("no such version: {repo} {package} {version} ({normalized})")
        }
    })
}

fn token_create(
    repo: &str,
    label: Option<&str>,
    expires_days: Option<i64>,
    database_url: &str,
) -> Result<()> {
    with_catalog(database_url, async |catalog| {
        let repo_id = resolve_repo(&catalog, repo).await?;
        let token = catalog
            .create_token(repo_id, label, expires_days)
            .await
            .context("creating token")?;
        // The token itself goes to stdout (scriptable); the notice to stderr.
        println!("{token}");
        eprintln!("Token created for {repo} — store it now; it will not be shown again.");
        Ok(())
    })
}

fn token_list(repo: &str, database_url: &str) -> Result<()> {
    with_catalog(database_url, async |catalog| {
        let repo_id = resolve_repo(&catalog, repo).await?;
        let tokens = catalog
            .list_tokens(repo_id)
            .await
            .context("listing tokens")?;
        if tokens.is_empty() {
            eprintln!("No tokens for {repo}.");
        }
        for t in tokens {
            let label = t.label.as_deref().unwrap_or("-");
            let expires = match (t.expires.as_deref(), t.expired) {
                (Some(d), true) => format!("expired {d}"),
                (Some(d), false) => format!("expires {d}"),
                (None, _) => "never expires".to_owned(),
            };
            let last = t.last_used.as_deref().unwrap_or("never used");
            let policy = match (t.policy.update_mode.as_deref(), t.policy.cooldown_days) {
                (None, None) => String::new(),
                (m, c) => format!(
                    "  policy={}/{}",
                    m.unwrap_or("inherit"),
                    c.map_or_else(|| "-".to_owned(), |d| d.to_string())
                ),
            };
            println!(
                "{}  {label}  [{}]  ({expires}; {last}){policy}",
                t.id, t.origin
            );
        }
        Ok(())
    })
}

fn token_policy(
    repo: &str,
    label: &str,
    mode: Option<&str>,
    cooldown_days: Option<i32>,
    database_url: &str,
) -> Result<()> {
    if let Some(m) = mode {
        anyhow::ensure!(
            matches!(m, "auto" | "manual" | "delayed"),
            "--mode must be auto, manual, or delayed"
        );
    }
    let policy = sconce_catalog::PolicyOverride {
        update_mode: mode.map(ToOwned::to_owned),
        cooldown_days,
    };
    with_catalog(database_url, async |catalog| {
        let repo_id = resolve_repo(&catalog, repo).await?;
        let changed = catalog
            .set_token_policy(repo_id, label, &policy)
            .await
            .context("setting token policy")?;
        anyhow::ensure!(changed, "no token labelled `{label}` in {repo}");
        if policy.is_some() {
            println!("token `{label}`: policy set (tighten-only at serve time)");
        } else {
            println!("token `{label}`: policy cleared (inherits the repo)");
        }
        Ok(())
    })
}

fn token_revoke(repo: &str, id: uuid::Uuid, database_url: &str) -> Result<()> {
    with_catalog(database_url, async |catalog| {
        let repo_id = resolve_repo(&catalog, repo).await?;
        if catalog
            .revoke_token(repo_id, id)
            .await
            .context("revoking token")?
        {
            eprintln!("Revoked token {id} from {repo}.");
            Ok(())
        } else {
            anyhow::bail!("no such token {id} in {repo}")
        }
    })
}

#[allow(clippy::too_many_arguments)]
fn serve(
    cas: Option<&Path>,
    database_url: &str,
    listen: std::net::SocketAddr,
    base_url: String,
    no_worker: bool,
    ui_listen: Option<std::net::SocketAddr>,
    single_tenant: bool,
    admin_password: Option<String>,
) -> Result<()> {
    use sconce_catalog::Catalog;

    let runtime = tokio::runtime::Runtime::new().context("starting async runtime")?;
    runtime.block_on(async {
        let store = open_store(cas)?;
        let catalog = Catalog::connect(database_url)
            .await
            .context("connecting to Postgres")?;
        catalog.migrate().await.context("applying migrations")?;

        // In-process worker (the single-binary story); disable with --no-worker
        // when running a dedicated `sconce worker` instead.
        if no_worker {
            tracing::info!("in-process worker disabled (--no-worker)");
        } else {
            let wcat = catalog.clone();
            let wstore = store.clone();
            let durl = database_url.to_owned();
            let key = sconce_catalog::secret::SecretKey::from_env().ok();
            tokio::spawn(async move {
                if let Err(e) = run_worker_loop(wcat, wstore, key, durl).await {
                    tracing::error!(error = format!("{e:#}"), "worker loop exited");
                }
            });
        }

        // Optional in-process admin UI on its own port.
        if let Some(ui_addr) = ui_listen {
            let ucat = catalog.clone();
            let ubase = base_url.clone();
            let apw = admin_password;
            tokio::spawn(async move {
                tracing::info!("admin UI on http://{ui_addr}");
                if let Err(e) =
                    sconce_server::ui::serve(ucat, ubase, single_tenant, apw, ui_addr).await
                {
                    tracing::error!(error = %e, "ui server exited");
                }
            });
        }

        tracing::info!(
            store = store.describe(),
            "serving on http://{listen} (base url: {base_url})"
        );
        sconce_server::serve(catalog, store, base_url, listen)
            .await
            .context("serving")?;
        Ok::<_, anyhow::Error>(())
    })
}

fn ui(
    database_url: &str,
    listen: std::net::SocketAddr,
    public_base_url: String,
    single_tenant: bool,
    admin_password: Option<String>,
) -> Result<()> {
    use sconce_catalog::Catalog;

    let runtime = tokio::runtime::Runtime::new().context("starting async runtime")?;
    runtime.block_on(async {
        let catalog = Catalog::connect(database_url)
            .await
            .context("connecting to Postgres")?;
        catalog.migrate().await.context("applying migrations")?;
        if single_tenant {
            if admin_password.is_none() {
                tracing::warn!(
                    "single-tenant with no --admin-password; the admin UI is open (bind to localhost)"
                );
            }
        } else if catalog.user_count().await? == 0 {
            tracing::warn!(
                "no users exist; create the first one with `sconce user-create --superadmin <email> <password>`"
            );
        }
        tracing::info!("admin UI on http://{listen}");
        sconce_server::ui::serve(catalog, public_base_url, single_tenant, admin_password, listen)
            .await
            .context("serving UI")?;
        Ok::<_, anyhow::Error>(())
    })
}

fn mirror(
    source: &Path,
    repo: &str,
    git_url: &str,
    cas: Option<&Path>,
    database_url: &str,
) -> Result<()> {
    use sconce_catalog::Catalog;

    // The mirror path is async (Postgres); spin a runtime just for it rather
    // than making the whole CLI async.
    let runtime = tokio::runtime::Runtime::new().context("starting async runtime")?;
    runtime.block_on(async {
        let store = open_store(cas)?;
        let catalog = Catalog::connect(database_url)
            .await
            .context("connecting to Postgres")?;
        catalog.migrate().await.context("applying migrations")?;
        let repo_id = resolve_repo(&catalog, repo).await?;

        let report = sconce_mirror::mirror_git_source(repo_id, source, git_url, &store, &catalog)
            .await
            .with_context(|| format!("mirroring {} into {repo}", source.display()))?;

        for m in &report.mirrored {
            println!(
                "  + {} {} ({}, {})",
                m.package, m.tag, m.normalized, m.stability
            );
        }
        for (tag, reason) in &report.skipped {
            println!("  - {tag}: {reason}");
        }
        println!(
            "mirrored {} version(s), skipped {}",
            report.mirrored.len(),
            report.skipped.len()
        );
        Ok::<_, anyhow::Error>(())
    })
}

fn ingest(repo: &Path, refspec: &str, cas: Option<&Path>) -> Result<()> {
    use sconce_cas::BlobStore;

    let archive = sconce_git::archive_ref(repo, refspec)
        .with_context(|| format!("archiving {} at {refspec}", repo.display()))?;
    let count = archive.len();
    let bytes = archive.into_zip();

    let store = open_store(cas)?;
    let existed = store.exists(&sconce_cas::BlobId::of(&bytes))?;
    let id = store.put(&bytes).context("storing blob")?;

    println!(
        "ingested {} entries from {}@{refspec} → blob {id} ({} bytes){}",
        count,
        repo.display(),
        bytes.len(),
        if existed {
            " [already present — deduped]"
        } else {
            ""
        }
    );
    Ok(())
}

fn archive_ref(repo: &Path, refspec: &str, out: &Path) -> Result<()> {
    let archive = sconce_git::archive_ref(repo, refspec)
        .with_context(|| format!("archiving {} at {refspec}", repo.display()))?;
    let count = archive.len();
    let bytes = archive.into_zip();
    std::fs::write(out, &bytes).with_context(|| format!("writing {}", out.display()))?;
    println!(
        "archived {count} entries from {}@{refspec} → {} ({} bytes)",
        repo.display(),
        out.display(),
        bytes.len(),
    );
    Ok(())
}

fn archive(src: &Path, out: &Path) -> Result<()> {
    let mut archive = CanonicalArchive::new();
    let mut count = 0usize;
    walk(src, src, &mut archive, &mut count)
        .with_context(|| format!("walking {}", src.display()))?;
    let bytes = archive.into_zip();
    std::fs::write(out, &bytes).with_context(|| format!("writing {}", out.display()))?;
    println!(
        "archived {count} entries → {} ({} bytes)",
        out.display(),
        bytes.len()
    );
    Ok(())
}

/// Recursively collect files/symlinks under `dir` into `archive`, keyed by their
/// path relative to `root`. Directory entries are not emitted (implied by
/// paths). `.git` is skipped. Sorting/canonicalization happens in the archiver.
fn walk(root: &Path, dir: &Path, archive: &mut CanonicalArchive, count: &mut usize) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;

        // Skip VCS metadata — never part of a package's content.
        if file_type.is_dir() && entry.file_name() == ".git" {
            continue;
        }

        let rel = path
            .strip_prefix(root)
            .expect("walked path is under root")
            .to_string_lossy()
            .into_owned();

        if file_type.is_symlink() {
            let target = std::fs::read_link(&path)?;
            archive.add(Entry::new(
                rel,
                Mode::Symlink,
                target.to_string_lossy().as_bytes().to_vec(),
            ));
            *count += 1;
        } else if file_type.is_dir() {
            walk(root, &path, archive, count)?;
        } else if file_type.is_file() {
            let content = std::fs::read(&path)?;
            archive.add(Entry::new(rel, file_mode(&path)?, content));
            *count += 1;
        }
        // Other node kinds (sockets, fifos, devices) are not package content.
    }
    Ok(())
}

/// Map a regular file to the canonical [`Mode`] by its executable bit. On
/// non-Unix hosts (no permission bits) everything is a regular file.
fn file_mode(path: &Path) -> Result<Mode> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode();
        Ok(if mode & 0o111 != 0 {
            Mode::Executable
        } else {
            Mode::File
        })
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(Mode::File)
    }
}

#[cfg(test)]
mod tests {
    use super::retry_backoff_secs;

    #[test]
    fn backoff_grows_then_caps_with_jitter() {
        // First attempt: 10s base ±50% jitter.
        let b1 = retry_backoff_secs(1);
        assert!((5.0..=15.0).contains(&b1), "attempt 1: {b1}");
        // Roughly doubles early on (compare the jitter-free base via many samples'
        // minimum is hard; just assert ordering of the lower bounds holds).
        assert!(retry_backoff_secs(2) >= 5.0 && retry_backoff_secs(3) >= 5.0);
        // Capped at one hour even for absurd attempt counts (no overflow/panic).
        for n in [12, 20, 1000, i32::MAX] {
            let b = retry_backoff_secs(n);
            assert!(
                b.is_finite() && (1800.0..=5400.0).contains(&b),
                "attempt {n}: {b}"
            );
        }
    }
}
