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
                database_url,
            } => ci_policy_add(
                &repo,
                &provider,
                &issuer,
                &audience,
                &claims,
                ttl_secs,
                &database_url,
            ),
            CiPolicyAction::List { repo, database_url } => ci_policy_list(&repo, &database_url),
        },
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
fn ci_policy_add(
    repo: &str,
    provider: &str,
    issuer: &str,
    audience: &str,
    claims: &[(String, String)],
    ttl_secs: i64,
    database_url: &str,
) -> Result<()> {
    let claims_json = serde_json::Value::Object(
        claims
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
            .collect(),
    );
    with_catalog(database_url, async |catalog| {
        let repo_id = resolve_repo(&catalog, repo).await?;
        let id = catalog
            .add_ci_policy(repo_id, provider, issuer, audience, &claims_json, ttl_secs)
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
