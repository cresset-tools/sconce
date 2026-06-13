//! `sconce` — a self-hostable, Composer-compatible private repository.
//!
//! This binary is in its earliest form: it exposes the deterministic archiver
//! ([`sconce_archive`]), the git-tree reader ([`sconce_git`]), and the
//! content-addressed store ([`sconce_cas`]) over the command line. The catalog,
//! mirror workers, and dynamic Composer serving land on top of this foundation.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
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
        /// Directory of the content-addressed store.
        #[arg(long)]
        cas: PathBuf,
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
        /// Directory of the content-addressed store.
        #[arg(long)]
        cas: PathBuf,
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

    /// Create a repository in an organization.
    RepoCreate {
        /// Organization slug.
        org: String,
        /// Repository slug.
        repo: String,
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
        /// Directory of the content-addressed store.
        #[arg(long)]
        cas: PathBuf,
        /// Postgres connection string.
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
        /// Address to listen on.
        #[arg(long, default_value = "127.0.0.1:8080")]
        listen: std::net::SocketAddr,
        /// Public base URL emitted in metadata/dist URLs.
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        base_url: String,
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
enum TokenAction {
    /// Create a new token for a repository and print it once.
    Create {
        /// Repository, as `<org>/<repo>`.
        #[arg(long)]
        repo: String,
        /// Optional human label.
        #[arg(long)]
        label: Option<String>,
        /// Postgres connection string.
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Archive { src, out } => archive(&src, &out),
        Command::ArchiveRef { repo, r#ref, out } => archive_ref(&repo, &r#ref, &out),
        Command::Ingest { repo, r#ref, cas } => ingest(&repo, &r#ref, &cas),
        Command::Mirror {
            source,
            repo,
            git_url,
            cas,
            database_url,
        } => mirror(&source, &repo, &git_url, &cas, &database_url),
        Command::Serve {
            cas,
            database_url,
            listen,
            base_url,
        } => serve(&cas, &database_url, listen, base_url),
        Command::OrgCreate {
            slug,
            name,
            database_url,
        } => org_create(&slug, name.as_deref(), &database_url),
        Command::RepoCreate {
            org,
            repo,
            database_url,
        } => repo_create(&org, &repo, &database_url),
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
                database_url,
            } => token_create(&repo, label.as_deref(), &database_url),
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
        catalog
            .create_org(slug, name)
            .await
            .context("creating org")?;
        println!("org created: {slug}");
        Ok(())
    })
}

fn repo_create(org: &str, repo: &str, database_url: &str) -> Result<()> {
    with_catalog(database_url, async |catalog| {
        catalog
            .create_repo(org, repo)
            .await
            .with_context(|| format!("creating repo (does org '{org}' exist?)"))?;
        println!("repo created: {org}/{repo}");
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

fn token_create(repo: &str, label: Option<&str>, database_url: &str) -> Result<()> {
    with_catalog(database_url, async |catalog| {
        let repo_id = resolve_repo(&catalog, repo).await?;
        let token = catalog
            .create_token(repo_id, label)
            .await
            .context("creating token")?;
        // The token itself goes to stdout (scriptable); the notice to stderr.
        println!("{token}");
        eprintln!("Token created for {repo} — store it now; it will not be shown again.");
        Ok(())
    })
}

fn serve(
    cas: &Path,
    database_url: &str,
    listen: std::net::SocketAddr,
    base_url: String,
) -> Result<()> {
    use sconce_cas::FsBlobStore;
    use sconce_catalog::Catalog;

    let runtime = tokio::runtime::Runtime::new().context("starting async runtime")?;
    runtime.block_on(async {
        let store =
            FsBlobStore::open(cas).with_context(|| format!("opening CAS at {}", cas.display()))?;
        let catalog = Catalog::connect(database_url)
            .await
            .context("connecting to Postgres")?;
        catalog.migrate().await.context("applying migrations")?;

        println!("sconce serving on http://{listen} (base url: {base_url})");
        sconce_server::serve(catalog, store, base_url, listen)
            .await
            .context("serving")?;
        Ok::<_, anyhow::Error>(())
    })
}

fn mirror(source: &Path, repo: &str, git_url: &str, cas: &Path, database_url: &str) -> Result<()> {
    use sconce_cas::FsBlobStore;
    use sconce_catalog::Catalog;

    // The mirror path is async (Postgres); spin a runtime just for it rather
    // than making the whole CLI async.
    let runtime = tokio::runtime::Runtime::new().context("starting async runtime")?;
    runtime.block_on(async {
        let store =
            FsBlobStore::open(cas).with_context(|| format!("opening CAS at {}", cas.display()))?;
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

fn ingest(repo: &Path, refspec: &str, cas: &Path) -> Result<()> {
    use sconce_cas::{BlobStore, FsBlobStore};

    let archive = sconce_git::archive_ref(repo, refspec)
        .with_context(|| format!("archiving {} at {refspec}", repo.display()))?;
    let count = archive.len();
    let bytes = archive.into_zip();

    let store =
        FsBlobStore::open(cas).with_context(|| format!("opening CAS at {}", cas.display()))?;
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
