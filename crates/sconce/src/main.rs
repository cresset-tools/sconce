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
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Archive { src, out } => archive(&src, &out),
        Command::ArchiveRef { repo, r#ref, out } => archive_ref(&repo, &r#ref, &out),
        Command::Ingest { repo, r#ref, cas } => ingest(&repo, &r#ref, &cas),
    }
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
