//! `sconce` — a fast, Composer-compatible static repository generator.
//!
//! This binary is in its earliest form: it exposes the deterministic archiver
//! ([`sconce_archive`]) over a directory tree, which is the primitive the
//! content-addressed store and the whole repository builder are built on. The
//! repository-generation commands (`build`, `serve`, mirroring) land on top of
//! this foundation.

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
    /// dedup. (Git-tree sourcing + `.gitattributes export-ignore` arrive with
    /// the mirror pipeline; this command archives a plain directory.)
    Archive {
        /// Directory to archive.
        src: PathBuf,
        /// Output `.zip` path.
        out: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Archive { src, out } => archive(&src, &out),
    }
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
