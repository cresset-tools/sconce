//! Read a git tree at a ref into a [`CanonicalArchive`].
//!
//! This is sconce's real package source. We archive from the **git object
//! database**, not a working-copy checkout, because the tree gives us canonical
//! data a checkout corrupts:
//!
//! - **Modes** are already canonical in git — only `blob` (regular), `blob`
//!   with the executable bit, `link` (symlink), and `commit` (submodule). No
//!   umask, no filesystem permission drift.
//! - **Content** is the exact blob bytes — no eol/smudge filters, no checkout
//!   mtimes.
//!
//! Combined with the deterministic [`CanonicalArchive`], the same `(repo, ref)`
//! always yields byte-identical archive output.
//!
//! Submodules (`commit` entries) carry no content at the ref and are skipped,
//! matching `git archive`.
//!
//! **Not yet handled:** `.gitattributes export-ignore` / `export-subst` (the
//! next step — gives full `git archive` content parity).

use gix::bstr::ByteSlice;
use gix::objs::tree::EntryKind;
use sconce_archive::{CanonicalArchive, Entry, Mode};

/// Errors reading a git tree.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("opening git repository")]
    Open(Box<gix::open::Error>),
    #[error("resolving ref {refspec:?}")]
    RevParse {
        refspec: String,
        #[source]
        source: Box<gix::revision::spec::parse::single::Error>,
    },
    #[error("peeling {refspec:?} to a tree")]
    PeelToTree {
        refspec: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("traversing the tree")]
    Traverse(Box<gix::traverse::tree::breadthfirst::Error>),
    #[error("reading object {oid}")]
    FindObject {
        oid: gix::ObjectId,
        #[source]
        source: Box<gix::object::find::existing::Error>,
    },
    #[error("a tree path was not valid UTF-8: {path:?}")]
    NonUtf8Path { path: String },
}

/// Build a [`CanonicalArchive`] from the tree that `refspec` resolves to in the
/// repository at `repo_path` (e.g. `"HEAD"`, `"v1.2.0"`, a commit sha).
///
/// `refspec` is peeled to a tree, so tags and commits both work.
pub fn archive_ref(
    repo_path: impl AsRef<std::path::Path>,
    refspec: &str,
) -> Result<CanonicalArchive, Error> {
    let repo = gix::open(repo_path.as_ref()).map_err(|e| Error::Open(Box::new(e)))?;

    let id = repo
        .rev_parse_single(refspec)
        .map_err(|source| Error::RevParse {
            refspec: refspec.to_owned(),
            source: Box::new(source),
        })?;
    let tree = id
        .object()
        .map_err(|source| Error::PeelToTree {
            refspec: refspec.to_owned(),
            source: Box::new(source),
        })?
        .peel_to_tree()
        .map_err(|source| Error::PeelToTree {
            refspec: refspec.to_owned(),
            source: Box::new(source),
        })?;

    // `Recorder` walks the whole tree and yields every entry with its full path,
    // mode, and oid — exactly what we need to materialize the file set.
    let mut recorder = gix::traverse::tree::Recorder::default();
    tree.traverse()
        .breadthfirst(&mut recorder)
        .map_err(|e| Error::Traverse(Box::new(e)))?;

    let mut archive = CanonicalArchive::new();
    for record in recorder.records {
        let mode = match record.mode.kind() {
            EntryKind::Blob => Mode::File,
            EntryKind::BlobExecutable => Mode::Executable,
            EntryKind::Link => Mode::Symlink,
            // Directories are implied by paths; submodules carry no content here.
            EntryKind::Tree | EntryKind::Commit => continue,
        };

        let path = record
            .filepath
            .to_str()
            .map_err(|_| Error::NonUtf8Path {
                path: record.filepath.to_string(),
            })?
            .to_owned();

        // Content: for blobs it's the file bytes; for symlinks it's the link
        // target (git stores the target as the blob's content).
        let object = repo
            .find_object(record.oid)
            .map_err(|source| Error::FindObject {
                oid: record.oid,
                source: Box::new(source),
            })?;

        archive.add(Entry::new(path, mode, object.data.clone()));
    }

    Ok(archive)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// Build a throwaway git repo in `dir` with a known tree and return nothing;
    /// commits are made with pinned identity so the test is hermetic. (The
    /// archive output is independent of commit metadata anyway — content comes
    /// from the tree — but pinning avoids depending on the host git config.)
    fn init_fixture_repo(dir: &std::path::Path) {
        let git = |args: &[&str]| {
            let status = Command::new("git")
                .args(args)
                .current_dir(dir)
                .env("GIT_AUTHOR_NAME", "t")
                .env("GIT_AUTHOR_EMAIL", "t@e")
                .env("GIT_COMMITTER_NAME", "t")
                .env("GIT_COMMITTER_EMAIL", "t@e")
                .status()
                .expect("run git");
            assert!(status.success(), "git {args:?} failed");
        };

        git(&["init", "-q", "-b", "main"]);
        std::fs::create_dir(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/Foo.php"), b"<?php\nclass Foo {}\n").unwrap();
        std::fs::write(dir.join("README.md"), b"# demo\n").unwrap();
        std::fs::write(dir.join("run.sh"), b"#!/bin/sh\necho hi\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.join("run.sh"), std::fs::Permissions::from_mode(0o755))
                .unwrap();
            std::os::unix::fs::symlink("src/Foo.php", dir.join("link")).unwrap();
        }
        git(&["add", "-A"]);
        git(&["commit", "-qm", "fixture"]);
    }

    fn tempdir() -> std::path::PathBuf {
        // A unique dir without pulling in a tempfile dep: process id + a
        // per-call counter, so parallel tests never share a path.
        use std::sync::atomic::{AtomicUsize, Ordering};
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut p = std::env::temp_dir();
        p.push(format!("sconce-git-test-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn archives_a_ref_with_canonical_modes() {
        let dir = tempdir();
        init_fixture_repo(&dir);

        let zip = archive_ref(&dir, "HEAD").expect("archive HEAD").into_zip();

        // Valid zip, deterministic, and content-bearing.
        assert_eq!(&zip[0..4], &[b'P', b'K', 0x03, 0x04], "is a zip");
        let again = archive_ref(&dir, "HEAD").expect("archive again").into_zip();
        assert_eq!(zip, again, "same (repo, ref) → identical bytes");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn skips_dot_git_and_keeps_committed_files_only() {
        let dir = tempdir();
        init_fixture_repo(&dir);

        let archive = archive_ref(&dir, "HEAD").expect("archive HEAD");
        // README, src/Foo.php, run.sh, and (on unix) the symlink — never .git.
        let expected = if cfg!(unix) { 4 } else { 3 };
        assert_eq!(
            archive.len(),
            expected,
            "only committed tree entries, no .git"
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
