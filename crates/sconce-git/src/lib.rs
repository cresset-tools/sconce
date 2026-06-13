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
//! **`.gitattributes export-ignore`** is honored, matching `git archive` (and
//! therefore what a real Composer dist contains): paths — and whole directories
//! — marked `export-ignore` are dropped. The attributes are read from the tree
//! being archived (not the worktree's `HEAD`), so archiving an old tag uses that
//! tag's `.gitattributes`. Submodules (`commit` entries) carry no content and
//! are skipped, also matching `git archive`.
//!
//! **Not yet handled:** `export-subst` keyword substitution (rare; a later step).

use std::collections::HashSet;

use gix::bstr::{BStr, ByteSlice};
use gix::objs::tree::EntryKind;
use gix::worktree::stack::state::attributes::Source;
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
    #[error("evaluating .gitattributes export-ignore")]
    Attributes(Box<dyn std::error::Error + Send + Sync>),
    #[error("listing tags")]
    Refs(Box<dyn std::error::Error + Send + Sync>),
    #[error("reading {path:?} at {refspec:?}")]
    ReadFile {
        refspec: String,
        path: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("reading object {oid}")]
    FindObject {
        oid: gix::ObjectId,
        #[source]
        source: Box<gix::object::find::existing::Error>,
    },
    #[error("reading commit time of {refspec:?}")]
    CommitTime {
        refspec: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("a tree path was not valid UTF-8: {path:?}")]
    NonUtf8Path { path: String },
}

/// Build a [`CanonicalArchive`] from the tree that `refspec` resolves to in the
/// repository at `repo_path` (e.g. `"HEAD"`, `"v1.2.0"`, a commit sha).
///
/// `refspec` is peeled to a tree, so tags and commits both work. Paths marked
/// `export-ignore` in the tree's `.gitattributes` are excluded.
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
    let tree_id = tree.id;

    // Attribute stack that reads `.gitattributes` from the tree itself (via an
    // index synthesized from it), so we honor export-ignore against the exact
    // ref being archived rather than the worktree.
    let index = repo
        .index_from_tree(&tree_id)
        .map_err(|e| Error::Attributes(Box::new(e)))?;
    let mut stack = repo
        .attributes_only(&index, Source::IdMapping)
        .map_err(|e| Error::Attributes(Box::new(e)))?;
    let mut outcome = stack.selected_attribute_matches(["export-ignore"]);

    // `Recorder` walks the whole tree breadth-first and yields every entry with
    // its full path, mode, and oid. Breadth-first means a directory is visited
    // before its contents, so we can collect export-ignored directories and skip
    // anything beneath them.
    let mut recorder = gix::traverse::tree::Recorder::default();
    tree.traverse()
        .breadthfirst(&mut recorder)
        .map_err(|e| Error::Traverse(Box::new(e)))?;

    let mut ignored_dirs: HashSet<Vec<u8>> = HashSet::new();
    let mut archive = CanonicalArchive::new();

    for record in &recorder.records {
        let ignored = export_ignored(
            &mut stack,
            &mut outcome,
            record.filepath.as_bstr(),
            record.mode,
        )?;

        let mode = match record.mode.kind() {
            EntryKind::Blob => Mode::File,
            EntryKind::BlobExecutable => Mode::Executable,
            EntryKind::Link => Mode::Symlink,
            EntryKind::Tree => {
                if ignored {
                    ignored_dirs.insert(record.filepath.to_vec());
                }
                continue;
            }
            // Submodules carry no content at the ref.
            EntryKind::Commit => continue,
        };

        if ignored || has_ignored_ancestor(record.filepath.as_bstr(), &ignored_dirs) {
            continue;
        }

        let path = record
            .filepath
            .to_str()
            .map_err(|_| Error::NonUtf8Path {
                path: record.filepath.to_string(),
            })?
            .to_owned();

        // Content: blob bytes, or — for symlinks — the link target (git stores
        // the target as the blob's content).
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

/// List the short names of all tags in the repository (e.g. `"v1.2.0"`), the
/// versions a mirror enumerates. Order is unspecified.
pub fn tags(repo_path: impl AsRef<std::path::Path>) -> Result<Vec<String>, Error> {
    let repo = gix::open(repo_path.as_ref()).map_err(|e| Error::Open(Box::new(e)))?;
    let platform = repo.references().map_err(|e| Error::Refs(Box::new(e)))?;
    let mut out = Vec::new();
    for reference in platform.tags().map_err(|e| Error::Refs(Box::new(e)))? {
        let reference = reference.map_err(Error::Refs)?;
        let short = reference.name().shorten();
        let name = short.to_str().map_err(|_| Error::NonUtf8Path {
            path: short.to_string(),
        })?;
        out.push(name.to_owned());
    }
    Ok(out)
}

/// The committer time (unix seconds) of the commit `refspec` resolves to — used
/// as a version's upstream release time, which drives cooldown policy.
pub fn commit_time(repo_path: impl AsRef<std::path::Path>, refspec: &str) -> Result<i64, Error> {
    let repo = gix::open(repo_path.as_ref()).map_err(|e| Error::Open(Box::new(e)))?;
    let err = |source: Box<dyn std::error::Error + Send + Sync>| Error::CommitTime {
        refspec: refspec.to_owned(),
        source,
    };
    let id = repo
        .rev_parse_single(refspec)
        .map_err(|source| Error::RevParse {
            refspec: refspec.to_owned(),
            source: Box::new(source),
        })?;
    let commit = id
        .object()
        .map_err(|e| err(Box::new(e)))?
        .peel_to_commit()
        .map_err(|e| err(Box::new(e)))?;
    Ok(commit.time().map_err(|e| err(Box::new(e)))?.seconds)
}

/// Read a file's bytes at `refspec`, or `None` if no such file exists there.
/// Used to pull `composer.json` from each tag during mirroring.
pub fn read_file(
    repo_path: impl AsRef<std::path::Path>,
    refspec: &str,
    path: &str,
) -> Result<Option<Vec<u8>>, Error> {
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

    let read_err = |source: Box<dyn std::error::Error + Send + Sync>| Error::ReadFile {
        refspec: refspec.to_owned(),
        path: path.to_owned(),
        source,
    };
    match tree
        .lookup_entry_by_path(path)
        .map_err(|e| read_err(Box::new(e)))?
    {
        Some(entry) => {
            let object = entry.object().map_err(|e| read_err(Box::new(e)))?;
            Ok(Some(object.data.clone()))
        }
        None => Ok(None),
    }
}

/// Whether `path` (with tree `mode`) has `export-ignore` set in `.gitattributes`.
fn export_ignored(
    stack: &mut gix::AttributeStack<'_>,
    outcome: &mut gix::attrs::search::Outcome,
    path: &BStr,
    mode: gix::objs::tree::EntryMode,
) -> Result<bool, Error> {
    outcome.reset();
    let platform = stack
        .at_entry(path, Some(mode.into()))
        .map_err(|e| Error::Attributes(Box::new(e)))?;
    platform.matching_attributes(outcome);
    // We selected only `export-ignore`, so any selected match in the `Set` state
    // means it applies. (`-export-ignore` would be `Unset` and not match here.)
    Ok(outcome
        .iter_selected()
        .any(|m| matches!(m.assignment.state, gix::attrs::StateRef::Set)))
}

/// Whether any ancestor directory of `path` is in the export-ignored set.
fn has_ignored_ancestor(path: &BStr, ignored: &HashSet<Vec<u8>>) -> bool {
    if ignored.is_empty() {
        return false;
    }
    let bytes = path.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'/' && ignored.contains(&bytes[..i]) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// Build a throwaway git repo in `dir`, committing whatever files already
    /// exist there, with pinned identity so the test is hermetic.
    fn commit_repo(dir: &std::path::Path) {
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
        git(&["add", "-A"]);
        git(&["commit", "-qm", "fixture"]);
    }

    fn write(dir: &std::path::Path, rel: &str, bytes: &[u8]) {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, bytes).unwrap();
    }

    fn tempdir() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut p = std::env::temp_dir();
        p.push(format!("sconce-git-test-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// Sorted list of paths in an archive, by re-reading its central directory
    /// names is overkill; instead archive into entries and inspect via a second
    /// helper. We expose the set through a tiny re-archive + unzip-free check:
    /// compare against `git archive` below by file count + names is enough.
    fn archived_paths(dir: &std::path::Path) -> Vec<String> {
        // Reuse the public API and pull names back out of the produced zip by
        // listing what `git archive` would include is done in the parity test;
        // here we just need names, so read them from the archive's zip via a
        // minimal scan of local-file-header filenames.
        let zip = archive_ref(dir, "HEAD").unwrap().into_zip();
        local_header_names(&zip)
    }

    /// Extract entry names from a stored-method zip by scanning local file
    /// headers (signature `PK\x03\x04`). Sufficient for tests.
    fn local_header_names(zip: &[u8]) -> Vec<String> {
        let mut names = Vec::new();
        let mut i = 0;
        while i + 30 <= zip.len() {
            if &zip[i..i + 4] != b"PK\x03\x04" {
                break;
            }
            let name_len = u16::from_le_bytes([zip[i + 26], zip[i + 27]]) as usize;
            let extra_len = u16::from_le_bytes([zip[i + 28], zip[i + 29]]) as usize;
            let comp_size =
                u32::from_le_bytes([zip[i + 18], zip[i + 19], zip[i + 20], zip[i + 21]]) as usize;
            let name_start = i + 30;
            let name =
                String::from_utf8_lossy(&zip[name_start..name_start + name_len]).into_owned();
            names.push(name);
            i = name_start + name_len + extra_len + comp_size;
        }
        names.sort();
        names
    }

    /// `git archive` to a zip, returning its sorted entry names — the source of
    /// truth we match against.
    fn git_archive_names(dir: &std::path::Path) -> Vec<String> {
        let out = Command::new("git")
            .args(["archive", "--format=zip", "HEAD"])
            .current_dir(dir)
            .output()
            .expect("git archive");
        assert!(out.status.success(), "git archive failed");
        let mut names = local_header_names(&out.stdout);
        // git archive omits directory entries too (stored method varies, but we
        // only compare file names); drop any trailing-slash dir entries if present.
        names.retain(|n| !n.ends_with('/'));
        names.sort();
        names
    }

    #[test]
    fn honors_export_ignore_matching_git_archive() {
        let dir = tempdir();
        write(&dir, "src/Foo.php", b"<?php\n");
        write(&dir, "README.md", b"# demo\n");
        write(&dir, "tests/FooTest.php", b"<?php\n");
        write(&dir, "tests/unit/BarTest.php", b"<?php\n");
        write(&dir, "phpunit.xml.dist", b"<phpunit/>\n");
        write(
            &dir,
            ".gitattributes",
            b"/tests export-ignore\nphpunit.xml.dist export-ignore\n",
        );
        commit_repo(&dir);

        let ours = archived_paths(&dir);
        let git = git_archive_names(&dir);
        assert_eq!(ours, git, "export-ignore selection must match git archive");
        // Sanity: the excluded paths are gone, the kept ones remain.
        assert!(ours.contains(&"src/Foo.php".to_string()));
        assert!(ours.contains(&".gitattributes".to_string()));
        assert!(
            !ours.iter().any(|p| p.starts_with("tests/")),
            "whole tests/ dir dropped"
        );
        assert!(!ours.contains(&"phpunit.xml.dist".to_string()));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn deterministic_and_skips_dot_git() {
        let dir = tempdir();
        write(&dir, "src/Foo.php", b"<?php\nclass Foo {}\n");
        write(&dir, "README.md", b"# demo\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            write(&dir, "run.sh", b"#!/bin/sh\necho hi\n");
            std::fs::set_permissions(dir.join("run.sh"), std::fs::Permissions::from_mode(0o755))
                .unwrap();
            std::os::unix::fs::symlink("src/Foo.php", dir.join("link")).unwrap();
        }
        commit_repo(&dir);

        let zip = archive_ref(&dir, "HEAD").unwrap().into_zip();
        assert_eq!(&zip[0..4], &[b'P', b'K', 0x03, 0x04]);
        let again = archive_ref(&dir, "HEAD").unwrap().into_zip();
        assert_eq!(zip, again, "same (repo, ref) → identical bytes");
        assert!(
            !local_header_names(&zip)
                .iter()
                .any(|n| n.starts_with(".git/"))
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
