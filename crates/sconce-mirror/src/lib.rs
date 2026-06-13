//! The mirror worker: turn a git source into catalog rows + CAS blobs.
//!
//! For each tag in the source repository it: derives a Composer version from the
//! tag, reads `composer.json` (for the package name + metadata), archives the
//! tree deterministically, stores the archive in the content-addressed store,
//! and upserts the blob, package, and version into the catalog. Tags without a
//! recognizable version or a `composer.json` are skipped and reported, not
//! failed on.
//!
//! Everything is idempotent: re-mirroring the same source re-derives the same
//! blob ids (so the CAS dedupes) and upserts the same catalog rows.

#![forbid(unsafe_code)]

mod version;

use std::path::Path;

use sconce_cas::BlobStore;
use sconce_catalog::Catalog;

pub use version::{ParsedVersion, normalize_tag};

/// Errors mirroring a source.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("reading git source")]
    Git(#[from] sconce_git::Error),
    #[error("content store i/o")]
    Cas(#[from] std::io::Error),
    #[error("catalog")]
    Catalog(Box<dyn std::error::Error + Send + Sync>),
    #[error("composer.json at {tag} is not valid JSON")]
    BadComposerJson { tag: String },
    #[error("composer.json at {tag} has no \"name\"")]
    NoName { tag: String },
}

/// A version that was mirrored.
#[derive(Debug, Clone)]
pub struct Mirrored {
    pub tag: String,
    pub package: String,
    pub normalized: String,
    pub stability: String,
}

/// Outcome of mirroring a source.
#[derive(Debug, Default)]
pub struct Report {
    pub mirrored: Vec<Mirrored>,
    /// `(tag, reason)` for tags that were skipped.
    pub skipped: Vec<(String, String)>,
}

/// Mirror every tagged version of the git repository at `repo_path` into
/// `store` + `catalog`. `git_url` is recorded as the package source.
pub async fn mirror_git_source(
    repo_path: &Path,
    git_url: &str,
    store: &(impl BlobStore + Sync),
    catalog: &Catalog,
) -> Result<Report, Error> {
    let mut report = Report::default();

    for tag in sconce_git::tags(repo_path)? {
        let Some(parsed) = normalize_tag(&tag) else {
            report
                .skipped
                .push((tag, "unrecognized version".to_owned()));
            continue;
        };

        let Some(cj_bytes) = sconce_git::read_file(repo_path, &tag, "composer.json")? else {
            report.skipped.push((tag, "no composer.json".to_owned()));
            continue;
        };
        let composer_json: serde_json::Value = serde_json::from_slice(&cj_bytes)
            .map_err(|_| Error::BadComposerJson { tag: tag.clone() })?;
        let name = composer_json
            .get("name")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| Error::NoName { tag: tag.clone() })?
            .to_owned();

        // Archive the tree and store it; the blob id is content-addressed.
        let zip = sconce_git::archive_ref(repo_path, &tag)?.into_zip();
        let blob = store.put(&zip)?;
        // A blob can never exceed i64::MAX bytes; saturate rather than wrap.
        let size = i64::try_from(zip.len()).unwrap_or(i64::MAX);

        let source = serde_json::json!({ "url": git_url });
        catalog
            .upsert_blob(blob.as_bytes(), size)
            .await
            .map_err(|e| Error::Catalog(Box::new(e)))?;
        let package_id = catalog
            .upsert_package(&name, "git", Some(&source))
            .await
            .map_err(|e| Error::Catalog(Box::new(e)))?;
        catalog
            .upsert_package_version(
                package_id,
                &tag,
                &parsed.normalized,
                &parsed.stability,
                &composer_json,
                Some(blob.as_bytes()),
                None, // source_reference (commit sha) — added later
            )
            .await
            .map_err(|e| Error::Catalog(Box::new(e)))?;

        report.mirrored.push(Mirrored {
            tag,
            package: name,
            normalized: parsed.normalized,
            stability: parsed.stability,
        });
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sconce_cas::FsBlobStore;
    use std::process::Command;

    fn git(dir: &Path, args: &[&str]) {
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
    }

    fn unique_temp(stem: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static C: AtomicU64 = AtomicU64::new(0);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "sconce-mirror-{stem}-{}-{}",
            std::process::id(),
            C.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    /// Build a tiny package repo with two tagged versions + a non-version tag.
    fn fixture_repo(name: &str) -> std::path::PathBuf {
        let dir = unique_temp("repo");
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/Lib.php"), b"<?php\n").unwrap();
        let write_composer = |ver: &str| {
            std::fs::write(
                dir.join("composer.json"),
                serde_json::to_vec(&serde_json::json!({"name": name, "version": ver})).unwrap(),
            )
            .unwrap();
        };
        git(&dir, &["init", "-q", "-b", "main"]);
        write_composer("1.0.0");
        git(&dir, &["add", "-A"]);
        git(&dir, &["commit", "-qm", "v1"]);
        git(&dir, &["tag", "v1.0.0"]);
        write_composer("1.1.0");
        git(&dir, &["commit", "-qam", "v1.1"]);
        git(&dir, &["tag", "v1.1.0"]);
        git(&dir, &["tag", "nightly"]); // not a version → skipped
        dir
    }

    #[tokio::test]
    async fn mirrors_tagged_versions_into_catalog_and_cas() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let catalog = Catalog::connect(&url).await.unwrap();
        catalog.migrate().await.unwrap();

        let name = format!("acme/lib-{}", std::process::id());
        let repo = fixture_repo(&name);
        let cas = unique_temp("cas");
        let store = FsBlobStore::open(&cas).unwrap();

        let report =
            mirror_git_source(&repo, "https://example.test/acme/lib.git", &store, &catalog)
                .await
                .unwrap();

        assert_eq!(report.mirrored.len(), 2, "two tagged versions mirrored");
        assert_eq!(report.skipped.len(), 1, "the 'nightly' tag was skipped");
        assert_eq!(report.skipped[0].0, "nightly");

        // Catalog has both versions, each pointing at a stored blob.
        let mut versions = catalog.package_versions(&name).await.unwrap();
        versions.sort_by(|a, b| a.normalized_version.cmp(&b.normalized_version));
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].normalized_version, "1.0.0.0");
        assert_eq!(versions[1].normalized_version, "1.1.0.0");
        // Each recorded dist sha resolves to a blob actually present in the CAS,
        // and that blob is a valid (PK-signed) zip.
        for v in &versions {
            let id =
                sconce_cas::BlobId::from_bytes(v.dist_blob_sha256.expect("dist blob recorded"));
            assert!(store.exists(&id).unwrap(), "dist blob present in CAS");
            let bytes = store.get(&id).unwrap().expect("readable");
            assert_eq!(
                &bytes[0..4],
                &[b'P', b'K', 0x03, 0x04],
                "stored blob is a zip"
            );
        }

        std::fs::remove_dir_all(&repo).ok();
        std::fs::remove_dir_all(&cas).ok();
    }
}
