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
use sconce_catalog::secret::SecretKey;
use sconce_catalog::{Catalog, Visibility};
use uuid::Uuid;

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
    #[error("no such upstream")]
    UnknownUpstream,
    #[error("decrypting upstream credential")]
    Secret(#[from] sconce_catalog::secret::SecretError),
    #[error("git clone failed: {0}")]
    Clone(String),
    #[error("http error: {0}")]
    Http(String),
    #[error("upstream metadata for {package} is malformed")]
    BadMetadata { package: String },
    #[error("dist sha1 mismatch for {package} {version} (corrupt download or tampered upstream)")]
    ShasumMismatch { package: String, version: String },
    #[error("invalid package-match regex: {0}")]
    BadPattern(String),
    #[error("a composer upstream requires a non-empty package filter (refusing to mirror the entire registry)")]
    FilterRequired,
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

/// Mirror every tagged version of the git repository at `repo_path` into the
/// catalog **repository** `repo_id` + `store`. `git_url` is recorded as the
/// package source. Packages are marked private and bound to no upstream — this
/// is the local-checkout path; use [`mirror_upstream`] to mirror a registered
/// upstream by URL.
pub async fn mirror_git_source(
    repo_id: uuid::Uuid,
    repo_path: &Path,
    git_url: &str,
    store: &(impl BlobStore + Sync),
    catalog: &Catalog,
) -> Result<Report, Error> {
    mirror_checkout(
        repo_id,
        repo_path,
        git_url,
        Visibility::Private,
        None,
        store,
        catalog,
    )
    .await
}

/// Sync a registered upstream — **the worker's entry point**. Dispatches on
/// kind: a `git` upstream is cloned and its tags mirrored; a `composer` upstream
/// mirrors the packages its stored `package_filter` selects (all of
/// `available-packages` if unset). `key` is needed only for a credentialed
/// (private) upstream.
pub async fn mirror_upstream(
    catalog: &Catalog,
    store: &(impl BlobStore + Sync),
    upstream_id: Uuid,
    key: Option<&SecretKey>,
) -> Result<Report, Error> {
    let up = catalog
        .get_upstream(upstream_id)
        .await
        .map_err(|e| Error::Catalog(Box::new(e)))?
        .ok_or(Error::UnknownUpstream)?;
    match up.kind.as_str() {
        "git" => mirror_git_clone(catalog, store, &up, key).await,
        "composer" => {
            let filter = up.package_filter.clone();
            mirror_composer_registry(catalog, store, &up, filter.as_deref()).await
        }
        other => Err(Error::Http(format!("unknown upstream kind: {other}"))),
    }
}

/// Clone a git upstream (with its decrypted credential, if any) and mirror its
/// tags, binding packages to the upstream and tagging them with its visibility.
async fn mirror_git_clone(
    catalog: &Catalog,
    store: &(impl BlobStore + Sync),
    up: &sconce_catalog::UpstreamRow,
    key: Option<&SecretKey>,
) -> Result<Report, Error> {
    // Decrypt the credential (if any) to inject into the clone URL.
    let credential = match up.credential.as_deref() {
        None => None,
        Some(ct) => Some(key.ok_or(sconce_catalog::secret::SecretError::NoKey)?.decrypt(ct)?),
    };
    let credential = credential.as_deref().map(|b| String::from_utf8_lossy(b).into_owned());

    let checkout =
        TempCheckout::clone_repo(&up.base, credential.as_deref(), &up.credential_type)?;
    mirror_checkout(
        up.repo_id,
        checkout.path(),
        &up.base,
        up.visibility,
        Some(up.id),
        store,
        catalog,
    )
    .await
}

/// Largest dist we'll download from a Composer upstream (guards against a
/// hostile/oversized `dist.url`).
const MAX_DIST_BYTES: u64 = 256 * 1024 * 1024;

/// Mirror a single package from a registered **composer** upstream: read its p2
/// metadata, download each version's dist **verbatim** (preserving the upstream
/// `dist.shasum` — re-archiving would change the sha1 and break Composer's
/// integrity check), store it in the CAS, and upsert the catalog. Packages take
/// the upstream's visibility and are bound to it.
pub async fn mirror_composer_package(
    catalog: &Catalog,
    store: &(impl BlobStore + Sync),
    upstream_id: Uuid,
    package: &str,
) -> Result<Report, Error> {
    let up = load_composer_upstream(catalog, upstream_id).await?;
    mirror_one_composer_package(catalog, store, &up, package).await
}

/// Mirror **every** package a composer upstream lists in `available-packages`,
/// optionally filtered by a regex (e.g. `^mage-os/` or `^magento/module-`). A
/// per-package failure is recorded in `skipped` rather than aborting the run.
/// (Pattern-only registries — `available-package-patterns` with no concrete
/// `available-packages` — can't be enumerated and yield nothing.)
pub async fn mirror_composer_upstream(
    catalog: &Catalog,
    store: &(impl BlobStore + Sync),
    upstream_id: Uuid,
    filter: Option<&str>,
) -> Result<Report, Error> {
    let up = load_composer_upstream(catalog, upstream_id).await?;
    mirror_composer_registry(catalog, store, &up, filter).await
}

/// Registry-mirror core (shared by the CLI and the worker's `mirror_upstream`):
/// enumerate `available-packages`, filter by `filter`, mirror each match.
async fn mirror_composer_registry(
    catalog: &Catalog,
    store: &(impl BlobStore + Sync),
    up: &sconce_catalog::UpstreamRow,
    filter: Option<&str>,
) -> Result<Report, Error> {
    if up.kind != "composer" {
        return Err(Error::Http("expected a 'composer' upstream".to_owned()));
    }
    // A filter is mandatory — an unfiltered sync would mirror the whole registry
    // (catastrophic for e.g. Packagist). Blank/whitespace counts as absent.
    let filter = filter.map(str::trim).filter(|f| !f.is_empty());
    let re = match filter {
        Some(p) => regex::Regex::new(p).map_err(|e| Error::BadPattern(e.to_string()))?,
        None => return Err(Error::FilterRequired),
    };

    let base = up.base.trim_end_matches('/');
    let body = http_get_string(&format!("{base}/packages.json"))?;
    let root: serde_json::Value =
        serde_json::from_str(&body).map_err(|_| Error::BadMetadata { package: "packages.json".to_owned() })?;
    let names: Vec<String> = root
        .get("available-packages")
        .and_then(serde_json::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(serde_json::Value::as_str)
                .filter(|n| re.is_match(n))
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default();

    let mut report = Report::default();
    for name in names {
        match mirror_one_composer_package(catalog, store, up, &name).await {
            Ok(r) => {
                report.mirrored.extend(r.mirrored);
                report.skipped.extend(r.skipped);
            }
            // Don't let one bad package abort a large registry mirror.
            Err(e) => report.skipped.push((name, e.to_string())),
        }
    }
    Ok(report)
}

/// Load an upstream and assert it is a `composer` one.
async fn load_composer_upstream(
    catalog: &Catalog,
    upstream_id: Uuid,
) -> Result<sconce_catalog::UpstreamRow, Error> {
    let up = catalog
        .get_upstream(upstream_id)
        .await
        .map_err(|e| Error::Catalog(Box::new(e)))?
        .ok_or(Error::UnknownUpstream)?;
    if up.kind != "composer" {
        return Err(Error::Http(
            "expected a 'composer' upstream".to_owned(),
        ));
    }
    Ok(up)
}

async fn mirror_one_composer_package(
    catalog: &Catalog,
    store: &(impl BlobStore + Sync),
    up: &sconce_catalog::UpstreamRow,
    package: &str,
) -> Result<Report, Error> {
    // p2 metadata: {base}/p2/{vendor}/{name}.json (the standard metadata-url).
    let base = up.base.trim_end_matches('/');
    let meta_url = format!("{base}/p2/{package}.json");
    let body = http_get_string(&meta_url)?;
    let meta: serde_json::Value =
        serde_json::from_str(&body).map_err(|_| Error::BadMetadata { package: package.to_owned() })?;
    let versions = meta
        .get("packages")
        .and_then(|p| p.get(package))
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| Error::BadMetadata { package: package.to_owned() })?;

    let mut report = Report::default();
    for obj in versions {
        let version = obj.get("version").and_then(serde_json::Value::as_str);
        let normalized = obj
            .get("version_normalized")
            .and_then(serde_json::Value::as_str);
        let dist = obj.get("dist");
        let dist_url = dist
            .and_then(|d| d.get("url"))
            .and_then(serde_json::Value::as_str);
        let shasum = dist
            .and_then(|d| d.get("shasum"))
            .and_then(serde_json::Value::as_str);
        let (Some(version), Some(normalized), Some(dist_url), Some(shasum)) =
            (version, normalized, dist_url, shasum)
        else {
            // No dist (e.g. some metapackages) → nothing to store.
            let v = version.unwrap_or("?").to_owned();
            report.skipped.push((v, "no dist".to_owned()));
            continue;
        };

        // Download verbatim and verify the upstream's sha1.
        let bytes = http_get_bytes(dist_url)?;
        if sha1_hex(&bytes) != shasum {
            return Err(Error::ShasumMismatch {
                package: package.to_owned(),
                version: version.to_owned(),
            });
        }
        let blob = store.put(&bytes)?;
        let size = i64::try_from(bytes.len()).unwrap_or(i64::MAX);
        let stability = composer_stability(version);

        catalog
            .upsert_blob(blob.as_bytes(), size)
            .await
            .map_err(|e| Error::Catalog(Box::new(e)))?;
        let package_id = catalog
            .upsert_package(up.repo_id, package, "composer", Some(&serde_json::json!({ "url": base })), up.visibility)
            .await
            .map_err(|e| Error::Catalog(Box::new(e)))?;
        catalog
            .set_package_upstream(package_id, up.id)
            .await
            .map_err(|e| Error::Catalog(Box::new(e)))?;
        catalog
            .upsert_package_version(
                package_id,
                version,
                normalized,
                &stability,
                obj, // the p2 object is the package metadata; serving injects dist
                Some(blob.as_bytes()),
                Some(shasum),
                None,
                None,
            )
            .await
            .map_err(|e| Error::Catalog(Box::new(e)))?;

        report.mirrored.push(Mirrored {
            tag: version.to_owned(),
            package: package.to_owned(),
            normalized: normalized.to_owned(),
            stability,
        });
    }
    Ok(report)
}

/// Cap on the dependency closure size (safety against a runaway graph).
const MAX_CLOSURE: usize = 2000;

/// Resolve a repo's full transitive dependency closure **read-only** — fetching
/// metadata to classify each dep but mirroring nothing. Each dep is resolved by
/// name against the repo's *composer* upstreams (private-first, so private wins
/// on ambiguity): `present` (already in the repo), `resolvable-private` /
/// `resolvable-public` (found in an upstream → recorded with its source), or
/// `missing` (nowhere). Returns the plan for the operator to review and pick from.
pub async fn resolve_closure(
    catalog: &Catalog,
    repo_id: Uuid,
) -> Result<Vec<sconce_catalog::DependencyPlanEntry>, Error> {
    use std::collections::{HashSet, VecDeque};
    let boxed = |e: sconce_catalog::SqlxError| Error::Catalog(Box::new(e));

    let present: HashSet<String> = catalog
        .all_package_names(repo_id)
        .await
        .map_err(boxed)?
        .into_iter()
        .collect();
    // Composer upstreams, private-first (private classification wins ties).
    let mut upstreams: Vec<_> = catalog
        .list_upstreams(repo_id)
        .await
        .map_err(boxed)?
        .into_iter()
        .filter(|u| u.kind == "composer")
        .collect();
    upstreams.sort_by_key(|u| u8::from(u.visibility != "private"));

    let mut queue: VecDeque<(String, String)> = VecDeque::new();
    let mut seen: HashSet<String> = HashSet::new();
    for (pkg, dep) in catalog.repo_direct_requires(repo_id).await.map_err(boxed)? {
        if is_package(&dep) {
            queue.push_back((dep, pkg));
        }
    }

    let mut plan = Vec::new();
    while let Some((dep, required_by)) = queue.pop_front() {
        if !is_package(&dep) || !seen.insert(dep.clone()) {
            continue;
        }
        if plan.len() >= MAX_CLOSURE {
            break;
        }
        if present.contains(&dep) {
            plan.push(plan_entry(&dep, "present", None, &required_by));
            continue;
        }
        // Probe each composer upstream by name; first hit resolves + classifies.
        let mut resolved = None;
        for u in &upstreams {
            if let Ok(Some(versions)) = fetch_p2(&u.base, &dep) {
                resolved = Some((u, versions));
                break;
            }
        }
        match resolved {
            Some((u, versions)) => {
                let status = if u.visibility == "private" {
                    "resolvable-private"
                } else {
                    "resolvable-public"
                };
                plan.push(plan_entry(&dep, status, Some(u.id), &required_by));
                // Expand into the latest listed version's requires.
                for d in latest_requires(&versions) {
                    if is_package(&d) {
                        queue.push_back((d, dep.clone()));
                    }
                }
            }
            None => plan.push(plan_entry(&dep, "missing", None, &required_by)),
        }
    }
    Ok(plan)
}

/// A composer package name has a `vendor/name` slash; platform reqs (`php`,
/// `ext-*`, `lib-*`, `composer-*`) don't and are skipped.
fn is_package(name: &str) -> bool {
    name.contains('/')
}

fn plan_entry(
    name: &str,
    status: &str,
    upstream: Option<Uuid>,
    required_by: &str,
) -> sconce_catalog::DependencyPlanEntry {
    sconce_catalog::DependencyPlanEntry {
        name: name.to_owned(),
        status: status.to_owned(),
        resolver_upstream_id: upstream,
        required_by: Some(required_by.to_owned()),
    }
}

/// GET `{base}/p2/{package}.json`. `Ok(Some(versions))` if present, `Ok(None)`
/// on 404 (not in this registry), `Err` on any other failure (so the caller
/// tries the next upstream and only records `missing` if all fail/404).
fn fetch_p2(base: &str, package: &str) -> Result<Option<Vec<serde_json::Value>>, Error> {
    let url = format!("{}/p2/{package}.json", base.trim_end_matches('/'));
    match ureq::get(&url).call() {
        Ok(resp) => {
            let body = resp.into_string().map_err(|e| Error::Http(e.to_string()))?;
            let v: serde_json::Value =
                serde_json::from_str(&body).map_err(|_| Error::BadMetadata {
                    package: package.to_owned(),
                })?;
            let versions = v
                .get("packages")
                .and_then(|p| p.get(package))
                .and_then(serde_json::Value::as_array)
                .cloned()
                .unwrap_or_default();
            Ok(Some(versions))
        }
        Err(ureq::Error::Status(404, _)) => Ok(None),
        Err(e) => Err(Error::Http(e.to_string())),
    }
}

/// The `require` package names of the last (latest listed) version in a p2 array.
fn latest_requires(versions: &[serde_json::Value]) -> Vec<String> {
    versions
        .last()
        .and_then(|v| v.get("require"))
        .and_then(serde_json::Value::as_object)
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}

/// Composer stability of a version string (default `stable`).
fn composer_stability(version: &str) -> String {
    let v = version.to_ascii_lowercase();
    for (needle, label) in [
        ("dev", "dev"),
        ("alpha", "alpha"),
        ("beta", "beta"),
        ("rc", "RC"),
    ] {
        if v.contains(needle) {
            return label.to_owned();
        }
    }
    "stable".to_owned()
}

fn http_get_string(url: &str) -> Result<String, Error> {
    ureq::get(url)
        .call()
        .map_err(|e| Error::Http(e.to_string()))?
        .into_string()
        .map_err(|e| Error::Http(e.to_string()))
}

fn http_get_bytes(url: &str) -> Result<Vec<u8>, Error> {
    use std::io::Read as _;
    let resp = ureq::get(url).call().map_err(|e| Error::Http(e.to_string()))?;
    let mut buf = Vec::new();
    resp.into_reader()
        .take(MAX_DIST_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| Error::Http(e.to_string()))?;
    if buf.len() as u64 > MAX_DIST_BYTES {
        return Err(Error::Http(format!("dist exceeds {MAX_DIST_BYTES} bytes: {url}")));
    }
    Ok(buf)
}

/// Shared worker: enumerate `repo_path`'s tags and upsert each version, tagging
/// packages with `visibility` and (optionally) binding them to `upstream_id`.
#[allow(clippy::too_many_arguments)]
async fn mirror_checkout(
    repo_id: Uuid,
    repo_path: &Path,
    source_url: &str,
    visibility: Visibility,
    upstream_id: Option<Uuid>,
    store: &(impl BlobStore + Sync),
    catalog: &Catalog,
) -> Result<Report, Error> {
    let git_url = source_url;
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
        // Composer verifies a dist by its sha1 (`dist.shasum`); compute it now
        // so serving never re-reads the blob.
        let dist_shasum = sha1_hex(&zip);
        // The tag's commit time is the version's release time — it drives
        // cooldown, so old tags are instantly past cooldown and only genuinely
        // new releases wait.
        let released_at = sconce_git::commit_time(repo_path, &tag).ok();
        // A blob can never exceed i64::MAX bytes; saturate rather than wrap.
        let size = i64::try_from(zip.len()).unwrap_or(i64::MAX);

        let source = serde_json::json!({ "url": git_url });
        catalog
            .upsert_blob(blob.as_bytes(), size)
            .await
            .map_err(|e| Error::Catalog(Box::new(e)))?;
        let package_id = catalog
            .upsert_package(repo_id, &name, "git", Some(&source), visibility)
            .await
            .map_err(|e| Error::Catalog(Box::new(e)))?;
        if let Some(uid) = upstream_id {
            catalog
                .set_package_upstream(package_id, uid)
                .await
                .map_err(|e| Error::Catalog(Box::new(e)))?;
        }
        catalog
            .upsert_package_version(
                package_id,
                &tag,
                &parsed.normalized,
                &parsed.stability,
                &composer_json,
                Some(blob.as_bytes()),
                Some(&dist_shasum),
                None, // source_reference (commit sha) — added later
                released_at,
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

/// Lowercase sha1 hex of `bytes` — Composer's `dist.shasum` format.
fn sha1_hex(bytes: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    use std::fmt::Write as _;
    let digest = Sha1::digest(bytes);
    digest.iter().fold(String::with_capacity(40), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Build the clone URL + any extra `git -c …` args for a credential, per its
/// `credential_type`. Non-http(s) bases (e.g. `file://`, local paths, ssh) take
/// no injected credential. Returns `(url, pre_subcommand_args)`.
fn build_clone_invocation(
    base: &str,
    credential: Option<&str>,
    credential_type: &str,
) -> (String, Vec<String>) {
    let with_userinfo = |userinfo: &str| {
        let (scheme, rest) = base.split_once("://").expect("http(s) checked by caller");
        format!("{scheme}://{userinfo}@{rest}")
    };
    let is_http = base.starts_with("http://") || base.starts_with("https://");
    match credential {
        Some(cred) if is_http => match credential_type {
            // Token as an Authorization header rather than in the URL.
            "bearer" => (
                base.to_owned(),
                vec![
                    "-c".to_owned(),
                    format!("http.extraHeader=Authorization: Bearer {cred}"),
                ],
            ),
            "github" => (with_userinfo(&format!("x-access-token:{cred}")), vec![]),
            "gitlab" => (with_userinfo(&format!("oauth2:{cred}")), vec![]),
            // 'basic' (default): the secret is the full userinfo (user:token).
            _ => (with_userinfo(cred), vec![]),
        },
        _ => (base.to_owned(), vec![]),
    }
}

/// A `git clone` into a temp directory, removed on drop. Cloning runs a blocking
/// subprocess — fine for the CLI/operator path; the background worker (planned)
/// will own concurrency.
struct TempCheckout {
    dir: std::path::PathBuf,
}

impl TempCheckout {
    fn clone_repo(
        base: &str,
        credential: Option<&str>,
        credential_type: &str,
    ) -> Result<Self, Error> {
        let mut dir = std::env::temp_dir();
        dir.push(format!("sconce-clone-{}", Uuid::new_v4()));
        let (url, pre_args) = build_clone_invocation(base, credential, credential_type);
        let out = std::process::Command::new("git")
            .args(&pre_args)
            .args(["clone", "--quiet", &url])
            .arg(&dir)
            .output()
            .map_err(|e| Error::Clone(format!("spawning git: {e}")))?;
        if !out.status.success() {
            // Never leak the credential: redact the secret from git's stderr
            // (covers both the URL-embedded and header forms).
            let mut msg = String::from_utf8_lossy(&out.stderr).into_owned();
            if let Some(cred) = credential {
                msg = msg.replace(cred, "***");
            }
            return Err(Error::Clone(msg.trim().to_owned()));
        }
        Ok(Self { dir })
    }

    fn path(&self) -> &Path {
        &self.dir
    }
}

impl Drop for TempCheckout {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
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
        let slug = format!("m{}", std::process::id());
        catalog.create_org(&slug, None).await.unwrap();
        let repo_id = catalog.create_repo(&slug, "r").await.unwrap();

        let name = format!("acme/lib-{}", std::process::id());
        let repo = fixture_repo(&name);
        let cas = unique_temp("cas");
        let store = FsBlobStore::open(&cas).unwrap();

        let report = mirror_git_source(
            repo_id,
            &repo,
            "https://example.test/acme/lib.git",
            &store,
            &catalog,
        )
        .await
        .unwrap();

        assert_eq!(report.mirrored.len(), 2, "two tagged versions mirrored");
        assert_eq!(report.skipped.len(), 1, "the 'nightly' tag was skipped");
        assert_eq!(report.skipped[0].0, "nightly");

        // Catalog has both versions, each pointing at a stored blob.
        let mut versions = catalog.package_versions(repo_id, &name).await.unwrap();
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

    #[tokio::test]
    async fn mirrors_a_public_upstream_by_cloning_and_tags_visibility() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let catalog = Catalog::connect(&url).await.unwrap();
        catalog.migrate().await.unwrap();
        let slug = format!("up{}", std::process::id());
        catalog.create_org(&slug, None).await.unwrap();
        let repo_id = catalog.create_repo(&slug, "r").await.unwrap();

        let name = format!("acme/up-{}", std::process::id());
        let repo = fixture_repo(&name);
        let cas = unique_temp("cas");
        let store = FsBlobStore::open(&cas).unwrap();

        // Register the local fixture as a PUBLIC git upstream; mirror clones it.
        let up = catalog
            .create_upstream(
                repo_id,
                "git",
                repo.to_str().unwrap(),
                Visibility::Public,
                None,
                None,
                "basic",
            )
            .await
            .unwrap();
        let report = mirror_upstream(&catalog, &store, up, None).await.unwrap();
        assert_eq!(report.mirrored.len(), 2, "two tagged versions mirrored");

        // The package is present and was tagged public — it survives flipping the
        // repo to public-only (a private package would be hidden).
        assert!(catalog.all_package_names(repo_id).await.unwrap().contains(&name));
        let mut s = catalog.repo_settings(repo_id).await.unwrap();
        s.allow_private_packages = false;
        catalog.set_repo_settings(repo_id, s).await.unwrap();
        assert!(
            catalog.all_package_names(repo_id).await.unwrap().contains(&name),
            "public upstream's package stays visible in a public-only repo"
        );

        std::fs::remove_dir_all(&repo).ok();
        std::fs::remove_dir_all(&cas).ok();
    }

    /// Mirror a real package from the official Mage-OS Composer repo. Network +
    /// DB; `#[ignore]` by default — run with `cargo test -- --ignored`.
    #[tokio::test]
    #[ignore = "network: mirrors from repo.mage-os.org"]
    async fn mirrors_mageos_package_from_official_repo() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let catalog = Catalog::connect(&url).await.unwrap();
        catalog.migrate().await.unwrap();
        let slug = format!("mageos{}", std::process::id());
        catalog.create_org(&slug, None).await.unwrap();
        let repo_id = catalog.create_repo(&slug, "r").await.unwrap();
        let cas = unique_temp("cas");
        let store = FsBlobStore::open(&cas).unwrap();

        // The official Mage-OS Composer repository, as a PUBLIC upstream.
        let up = catalog
            .create_upstream(
                repo_id,
                "composer",
                "https://repo.mage-os.org",
                Visibility::Public,
                Some("mage-os"),
                None,
                "basic",
            )
            .await
            .unwrap();

        let pkg = "mage-os/composer";
        let report = mirror_composer_package(&catalog, &store, up, pkg).await.unwrap();
        assert!(
            report.mirrored.len() >= 5,
            "mirrored several versions, got {}",
            report.mirrored.len()
        );

        // Every version landed in the catalog, and every stored dist hashes back
        // to the upstream's sha1 — verbatim storage preserved Composer's integrity
        // check (the whole reason we don't re-archive composer dists).
        let versions = catalog.package_versions(repo_id, pkg).await.unwrap();
        assert_eq!(versions.len(), report.mirrored.len());
        for v in &versions {
            let id = sconce_cas::BlobId::from_bytes(v.dist_blob_sha256.expect("dist blob"));
            let bytes = store.get(&id).unwrap().expect("blob present in CAS");
            assert_eq!(
                sha1_hex(&bytes),
                v.dist_shasum.clone().expect("recorded shasum"),
                "stored bytes hash to the upstream's dist.shasum"
            );
            assert_eq!(&bytes[0..2], b"PK", "stored dist is a zip");
        }

        // It's a public package → still visible if the repo goes public-only.
        let mut s = catalog.repo_settings(repo_id).await.unwrap();
        s.allow_private_packages = false;
        catalog.set_repo_settings(repo_id, s).await.unwrap();
        assert!(
            catalog
                .all_package_names(repo_id)
                .await
                .unwrap()
                .iter()
                .any(|n| n == pkg)
        );

        std::fs::remove_dir_all(&cas).ok();
    }

    /// A second real package (the `magento/*` alias namespace Mage-OS also
    /// serves), to show the composer path isn't specific to one package.
    #[tokio::test]
    #[ignore = "network: mirrors from repo.mage-os.org"]
    async fn mirrors_mageos_magento_namespace_package() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let catalog = Catalog::connect(&url).await.unwrap();
        catalog.migrate().await.unwrap();
        let slug = format!("mageos2{}", std::process::id());
        catalog.create_org(&slug, None).await.unwrap();
        let repo_id = catalog.create_repo(&slug, "r").await.unwrap();
        let cas = unique_temp("cas");
        let store = FsBlobStore::open(&cas).unwrap();
        let up = catalog
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

        let pkg = "magento/composer";
        let report = mirror_composer_package(&catalog, &store, up, pkg).await.unwrap();
        assert!(!report.mirrored.is_empty(), "mirrored at least one version");
        // A specific known version is present.
        let versions = catalog.package_versions(repo_id, pkg).await.unwrap();
        assert!(versions.iter().any(|v| v.version == "1.10.0"));

        std::fs::remove_dir_all(&cas).ok();
    }

    /// Whole-registry mirror of the official Mage-OS repo, scoped by a regex to
    /// the handful of `mage-os/composer*` packages. Network + DB; `#[ignore]`.
    #[tokio::test]
    #[ignore = "network: mirrors from repo.mage-os.org"]
    async fn mirrors_mageos_registry_by_regex() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let catalog = Catalog::connect(&url).await.unwrap();
        catalog.migrate().await.unwrap();
        let slug = format!("mageosre{}", std::process::id());
        catalog.create_org(&slug, None).await.unwrap();
        let repo_id = catalog.create_repo(&slug, "r").await.unwrap();
        let cas = unique_temp("cas");
        let store = FsBlobStore::open(&cas).unwrap();
        let up = catalog
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

        // Matches mage-os/composer, -dependency-version-audit-plugin,
        // -root-update-plugin (a few packages, not the whole registry).
        let report = mirror_composer_upstream(&catalog, &store, up, Some(r"^mage-os/composer"))
            .await
            .unwrap();

        // The regex selected several distinct packages, all now in the catalog.
        let names = catalog.all_package_names(repo_id).await.unwrap();
        assert!(
            names.len() >= 2,
            "regex matched multiple packages, got {names:?}"
        );
        assert!(names.iter().all(|n| n.starts_with("mage-os/composer")));
        assert!(!report.mirrored.is_empty());

        std::fs::remove_dir_all(&cas).ok();
    }

    #[test]
    fn credential_types_format_the_clone_invocation() {
        let b = "https://git.example.com/acme/app.git";
        // basic: secret is full userinfo, embedded in the URL.
        assert_eq!(
            build_clone_invocation(b, Some("user:tok"), "basic"),
            ("https://user:tok@git.example.com/acme/app.git".to_owned(), vec![])
        );
        // github/gitlab: secret is a bare token, prefixed appropriately.
        assert_eq!(
            build_clone_invocation(b, Some("ghp_x"), "github").0,
            "https://x-access-token:ghp_x@git.example.com/acme/app.git"
        );
        assert_eq!(
            build_clone_invocation(b, Some("glpat_x"), "gitlab").0,
            "https://oauth2:glpat_x@git.example.com/acme/app.git"
        );
        // bearer: URL stays clean; token goes in an extraHeader arg.
        let (url, args) = build_clone_invocation(b, Some("tok"), "bearer");
        assert_eq!(url, b);
        assert_eq!(args, vec!["-c".to_owned(), "http.extraHeader=Authorization: Bearer tok".to_owned()]);
        // No credential, or a non-http base, injects nothing.
        assert_eq!(build_clone_invocation(b, None, "basic"), (b.to_owned(), vec![]));
        assert_eq!(
            build_clone_invocation("/local/path", Some("tok"), "github"),
            ("/local/path".to_owned(), vec![])
        );
    }

    /// The worker's entry point (`mirror_upstream`) now dispatches composer
    /// upstreams to the registry mirror, scoped by the upstream's stored filter.
    /// Network + DB; `#[ignore]`.
    #[tokio::test]
    #[ignore = "network: mirrors from repo.mage-os.org"]
    async fn mirror_upstream_dispatches_composer_with_stored_filter() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let catalog = Catalog::connect(&url).await.unwrap();
        catalog.migrate().await.unwrap();
        let slug = format!("disp{}", std::process::id());
        catalog.create_org(&slug, None).await.unwrap();
        let repo_id = catalog.create_repo(&slug, "r").await.unwrap();
        let cas = unique_temp("cas");
        let store = FsBlobStore::open(&cas).unwrap();
        let up = catalog
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
        // Store the filter, then sync via the same entry point the worker uses.
        catalog
            .set_upstream_filter(repo_id, up, Some(r"^mage-os/composer"))
            .await
            .unwrap();

        let report = mirror_upstream(&catalog, &store, up, None).await.unwrap();
        assert!(!report.mirrored.is_empty());
        let names = catalog.all_package_names(repo_id).await.unwrap();
        assert!(names.len() >= 2, "filter selected several packages: {names:?}");
        assert!(names.iter().all(|n| n.starts_with("mage-os/composer")));

        std::fs::remove_dir_all(&cas).ok();
    }

    #[tokio::test]
    async fn composer_sync_without_a_filter_is_refused() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let catalog = Catalog::connect(&url).await.unwrap();
        catalog.migrate().await.unwrap();
        let slug = format!("nf{}", std::process::id());
        catalog.create_org(&slug, None).await.unwrap();
        let repo_id = catalog.create_repo(&slug, "r").await.unwrap();
        let cas = unique_temp("cas");
        let store = FsBlobStore::open(&cas).unwrap();
        let up = catalog
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

        // No filter stored → both the worker entry point and the explicit-filter
        // path refuse, BEFORE any network call (so this needs no network).
        assert!(matches!(
            mirror_upstream(&catalog, &store, up, None).await,
            Err(Error::FilterRequired)
        ));
        assert!(matches!(
            mirror_composer_upstream(&catalog, &store, up, Some("   ")).await,
            Err(Error::FilterRequired)
        ));

        std::fs::remove_dir_all(&cas).ok();
    }

    /// Hold a Postgres advisory lock (same key as the catalog queue tests) to
    /// serialize global job-queue tests across processes, with a clean slate.
    async fn queue_guard(url: &str) -> sqlx::PgConnection {
        use sqlx::Connection as _;
        let mut conn = sqlx::PgConnection::connect(url).await.unwrap();
        sqlx::query("select pg_advisory_lock(778899)")
            .execute(&mut conn)
            .await
            .unwrap();
        sqlx::query("delete from mirror_jobs")
            .execute(&mut conn)
            .await
            .unwrap();
        conn
    }

    #[tokio::test]
    async fn worker_inner_loop_claims_mirrors_and_completes() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let _guard = queue_guard(&url).await;
        let catalog = Catalog::connect(&url).await.unwrap();
        catalog.migrate().await.unwrap();
        let slug = format!("wk{}", std::process::id());
        catalog.create_org(&slug, None).await.unwrap();
        let repo_id = catalog.create_repo(&slug, "r").await.unwrap();

        let name = format!("acme/wk-{}", std::process::id());
        let repo = fixture_repo(&name);
        let cas = unique_temp("cas");
        let store = FsBlobStore::open(&cas).unwrap();
        let up = catalog
            .create_upstream(repo_id, "git", repo.to_str().unwrap(), Visibility::Private, None, None, "basic")
            .await
            .unwrap();

        // Drive one iteration of the worker's loop by hand.
        catalog.enqueue_mirror_job(up).await.unwrap();
        let job = catalog.claim_mirror_job().await.unwrap().expect("claim");
        assert_eq!(job.kind, "mirror_upstream");
        let report = mirror_upstream(&catalog, &store, job.upstream_id.unwrap(), None)
            .await
            .unwrap();
        catalog.complete_mirror_job(job.id).await.unwrap();
        assert_eq!(report.mirrored.len(), 2);

        let listed = catalog.list_upstreams(repo_id).await.unwrap();
        let u = listed.iter().find(|u| u.id == up).unwrap();
        assert_eq!(u.job_status.as_deref(), Some("ready"));

        std::fs::remove_dir_all(&repo).ok();
        std::fs::remove_dir_all(&cas).ok();
    }
}
