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

mod subscription;
mod version;

pub use subscription::Subscription;

use std::path::Path;

use composer_wire::{PackageDocument, RootManifest};
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
    /// A transport-level HTTP failure (connect / DNS / timeout / read) — no
    /// status was received, so it's treated as transient.
    #[error("http error: {0}")]
    Http(String),
    /// A definite HTTP response status. Distinguished from [`Error::Http`] so the
    /// worker can tell a *permanent* `404`/`403` (the source is gone / access is
    /// refused) from a transient `5xx`/`429`.
    #[error("http {code} from {url}")]
    HttpStatus { code: u16, url: String },
    #[error("upstream metadata for {package} is malformed")]
    BadMetadata { package: String },
    #[error("dist sha1 mismatch for {package} {version} (corrupt download or tampered upstream)")]
    ShasumMismatch { package: String, version: String },
    #[error("invalid package-match regex: {0}")]
    BadPattern(String),
    #[error(
        "a composer upstream requires a non-empty package filter (refusing to mirror the entire registry)"
    )]
    FilterRequired,
}

impl Error {
    /// Whether this failure is **terminal** — retrying the same job will fail the
    /// same way, so the worker should stop (and the package can be flagged
    /// *broken*) rather than back off. Non-terminal failures (transport errors,
    /// our own DB/disk, transient corruption) should retry with backoff.
    ///
    /// **Ambiguity routes to non-terminal**: we never want a maybe-temporary
    /// failure to wrongly flag a package broken (the same rule the dependency
    /// classifier uses — a probe failure is not a fact).
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        match self {
            // Deterministically bad upstream content — re-fetching is identical.
            Error::BadComposerJson { .. } | Error::NoName { .. } | Error::BadMetadata { .. }
            // The upstream is gone, or its config can never succeed as-is.
            | Error::UnknownUpstream
            | Error::Secret(_)
            | Error::BadPattern(_)
            | Error::FilterRequired => true,
            // A definite status: gone / forbidden are terminal; 5xx/429 retry.
            Error::HttpStatus { code, .. } => matches!(code, 401 | 403 | 404 | 410),
            // git clone: classify from its (credential-redacted) stderr.
            Error::Clone(stderr) => clone_error_reason(stderr).is_some(),
            // Our infra, transport errors, transient corruption → retry.
            Error::Git(_)
            | Error::Cas(_)
            | Error::Catalog(_)
            | Error::Http(_)
            | Error::ShasumMismatch { .. } => false,
        }
    }

    /// A stable reason code for a *terminal* failure (drives the package's
    /// `broken_reason`): `bad_content` | `auth_failed` | `source_gone` |
    /// `credential_error` | `config_error`. `None` for non-terminal failures.
    #[must_use]
    pub fn reason(&self) -> Option<&'static str> {
        match self {
            Error::BadComposerJson { .. } | Error::NoName { .. } | Error::BadMetadata { .. } => {
                Some("bad_content")
            }
            Error::HttpStatus {
                code: 401 | 403, ..
            } => Some("auth_failed"),
            Error::UnknownUpstream
            | Error::HttpStatus {
                code: 404 | 410, ..
            } => Some("source_gone"),
            Error::Secret(_) => Some("credential_error"),
            Error::BadPattern(_) | Error::FilterRequired => Some("config_error"),
            Error::Clone(stderr) => clone_error_reason(stderr),
            _ => None,
        }
    }
}

/// Classify a `git clone` failure from its stderr. Returns the terminal reason
/// (`auth_failed` / `source_gone`) or `None` when the message looks transient
/// (host unresolved, connection refused/timed out, TLS) — those retry.
fn clone_error_reason(stderr: &str) -> Option<&'static str> {
    /// Access permanently refused — wrong/expired/missing credential.
    const AUTH: &[&str] = &[
        "authentication failed",
        "could not read username",
        "could not read password",
        "invalid username or password",
        "permission denied",
        "access denied",
        "401 unauthorized",
        "403 forbidden",
        "error: 401",
        "error: 403",
    ];
    /// The repository / ref is gone.
    const GONE: &[&str] = &[
        "not found",
        "does not exist",
        "could not be found",
        "error: 404",
    ];
    let s = stderr.to_ascii_lowercase();
    if AUTH.iter().any(|m| s.contains(m)) {
        Some("auth_failed")
    } else if GONE.iter().any(|m| s.contains(m)) {
        Some("source_gone")
    } else {
        None
    }
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
        &Subscription::compile(&[])?,
        &[],
        store,
        catalog,
    )
    .await
}

/// Sync a registered upstream — **the worker's entry point**. Dispatches on
/// kind: a `git` upstream is cloned and its tags mirrored (its require-list, if
/// any, applies a per-package version floor); a `composer` upstream mirrors the
/// packages its require-list selects (it must be non-empty — an unscoped registry
/// sync is refused). `key` is needed only for a credentialed (private) upstream.
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
    let sub = Subscription::compile(&up.requires)?;
    match up.kind.as_str() {
        "git" => mirror_git_clone(catalog, store, &up, key, &sub).await,
        "composer" => mirror_composer_registry(catalog, store, &up, &sub).await,
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
    sub: &Subscription,
) -> Result<Report, Error> {
    // Decrypt the credential (if any) to inject into the clone URL.
    let credential = match up.credential.as_deref() {
        None => None,
        Some(ct) => Some(
            key.ok_or(sconce_catalog::secret::SecretError::NoKey)?
                .decrypt(ct)?,
        ),
    };
    let credential = credential
        .as_deref()
        .map(|b| String::from_utf8_lossy(b).into_owned());

    let checkout = TempCheckout::clone_repo(&up.base, credential.as_deref(), &up.credential_type)?;
    mirror_checkout(
        up.repo_id,
        checkout.path(),
        &up.base,
        up.visibility,
        Some(up.id),
        sub,
        &up.source_paths,
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
    // An explicit single-package sync still honors a floor if the upstream's
    // require-list opts this package in; a package matched by no entry mirrors
    // every version (the operator asked for it by name).
    let sub = Subscription::compile(&up.requires)?;
    mirror_one_composer_package(catalog, store, &up, package, &sub).await
}

/// Mirror **every** package a composer upstream's require-list selects from its
/// `available-packages`. A per-package failure is recorded in `skipped` rather
/// than aborting the run. (Pattern-only registries — `available-package-patterns`
/// with no concrete `available-packages` — can't be enumerated and yield nothing.)
pub async fn mirror_composer_upstream(
    catalog: &Catalog,
    store: &(impl BlobStore + Sync),
    upstream_id: Uuid,
) -> Result<Report, Error> {
    let up = load_composer_upstream(catalog, upstream_id).await?;
    let sub = Subscription::compile(&up.requires)?;
    mirror_composer_registry(catalog, store, &up, &sub).await
}

/// Registry-mirror core (shared by the CLI and the worker's `mirror_upstream`):
/// enumerate `available-packages`, filter by `filter`, mirror each match.
async fn mirror_composer_registry(
    catalog: &Catalog,
    store: &(impl BlobStore + Sync),
    up: &sconce_catalog::UpstreamRow,
    sub: &Subscription,
) -> Result<Report, Error> {
    if up.kind != "composer" {
        return Err(Error::Http("expected a 'composer' upstream".to_owned()));
    }
    // A subscription is mandatory — an empty require-list would mirror the whole
    // registry (catastrophic for e.g. Packagist). Require at least one entry (an
    // explicit `all` entry is how an operator opts into a require-all).
    if sub.is_empty() {
        return Err(Error::FilterRequired);
    }

    let base = up.base.trim_end_matches('/');
    let body = http_get_string(&format!("{base}/packages.json"))?;
    let root = RootManifest::parse(body.as_bytes()).map_err(|_| Error::BadMetadata {
        package: "packages.json".to_owned(),
    })?;
    // The full set the registry concretely lists (None for pattern-only
    // registries that publish `available-package-patterns` instead). We need the
    // *unfiltered* set to reconcile removals independently of the sync filter.
    let available: Option<std::collections::HashSet<String>> = root
        .available_packages
        .map(|names| names.into_iter().collect());
    let names: Vec<String> = available
        .iter()
        .flatten()
        .filter(|n| sub.matches_name(n))
        .cloned()
        .collect();

    // Archived packages are frozen — never re-mirror them (that would un-freeze
    // version discovery).
    let archived: std::collections::HashSet<String> = catalog
        .list_packages(up.repo_id)
        .await
        .map_err(|e| Error::Catalog(Box::new(e)))?
        .into_iter()
        .filter(|p| p.archived)
        .map(|p| p.name)
        .collect();

    let mut report = Report::default();
    for name in names {
        if archived.contains(&name) {
            report.skipped.push((name, "archived".to_owned()));
            continue;
        }
        match mirror_one_composer_package(catalog, store, up, &name, sub).await {
            Ok(r) => {
                report.mirrored.extend(r.mirrored);
                report.skipped.extend(r.skipped);
            }
            // Don't let one bad package abort a large registry mirror. (A terminal
            // failure already flagged that package broken inside the call.)
            Err(e) => report.skipped.push((name, e.to_string())),
        }
    }

    // Reconcile removals: a package we already mirror from this upstream that has
    // vanished from a concretely-published `available-packages` was yanked
    // upstream → flag it broken (source_gone). Only when the registry actually
    // enumerates (never for pattern-only registries, where absence ≠ removal).
    if let Some(available) = &available {
        for existing in catalog
            .upstream_package_names(up.id)
            .await
            .map_err(|e| Error::Catalog(Box::new(e)))?
        {
            if !available.contains(&existing)
                && catalog
                    .mark_package_broken(up.repo_id, &existing, "source_gone")
                    .await
                    .map_err(|e| Error::Catalog(Box::new(e)))?
            {
                report
                    .skipped
                    .push((existing, "removed upstream".to_owned()));
            }
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
        return Err(Error::Http("expected a 'composer' upstream".to_owned()));
    }
    Ok(up)
}

/// Mirror one package and **record its lifecycle**: on success clear any broken
/// flag and stamp `last_success_at`; on a *terminal* failure flag the (existing)
/// package broken with the classified reason. Non-terminal failures leave the
/// flag untouched (the worker will back off and retry). Lifecycle bookkeeping is
/// best-effort — it never overrides the real mirror outcome.
async fn mirror_one_composer_package(
    catalog: &Catalog,
    store: &(impl BlobStore + Sync),
    up: &sconce_catalog::UpstreamRow,
    package: &str,
    sub: &Subscription,
) -> Result<Report, Error> {
    let result = mirror_one_composer_package_inner(catalog, store, up, package, sub).await;
    match &result {
        Ok(_) => {
            let _ = catalog.mark_package_synced(up.repo_id, package).await;
        }
        // `reason()` is Some exactly for terminal failures.
        Err(e) => {
            if let Some(reason) = e.reason() {
                let _ = catalog
                    .mark_package_broken(up.repo_id, package, reason)
                    .await;
            }
        }
    }
    result
}

async fn mirror_one_composer_package_inner(
    catalog: &Catalog,
    store: &(impl BlobStore + Sync),
    up: &sconce_catalog::UpstreamRow,
    package: &str,
    sub: &Subscription,
) -> Result<Report, Error> {
    // p2 metadata: {base}/p2/{vendor}/{name}.json (the standard metadata-url).
    let base = up.base.trim_end_matches('/');
    let meta_url = format!("{base}/p2/{package}.json");
    let body = http_get_string(&meta_url)?;
    // Parse + apply composer/2.0 minified-expansion. Packagist and many mirrors
    // serve minified p2 documents; the previous hand-rolled parse read the raw
    // sparse-diff entries verbatim and mis-read every entry after the first.
    // composer-wire expands them into full version objects first.
    let versions: Vec<serde_json::Value> = PackageDocument::parse(body.as_bytes())
        .map_err(|_| Error::BadMetadata {
            package: package.to_owned(),
        })?
        .expand()
        .remove(package)
        .ok_or_else(|| Error::BadMetadata {
            package: package.to_owned(),
        })?
        .into_iter()
        .map(serde_json::Value::Object)
        .collect();

    let mut report = Report::default();
    for obj in &versions {
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

        // Apply the subscription's version floor for this package (if any entry
        // opts it in below a minimum).
        if !sub.version_allowed(package, normalized) {
            report
                .skipped
                .push((version.to_owned(), "below version floor".to_owned()));
            continue;
        }

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
            .upsert_package(
                up.repo_id,
                package,
                "composer",
                Some(&serde_json::json!({ "url": base })),
                up.visibility,
            )
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
            // Expand composer/2.0 minified p2 before reading versions (same
            // reasoning as mirror_one_composer_package_inner).
            let versions = PackageDocument::parse(body.as_bytes())
                .map_err(|_| Error::BadMetadata {
                    package: package.to_owned(),
                })?
                .expand()
                .remove(package)
                .unwrap_or_default()
                .into_iter()
                .map(serde_json::Value::Object)
                .collect();
            Ok(Some(versions))
        }
        Err(ureq::Error::Status(404, _)) => Ok(None),
        Err(e) => Err(http_error(&url, e)),
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

/// Map a `ureq` failure to our error, **preserving the HTTP status** (so a
/// permanent `404`/`403` is distinguishable from a transient transport error).
fn http_error(url: &str, e: ureq::Error) -> Error {
    match e {
        ureq::Error::Status(code, _) => Error::HttpStatus {
            code,
            url: url.to_owned(),
        },
        ureq::Error::Transport(t) => Error::Http(format!("{url}: {t}")),
    }
}

fn http_get_string(url: &str) -> Result<String, Error> {
    ureq::get(url)
        .call()
        .map_err(|e| http_error(url, e))?
        .into_string()
        .map_err(|e| Error::Http(format!("{url}: {e}")))
}

fn http_get_bytes(url: &str) -> Result<Vec<u8>, Error> {
    use std::io::Read as _;
    let resp = ureq::get(url).call().map_err(|e| http_error(url, e))?;
    let mut buf = Vec::new();
    resp.into_reader()
        .take(MAX_DIST_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| Error::Http(format!("{url}: {e}")))?;
    if buf.len() as u64 > MAX_DIST_BYTES {
        return Err(Error::Http(format!(
            "dist exceeds {MAX_DIST_BYTES} bytes: {url}"
        )));
    }
    Ok(buf)
}

/// Shared worker: enumerate `repo_path`'s tags and upsert each version, tagging
/// packages with `visibility` and (optionally) binding them to `upstream_id`.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn mirror_checkout(
    repo_id: Uuid,
    repo_path: &Path,
    source_url: &str,
    visibility: Visibility,
    upstream_id: Option<Uuid>,
    sub: &Subscription,
    source_paths: &[String],
    store: &(impl BlobStore + Sync),
    catalog: &Catalog,
) -> Result<Report, Error> {
    let git_url = source_url;
    let mut report = Report::default();

    // A monorepo upstream lists each package's subdirectory; the common single-
    // package case (no explicit paths) mirrors the repo root (`""`).
    let owned_root = [String::new()];
    let paths: &[String] = if source_paths.is_empty() {
        &owned_root
    } else {
        source_paths
    };

    for tag in sconce_git::tags(repo_path)? {
        let Some(parsed) = normalize_tag(&tag) else {
            report
                .skipped
                .push((tag, "unrecognized version".to_owned()));
            continue;
        };

        // The tag's commit time is the version's release time (shared by every
        // package at this tag) — it drives cooldown, so old tags are instantly
        // past cooldown and only genuinely new releases wait.
        let released_at = sconce_git::commit_time(repo_path, &tag).ok();

        // One tag can yield many packages (a monorepo), each at its own subpath.
        for sp in paths {
            let label = |item: &str| {
                if sp.is_empty() {
                    item.to_owned()
                } else {
                    format!("{sp}: {item}")
                }
            };
            let cj_path = if sp.is_empty() {
                "composer.json".to_owned()
            } else {
                format!("{sp}/composer.json")
            };
            let Some(cj_bytes) = sconce_git::read_file(repo_path, &tag, &cj_path)? else {
                // A subpath without a composer.json at this tag is normal (the
                // package was added later) — skip it, don't fail the tag.
                report
                    .skipped
                    .push((tag.clone(), label("no composer.json")));
                continue;
            };
            let composer_json: serde_json::Value = serde_json::from_slice(&cj_bytes)
                .map_err(|_| Error::BadComposerJson { tag: tag.clone() })?;
            let name = composer_json
                .get("name")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| Error::NoName { tag: tag.clone() })?
                .to_owned();

            // Apply the upstream's version floor (if its require-list opts this
            // package in below a minimum). An empty require-list mirrors every tag.
            if !sub.version_allowed(&name, &parsed.normalized) {
                report
                    .skipped
                    .push((tag.clone(), label("below version floor")));
                continue;
            }

            // Archive the package's subtree and store it; the blob is content-
            // addressed. The subtree archives with paths relative to it, so its
            // `dist.shasum` is stable and dedupes independently of siblings.
            let zip = sconce_git::archive_subtree(repo_path, &tag, sp)?.into_zip();
            let blob = store.put(&zip)?;
            // Composer verifies a dist by its sha1 (`dist.shasum`); compute it now
            // so serving never re-reads the blob.
            let dist_shasum = sha1_hex(&zip);
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
                .set_package_source_path(package_id, sp)
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
                    Some(&dist_shasum),
                    None, // source_reference (commit sha) — added later
                    released_at,
                )
                .await
                .map_err(|e| Error::Catalog(Box::new(e)))?;

            report.mirrored.push(Mirrored {
                tag: tag.clone(),
                package: name,
                normalized: parsed.normalized.clone(),
                stability: parsed.stability.clone(),
            });
        }
    }

    // A successful clone+mirror clears any earlier broken flag on the packages it
    // produced (best-effort; distinct names only).
    let mut synced: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for m in &report.mirrored {
        if synced.insert(m.package.as_str()) {
            let _ = catalog.mark_package_synced(repo_id, &m.package).await;
        }
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

    /// A monorepo: one tag, two packages each at a subpath (plus a root
    /// composer.json that is NOT one of the configured paths).
    fn fixture_monorepo() -> std::path::PathBuf {
        let dir = unique_temp("mono");
        std::fs::create_dir_all(&dir).unwrap();
        let write = |rel: &str, name: &str| {
            let p = dir.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(
                &p,
                serde_json::to_vec(&serde_json::json!({"name": name})).unwrap(),
            )
            .unwrap();
        };
        git(&dir, &["init", "-q", "-b", "main"]);
        write("composer.json", "acme/mono"); // root meta — not mirrored
        write("packages/console/composer.json", "acme/console");
        std::fs::write(dir.join("packages/console/Console.php"), b"<?php\n").unwrap();
        write("packages/http/composer.json", "acme/http");
        git(&dir, &["add", "-A"]);
        git(&dir, &["commit", "-qm", "v1"]);
        git(&dir, &["tag", "v1.0.0"]);
        dir
    }

    #[tokio::test]
    async fn monorepo_upstream_mirrors_each_subpath_as_a_package() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let catalog = Catalog::connect(&url).await.unwrap();
        catalog.migrate().await.unwrap();
        let slug = format!("mono{}", std::process::id());
        catalog.create_org(&slug, None).await.unwrap();
        let repo_id = catalog.create_repo(&slug, "r").await.unwrap();
        let cas = unique_temp("cas");
        let store = FsBlobStore::open(&cas).unwrap();
        let repo = fixture_monorepo();

        // A git upstream cloning the local fixture, with two monorepo subpaths.
        let up = catalog
            .create_upstream(
                repo_id,
                "git",
                repo.to_str().unwrap(),
                Visibility::Private,
                None,
                None,
                "basic",
            )
            .await
            .unwrap();
        catalog
            .set_upstream_source_paths(
                repo_id,
                up,
                &["packages/console".to_owned(), "packages/http".to_owned()],
            )
            .await
            .unwrap();

        let report = mirror_upstream(&catalog, &store, up, None).await.unwrap();

        // Both subpath packages mirrored at the one tag; the root meta package is
        // NOT (it isn't a configured path).
        let mut names: Vec<&str> = report.mirrored.iter().map(|m| m.package.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, ["acme/console", "acme/http"]);
        let catalog_names = catalog.all_package_names(repo_id).await.unwrap();
        assert!(!catalog_names.iter().any(|n| n == "acme/mono"));

        std::fs::remove_dir_all(&cas).ok();
        std::fs::remove_dir_all(&repo).ok();
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
        assert!(
            catalog
                .all_package_names(repo_id)
                .await
                .unwrap()
                .contains(&name)
        );
        let mut s = catalog.repo_settings(repo_id).await.unwrap();
        s.allow_private_packages = false;
        catalog.set_repo_settings(repo_id, s).await.unwrap();
        assert!(
            catalog
                .all_package_names(repo_id)
                .await
                .unwrap()
                .contains(&name),
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
        let report = mirror_composer_package(&catalog, &store, up, pkg)
            .await
            .unwrap();
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
        let report = mirror_composer_package(&catalog, &store, up, pkg)
            .await
            .unwrap();
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
    async fn mirrors_mageos_registry_by_subscription() {
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
        catalog
            .set_upstream_requires(
                repo_id,
                up,
                &[sconce_catalog::UpstreamRequire::parse("mage-os/composer*").unwrap()],
            )
            .await
            .unwrap();
        let report = mirror_composer_upstream(&catalog, &store, up)
            .await
            .unwrap();

        // The subscription selected several distinct packages, all in the catalog.
        let names = catalog.all_package_names(repo_id).await.unwrap();
        assert!(
            names.len() >= 2,
            "subscription matched multiple packages, got {names:?}"
        );
        assert!(names.iter().all(|n| n.starts_with("mage-os/composer")));
        assert!(!report.mirrored.is_empty());

        std::fs::remove_dir_all(&cas).ok();
    }

    #[test]
    fn error_classification_terminal_vs_transient() {
        // Bad upstream content — deterministic, won't fix on retry.
        let bad = Error::BadComposerJson { tag: "v1".into() };
        assert!(bad.is_terminal());
        assert_eq!(bad.reason(), Some("bad_content"));
        assert_eq!(
            Error::BadMetadata {
                package: "a/b".into()
            }
            .reason(),
            Some("bad_content")
        );

        // HTTP status: 404/410 gone, 401/403 auth → terminal; 5xx/429 → retry.
        let url = "https://repo.test/p2/a/b.json".to_owned();
        assert_eq!(
            Error::HttpStatus {
                code: 404,
                url: url.clone()
            }
            .reason(),
            Some("source_gone")
        );
        assert!(
            Error::HttpStatus {
                code: 410,
                url: url.clone()
            }
            .is_terminal()
        );
        assert_eq!(
            Error::HttpStatus {
                code: 403,
                url: url.clone()
            }
            .reason(),
            Some("auth_failed")
        );
        for transient in [500u16, 502, 503, 429] {
            let e = Error::HttpStatus {
                code: transient,
                url: url.clone(),
            };
            assert!(!e.is_terminal(), "{transient} should retry");
            assert_eq!(e.reason(), None);
        }

        // Transport error (no status) → transient.
        assert!(!Error::Http("connect timed out".into()).is_terminal());
        // Our own infra / transient corruption → transient.
        assert!(
            !Error::ShasumMismatch {
                package: "a/b".into(),
                version: "1.0".into()
            }
            .is_terminal()
        );

        // Upstream gone / config errors → terminal.
        assert_eq!(Error::UnknownUpstream.reason(), Some("source_gone"));
        assert_eq!(Error::FilterRequired.reason(), Some("config_error"));
    }

    #[test]
    fn clone_stderr_classification() {
        // Auth failures → terminal/auth_failed.
        for s in [
            "fatal: Authentication failed for 'https://github.com/x/y.git'",
            "remote: Permission denied (publickey).",
            "The requested URL returned error: 403",
        ] {
            let e = Error::Clone(s.to_owned());
            assert!(e.is_terminal(), "{s:?} should be terminal");
            assert_eq!(e.reason(), Some("auth_failed"), "{s:?}");
        }
        // Missing repo → terminal/source_gone.
        for s in [
            "remote: Repository not found.",
            "fatal: repository 'https://github.com/x/gone.git' not found",
            "The requested URL returned error: 404",
        ] {
            assert_eq!(
                Error::Clone(s.to_owned()).reason(),
                Some("source_gone"),
                "{s:?}"
            );
        }
        // Transient network → NOT terminal (must back off, never flag broken).
        for s in [
            "fatal: unable to access '...': Could not resolve host: github.com",
            "fatal: unable to access '...': Failed to connect to github.com port 443: Connection timed out",
            "fatal: unable to access '...': The requested URL returned error: 503",
        ] {
            let e = Error::Clone(s.to_owned());
            assert!(!e.is_terminal(), "{s:?} should retry");
            assert_eq!(e.reason(), None, "{s:?}");
        }
    }

    #[test]
    fn credential_types_format_the_clone_invocation() {
        let b = "https://git.example.com/acme/app.git";
        // basic: secret is full userinfo, embedded in the URL.
        assert_eq!(
            build_clone_invocation(b, Some("user:tok"), "basic"),
            (
                "https://user:tok@git.example.com/acme/app.git".to_owned(),
                vec![]
            )
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
        assert_eq!(
            args,
            vec![
                "-c".to_owned(),
                "http.extraHeader=Authorization: Bearer tok".to_owned()
            ]
        );
        // No credential, or a non-http base, injects nothing.
        assert_eq!(
            build_clone_invocation(b, None, "basic"),
            (b.to_owned(), vec![])
        );
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
            .set_upstream_requires(
                repo_id,
                up,
                &[sconce_catalog::UpstreamRequire::parse("mage-os/composer*").unwrap()],
            )
            .await
            .unwrap();

        let report = mirror_upstream(&catalog, &store, up, None).await.unwrap();
        assert!(!report.mirrored.is_empty());
        let names = catalog.all_package_names(repo_id).await.unwrap();
        assert!(
            names.len() >= 2,
            "filter selected several packages: {names:?}"
        );
        assert!(names.iter().all(|n| n.starts_with("mage-os/composer")));

        std::fs::remove_dir_all(&cas).ok();
    }

    /// Lifecycle end-to-end against the real Mage-OS registry: a package we
    /// mirror that vanishes from `available-packages` is flagged broken on the
    /// next sync; archiving it stops it being re-flagged. Network + DB; `#[ignore]`.
    #[tokio::test]
    #[ignore = "network: mirrors from repo.mage-os.org"]
    async fn registry_reconcile_flags_removed_then_archive_silences() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let catalog = Catalog::connect(&url).await.unwrap();
        catalog.migrate().await.unwrap();
        let slug = format!("recon{}", std::process::id());
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
        catalog
            .set_upstream_requires(
                repo_id,
                up,
                &[sconce_catalog::UpstreamRequire::parse("mage-os/composer*").unwrap()],
            )
            .await
            .unwrap();

        // Real sync: a few mage-os/composer* packages land healthy.
        mirror_upstream(&catalog, &store, up, None).await.unwrap();

        // Simulate a package we mirrored that no longer exists upstream: bind a
        // ghost name (never in available-packages) to this upstream.
        let ghost = "mage-os/ghost-removed";
        let pid = catalog
            .upsert_package(repo_id, ghost, "composer", None, Visibility::Public)
            .await
            .unwrap();
        catalog.set_package_upstream(pid, up).await.unwrap();

        // Next sync reconciles: the ghost is flagged broken/source_gone; the real
        // packages stay healthy.
        mirror_upstream(&catalog, &store, up, None).await.unwrap();
        let pkgs = catalog.list_packages(repo_id).await.unwrap();
        let g = pkgs.iter().find(|p| p.name == ghost).unwrap();
        assert_eq!(g.sync_health, "broken");
        assert_eq!(g.broken_reason.as_deref(), Some("source_gone"));
        assert!(
            pkgs.iter()
                .filter(|p| p.name != ghost)
                .all(|p| p.sync_health == "ok"),
            "real packages stay healthy"
        );

        // Archive the ghost → it's no longer reconciled (archived masks it).
        catalog.archive_package(repo_id, ghost).await.unwrap();
        mirror_upstream(&catalog, &store, up, None).await.unwrap();
        let g = catalog
            .list_packages(repo_id)
            .await
            .unwrap()
            .into_iter()
            .find(|p| p.name == ghost)
            .unwrap();
        assert!(g.archived, "ghost stays archived (frozen), not churned");

        std::fs::remove_dir_all(&cas).ok();
    }

    #[tokio::test]
    async fn composer_sync_without_a_subscription_is_refused() {
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

        // Empty require-list → both the worker entry point and the explicit
        // registry path refuse, BEFORE any network call (so this needs no network).
        assert!(matches!(
            mirror_upstream(&catalog, &store, up, None).await,
            Err(Error::FilterRequired)
        ));
        assert!(matches!(
            mirror_composer_upstream(&catalog, &store, up).await,
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
            .create_upstream(
                repo_id,
                "git",
                repo.to_str().unwrap(),
                Visibility::Private,
                None,
                None,
                "basic",
            )
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
