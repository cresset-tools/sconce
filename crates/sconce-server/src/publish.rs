//! Package **publish** (push) API — the inverse of the mirror worker.
//!
//! A client (the `sconce publish` CLI / GitHub Action) uploads a package as a
//! gzip'd tar of its directory; sconce untars it, re-archives it through the same
//! deterministic [`sconce_archive`] used for mirrored packages (so identical trees
//! dedupe and `dist.shasum` stays stable), stores the zip in the CAS, and writes an
//! **immutable** `package_versions` row that flows through the normal approval queue.
//!
//! Two shapes, same ingest pipeline:
//! - **Single-shot** `PUT …/packages/{vendor}/{name}/{version}` — whole tar.gz body.
//! - **Chunked** — an upload session whose parts are staged in the CAS and assembled
//!   server-side, so a per-request body limit isn't the ceiling on package size.
//!
//! Auth is a short-lived **publish token** (minted only by the OIDC publish
//! exchange), resolved by [`PublishAuthedRepo`].

use std::collections::HashMap;
use std::io::Read;
use std::path::Component;

use axum::body::Bytes;
use axum::extract::{FromRequestParts, Path, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Json, Response};
use flate2::read::GzDecoder;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use sconce_archive::{CanonicalArchive, Entry, Mode};
use sconce_cas::{AnyBlobStore, BlobId, BlobStore};
use sconce_catalog::{PublishOutcome, Visibility};

use crate::{AppError, AppState, blocking, extract_token, parse_hex32};

/// How long an unfinished upload session lives before the worker sweep aborts it.
const UPLOAD_TTL_SECS: i64 = 24 * 3600;

/// Per-request body cap (single-shot upload and each chunk). The axum default is
/// 2 MiB — far too small for a package.
pub(crate) fn max_upload_bytes() -> u64 {
    env_bytes("SCONCE_MAX_UPLOAD_BYTES", 100 * 1024 * 1024)
}

/// Ceiling on a whole assembled package — both the sum of chunk sizes and the
/// unpacked tar size (the latter guards against a gzip bomb).
pub(crate) fn max_package_bytes() -> u64 {
    env_bytes("SCONCE_MAX_PACKAGE_BYTES", 1024 * 1024 * 1024)
}

fn env_bytes(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

// ---------------------------------------------------------------------------
// Auth extractor
// ---------------------------------------------------------------------------

/// The repository a publish request is authenticated for. Taking
/// `PublishAuthedRepo(repo_id)` as a handler argument resolves the bearer
/// **publish token** and checks it authorizes the repo named in the path — before
/// the handler body (and thus the upload) runs. Modeled on `api::AuthedRepo`, but
/// backed by `resolve_publish_token` so read/service tokens can never publish.
pub(crate) struct PublishAuthedRepo(pub(crate) Uuid);

impl FromRequestParts<AppState> for PublishAuthedRepo {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let Path(params) = Path::<HashMap<String, String>>::from_request_parts(parts, state)
            .await
            .map_err(|_| AppError::NotFound)?;
        let org = params.get("org").ok_or(AppError::NotFound)?;
        let repo = params.get("repo").ok_or(AppError::NotFound)?;
        let token = extract_token(&parts.headers).ok_or(AppError::Unauthorized)?;
        let token_repo = state
            .catalog
            .resolve_publish_token(&token)
            .await?
            .ok_or(AppError::Unauthorized)?;
        let path_repo = state
            .catalog
            .resolve_repo(org, repo)
            .await?
            .ok_or(AppError::NotFound)?;
        if token_repo == path_repo {
            Ok(PublishAuthedRepo(path_repo))
        } else {
            Err(AppError::Forbidden)
        }
    }
}

// ---------------------------------------------------------------------------
// Single-shot upload
// ---------------------------------------------------------------------------

/// `PUT /{org}/{repo}/packages/{vendor}/{name}/{version}` — the whole tar.gz as the
/// request body (bounded by `SCONCE_MAX_UPLOAD_BYTES`).
pub(crate) async fn publish_single(
    PublishAuthedRepo(repo_id): PublishAuthedRepo,
    State(s): State<AppState>,
    Path((_org, _repo, vendor, name, version)): Path<(String, String, String, String, String)>,
    body: Bytes,
) -> Result<Response, AppError> {
    let expected_name = format!("{vendor}/{name}");
    let store = s.store.clone();
    let input = body.to_vec();
    let cap = max_package_bytes();
    let prepared =
        spawn_prepare(move || archive_targz(&input, &expected_name, &store, cap)).await?;
    let outcome = persist(&s, repo_id, &vendor, &name, &version, prepared).await?;
    Ok(publish_response(outcome))
}

// ---------------------------------------------------------------------------
// Chunked / resumable upload
// ---------------------------------------------------------------------------

/// `POST /{org}/{repo}/packages/{vendor}/{name}/{version}/uploads` — open a session.
pub(crate) async fn upload_init(
    PublishAuthedRepo(repo_id): PublishAuthedRepo,
    State(s): State<AppState>,
    Path((_org, _repo, vendor, name, version)): Path<(String, String, String, String, String)>,
) -> Result<Json<Value>, AppError> {
    let id = s
        .catalog
        .create_upload_session(repo_id, &vendor, &name, &version, UPLOAD_TTL_SECS)
        .await?;
    Ok(Json(json!({
        "upload_id": id,
        "part_size_limit": max_upload_bytes(),
        "max_package_bytes": max_package_bytes(),
    })))
}

/// `PUT /{org}/{repo}/uploads/{upload_id}/parts/{n}` — stage one chunk (1-based).
pub(crate) async fn upload_part(
    PublishAuthedRepo(repo_id): PublishAuthedRepo,
    State(s): State<AppState>,
    Path((_org, _repo, upload_id, n)): Path<(String, String, Uuid, i32)>,
    body: Bytes,
) -> Result<StatusCode, AppError> {
    open_session(&s, upload_id, repo_id).await?;
    if n < 1 {
        return Err(AppError::BadRequest("part number must be >= 1".into()));
    }
    let size = i64::try_from(body.len()).unwrap_or(i64::MAX);
    let bytes = body.to_vec();
    let store = s.store.clone();
    let blob = blocking(move || store.put(&bytes)).await?;
    // Record the blob so the orphan GC's grace window doesn't reap it mid-upload.
    s.catalog.upsert_blob(blob.as_bytes(), size).await?;
    s.catalog
        .record_upload_part(upload_id, n, blob.as_bytes(), size)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /{org}/{repo}/uploads/{upload_id}` — session status + recorded parts, so a
/// resuming client can skip parts it already sent.
pub(crate) async fn upload_status(
    PublishAuthedRepo(repo_id): PublishAuthedRepo,
    State(s): State<AppState>,
    Path((_org, _repo, upload_id)): Path<(String, String, Uuid)>,
) -> Result<Json<Value>, AppError> {
    let session = s
        .catalog
        .upload_session(upload_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if session.repo_id != repo_id {
        return Err(AppError::Forbidden);
    }
    let parts = s.catalog.upload_parts(upload_id).await?;
    let parts: Vec<Value> = parts
        .iter()
        .map(|p| {
            json!({
                "part_number": p.part_number,
                "sha256": hex(&p.chunk_sha256),
                "size": p.size_bytes,
            })
        })
        .collect();
    Ok(Json(json!({
        "upload_id": session.id,
        "status": session.status,
        "parts": parts,
    })))
}

/// The complete-upload request body: how many parts the client sent, and the
/// sha256 of the assembled tar.gz (for an end-to-end integrity check).
#[derive(Deserialize)]
pub(crate) struct CompleteReq {
    parts: i32,
    sha256: String,
}

/// `POST /{org}/{repo}/uploads/{upload_id}/complete` — assemble + ingest.
pub(crate) async fn upload_complete(
    PublishAuthedRepo(repo_id): PublishAuthedRepo,
    State(s): State<AppState>,
    Path((_org, _repo, upload_id)): Path<(String, String, Uuid)>,
    Json(req): Json<CompleteReq>,
) -> Result<Response, AppError> {
    let session = open_session(&s, upload_id, repo_id).await?;
    let parts = s.catalog.upload_parts(upload_id).await?;

    // Manifest must be exactly parts 1..=req.parts, contiguous.
    if parts.len() != usize::try_from(req.parts.max(0)).unwrap_or(0) {
        return Err(AppError::BadRequest(format!(
            "expected {} parts, {} are staged",
            req.parts,
            parts.len()
        )));
    }
    for (i, p) in parts.iter().enumerate() {
        if p.part_number != i32::try_from(i).unwrap_or(i32::MAX) + 1 {
            return Err(AppError::BadRequest(
                "staged parts are not contiguous from 1".into(),
            ));
        }
    }
    let expected_sha = parse_hex32(&req.sha256)
        .ok_or_else(|| AppError::BadRequest("sha256 must be 64 hex chars".into()))?;
    let cap = max_package_bytes();
    let total: u64 = parts
        .iter()
        .map(|p| u64::try_from(p.size_bytes).unwrap_or(0))
        .sum();
    if total > cap {
        return Err(AppError::PayloadTooLarge);
    }

    let ids: Vec<BlobId> = parts
        .iter()
        .map(|p| as_blob_id(&p.chunk_sha256))
        .collect::<Option<_>>()
        .ok_or(AppError::NotFound)?;
    let store = s.store.clone();
    let expected_name = format!("{}/{}", session.vendor, session.name);
    let prepared = spawn_prepare(move || {
        assemble_and_archive(&store, &ids, expected_sha, &expected_name, cap)
    })
    .await?;

    let outcome = persist(
        &s,
        repo_id,
        &session.vendor,
        &session.name,
        &session.version,
        prepared,
    )
    .await?;
    s.catalog.set_upload_status(upload_id, "completed").await?;
    Ok(publish_response(outcome))
}

/// `DELETE /{org}/{repo}/uploads/{upload_id}` — abort. Staged chunks are reclaimed
/// by the orphan GC.
pub(crate) async fn upload_abort(
    PublishAuthedRepo(repo_id): PublishAuthedRepo,
    State(s): State<AppState>,
    Path((_org, _repo, upload_id)): Path<(String, String, Uuid)>,
) -> Result<StatusCode, AppError> {
    let session = s
        .catalog
        .upload_session(upload_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if session.repo_id != repo_id {
        return Err(AppError::Forbidden);
    }
    s.catalog.set_upload_status(upload_id, "aborted").await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Load a session and require it belongs to `repo_id` and is still `open`.
async fn open_session(
    s: &AppState,
    upload_id: Uuid,
    repo_id: Uuid,
) -> Result<sconce_catalog::UploadSession, AppError> {
    let session = s
        .catalog
        .upload_session(upload_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if session.repo_id != repo_id {
        return Err(AppError::Forbidden);
    }
    if session.status != "open" {
        return Err(AppError::Conflict("upload session is not open".into()));
    }
    Ok(session)
}

// ---------------------------------------------------------------------------
// Ingest pipeline (shared)
// ---------------------------------------------------------------------------

/// The re-archived, CAS-stored result of an upload, ready to persist.
struct Prepared {
    blob: [u8; 32],
    size: i64,
    composer_json: Value,
    dist_shasum: String,
}

/// A failure while preparing an upload. Distinct from a plain storage error so
/// each maps to the right client status instead of a blanket 500.
#[derive(Debug)]
enum PrepareError {
    Bad(String),
    TooLarge,
    /// A staged chunk was reclaimed (e.g. GC ran) before `complete`.
    Gone,
    Io(std::io::Error),
}

impl From<std::io::Error> for PrepareError {
    fn from(e: std::io::Error) -> Self {
        PrepareError::Io(e)
    }
}

impl From<PrepareError> for AppError {
    fn from(e: PrepareError) -> Self {
        match e {
            PrepareError::Bad(m) => AppError::BadRequest(m),
            PrepareError::TooLarge => AppError::PayloadTooLarge,
            PrepareError::Gone => AppError::Gone,
            PrepareError::Io(e) => AppError::Storage(e),
        }
    }
}

/// Run the (blocking, CPU-bound) prepare step off the async executor and flatten
/// the join + prepare errors into an `AppError`.
async fn spawn_prepare(
    f: impl FnOnce() -> Result<Prepared, PrepareError> + Send + 'static,
) -> Result<Prepared, AppError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| AppError::Storage(std::io::Error::other(e)))?
        .map_err(AppError::from)
}

/// Fetch the staged chunks in order, verify the assembled sha256, then archive.
fn assemble_and_archive(
    store: &AnyBlobStore,
    ids: &[BlobId],
    expected_sha: [u8; 32],
    expected_name: &str,
    cap: u64,
) -> Result<Prepared, PrepareError> {
    use sha2::{Digest, Sha256};
    let mut input = Vec::new();
    let mut hasher = Sha256::new();
    for id in ids {
        let bytes = store.get(id)?.ok_or(PrepareError::Gone)?;
        hasher.update(&bytes);
        input.extend_from_slice(&bytes);
        if u64::try_from(input.len()).unwrap_or(u64::MAX) > cap {
            return Err(PrepareError::TooLarge);
        }
    }
    if hasher.finalize().as_slice() != expected_sha {
        return Err(PrepareError::Bad(
            "assembled upload does not match the declared sha256".into(),
        ));
    }
    archive_targz(&input, expected_name, store, cap)
}

/// The heart of the ingest: gunzip + untar a package, re-archive it deterministically,
/// validate its `composer.json`, and store the zip in the CAS.
fn archive_targz(
    input: &[u8],
    expected_name: &str,
    store: &AnyBlobStore,
    cap: u64,
) -> Result<Prepared, PrepareError> {
    let mut ar = tar::Archive::new(GzDecoder::new(input));
    let mut archive = CanonicalArchive::new();
    let mut composer_json: Option<Value> = None;
    let mut unpacked: u64 = 0;

    let entries = ar
        .entries()
        .map_err(|_| PrepareError::Bad("body is not a valid gzip'd tar".into()))?;
    for entry in entries {
        let mut entry = entry.map_err(|_| PrepareError::Bad("corrupt tar entry".into()))?;
        let kind = entry.header().entry_type();
        let raw = entry
            .path()
            .map_err(|_| PrepareError::Bad("tar entry has a non-UTF-8 path".into()))?
            .to_path_buf();
        // Never touches disk, but reject traversal so archives stay well-formed.
        if raw.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(PrepareError::Bad(format!(
                "illegal path in archive: {}",
                raw.display()
            )));
        }
        let rel = raw.to_string_lossy().replace('\\', "/");
        let rel = rel.strip_prefix("./").unwrap_or(&rel).to_owned();
        if rel.is_empty() {
            continue;
        }

        if kind.is_dir() {
            continue;
        }
        if kind.is_symlink() {
            let target = entry
                .link_name()
                .map_err(|_| PrepareError::Bad("bad symlink in archive".into()))?
                .ok_or_else(|| PrepareError::Bad("symlink without a target".into()))?;
            let content = target.to_string_lossy().as_bytes().to_vec();
            archive.add(Entry::new(rel, Mode::Symlink, content));
        } else if kind.is_file() {
            let mode = entry.header().mode().unwrap_or(0o644);
            let mut content = Vec::new();
            entry
                .read_to_end(&mut content)
                .map_err(|_| PrepareError::Bad("could not read a tar entry".into()))?;
            unpacked = unpacked.saturating_add(u64::try_from(content.len()).unwrap_or(u64::MAX));
            if unpacked > cap {
                return Err(PrepareError::TooLarge);
            }
            if rel == "composer.json" {
                composer_json =
                    Some(serde_json::from_slice(&content).map_err(|_| {
                        PrepareError::Bad("composer.json is not valid JSON".into())
                    })?);
            }
            let m = if mode & 0o111 != 0 {
                Mode::Executable
            } else {
                Mode::File
            };
            archive.add(Entry::new(rel, m, content));
        }
        // Anything else (hard link, device, fifo) is skipped.
    }

    let composer_json = composer_json
        .ok_or_else(|| PrepareError::Bad("archive has no composer.json at its root".into()))?;
    let name = composer_json
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| PrepareError::Bad("composer.json has no \"name\" field".into()))?;
    if name != expected_name {
        return Err(PrepareError::Bad(format!(
            "composer.json name \"{name}\" does not match the upload path \"{expected_name}\""
        )));
    }
    if archive.is_empty() {
        return Err(PrepareError::Bad("archive is empty".into()));
    }

    let zip = archive.into_zip();
    let dist_shasum = sha1_hex(&zip);
    let size = i64::try_from(zip.len()).unwrap_or(i64::MAX);
    let blob = store.put(&zip)?;
    Ok(Prepared {
        blob: *blob.as_bytes(),
        size,
        composer_json,
        dist_shasum,
    })
}

/// Persist the prepared upload: register the blob, upsert the package (provenance
/// `kind = "upload"`, no upstream), and insert the version immutably.
async fn persist(
    s: &AppState,
    repo_id: Uuid,
    vendor: &str,
    name: &str,
    version: &str,
    prepared: Prepared,
) -> Result<PublishOutcome, AppError> {
    let (normalized, stability) = normalize_version(version).ok_or_else(|| {
        AppError::BadRequest(format!(
            "\"{version}\" is not a numeric Composer version (e.g. 1.2.0, v2.0.0-beta1)"
        ))
    })?;
    let pkg_name = format!("{vendor}/{name}");
    s.catalog.upsert_blob(&prepared.blob, prepared.size).await?;
    let source = json!({ "kind": "upload" });
    let package_id = s
        .catalog
        .upsert_package(
            repo_id,
            &pkg_name,
            "upload",
            Some(&source),
            Visibility::Private,
        )
        .await
        .map_err(|e| match e {
            sconce_catalog::UpsertPackageError::Policy(m) => AppError::BadRequest(m),
            sconce_catalog::UpsertPackageError::Db(e) => AppError::Catalog(e),
        })?;
    let outcome = s
        .catalog
        .insert_pushed_version(
            package_id,
            version,
            &normalized,
            &stability,
            &prepared.composer_json,
            &prepared.blob,
            &prepared.dist_shasum,
            now_unix(),
        )
        .await?;
    Ok(outcome)
}

fn publish_response(outcome: PublishOutcome) -> Response {
    match outcome {
        PublishOutcome::Created => {
            (StatusCode::CREATED, Json(json!({ "status": "created" }))).into_response()
        }
        PublishOutcome::AlreadyPublished => {
            (StatusCode::OK, Json(json!({ "status": "exists" }))).into_response()
        }
        PublishOutcome::Conflict => (
            StatusCode::CONFLICT,
            Json(json!({
                "status": "conflict",
                "error": "this version is already published with different contents",
            })),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// Normalize a published version string with Composer's parser; `None` unless it's
/// a numeric version (branch-style versions like `dev-main` are not publishable).
fn normalize_version(v: &str) -> Option<(String, String)> {
    use composer_semver::Version;
    use composer_semver::version::VersionKind;
    let parsed = Version::parse(v).ok()?;
    if !matches!(parsed.kind, VersionKind::Numeric { .. }) {
        return None;
    }
    // Read stability (borrows) before moving `normalized` out of `parsed`.
    let stability = parsed.stability().as_str().to_owned();
    Some((parsed.normalized, stability))
}

/// Composer verifies dists by sha1, so it is precomputed from the zip bytes.
fn sha1_hex(bytes: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    hex(&Sha1::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn as_blob_id(bytes: &[u8]) -> Option<BlobId> {
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Some(BlobId::from_bytes(arr))
}

fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

#[cfg(test)]
#[allow(clippy::items_after_statements, clippy::too_many_lines)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static UNIQ: AtomicU64 = AtomicU64::new(0);

    fn tmp_store() -> AnyBlobStore {
        let n = UNIQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("sconce-pub-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        AnyBlobStore::open(Some(&dir)).unwrap()
    }

    /// Build a gzip'd tar from `(path, content, mode)` regular-file entries.
    fn targz(entries: &[(&str, &[u8], u32)]) -> Vec<u8> {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut b = tar::Builder::new(&mut enc);
            for (path, content, mode) in entries {
                let mut h = tar::Header::new_gnu();
                h.set_size(content.len() as u64);
                h.set_mode(*mode);
                h.set_entry_type(tar::EntryType::Regular);
                h.set_cksum();
                b.append_data(&mut h, path, *content).unwrap();
            }
            b.finish().unwrap();
        }
        enc.finish().unwrap()
    }

    /// A pushed tarball is re-archived to *exactly* the same bytes as building the
    /// canonical archive directly from the same tree — the property that makes
    /// pushed and mirrored packages dedupe and share a stable `dist.shasum`.
    #[test]
    fn archive_targz_is_deterministic_and_validates() {
        let cj = br#"{"name":"acme/tool"}"#;
        let tar = targz(&[
            ("composer.json", cj, 0o644),
            ("src/Foo.php", b"hi", 0o644),
            ("bin/run", b"run", 0o755),
        ]);
        let store = tmp_store();
        let prepared = archive_targz(&tar, "acme/tool", &store, 1 << 30).expect("archive");

        // Independently build the expected canonical zip.
        let mut expected = CanonicalArchive::new();
        expected.add(Entry::new("composer.json", Mode::File, cj.to_vec()));
        expected.add(Entry::new("src/Foo.php", Mode::File, b"hi".to_vec()));
        expected.add(Entry::new("bin/run", Mode::Executable, b"run".to_vec()));
        let expected_zip = expected.into_zip();
        assert_eq!(&prepared.blob, BlobId::of(&expected_zip).as_bytes());
        assert_eq!(prepared.dist_shasum, sha1_hex(&expected_zip));
        assert_eq!(prepared.composer_json["name"], "acme/tool");
        // The blob was actually stored.
        assert!(store.exists(&BlobId::from_bytes(prepared.blob)).unwrap());
    }

    #[test]
    fn archive_targz_rejects_name_mismatch_and_missing_composer_json() {
        let store = tmp_store();
        let tar = targz(&[("composer.json", br#"{"name":"acme/tool"}"#, 0o644)]);
        assert!(matches!(
            archive_targz(&tar, "acme/other", &store, 1 << 30),
            Err(PrepareError::Bad(_))
        ));
        let no_cj = targz(&[("src/Foo.php", b"hi", 0o644)]);
        assert!(matches!(
            archive_targz(&no_cj, "acme/tool", &store, 1 << 30),
            Err(PrepareError::Bad(_))
        ));
    }

    // --- HTTP round-trip (needs Postgres; skipped when DATABASE_URL is unset) ---

    use axum::body::Body;
    use axum::http::{Request, header};
    use http_body_util::BodyExt;
    use sconce_catalog::Catalog;
    use tower::ServiceExt;

    async fn body_text(resp: axum::response::Response) -> String {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    fn put_pkg(uri: &str, token: &str, body: Vec<u8>) -> Request<Body> {
        Request::builder()
            .method("PUT")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/tar+gzip")
            .body(Body::from(body))
            .unwrap()
    }

    #[tokio::test]
    async fn publish_http_roundtrip() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let cat = Catalog::connect(&url).await.expect("connect");
        cat.migrate().await.expect("migrate");
        let n = UNIQ.fetch_add(1, Ordering::Relaxed);
        let slug = format!("pub{}-{n}", std::process::id());
        cat.create_org(&slug, None).await.unwrap();
        let repo_id = cat.create_repo(&slug, "r").await.unwrap();
        // A second repo, to prove a token for one repo can't publish to another.
        let other_id = cat.create_repo(&slug, "other").await.unwrap();
        let _ = repo_id;
        let _ = other_id;

        let token = cat.create_publish_token(repo_id, "t", 900).await.unwrap();
        let other_token = cat.create_publish_token(other_id, "t", 900).await.unwrap();
        let read = cat.create_token(repo_id, Some("r"), None).await.unwrap();

        let app = crate::router(cat.clone(), tmp_store(), "http://localhost".to_owned());

        let cj = br#"{"name":"acme/tool","description":"x"}"#;
        let tar = targz(&[("composer.json", cj, 0o644), ("src/A.php", b"a", 0o644)]);

        // 1. No credential → 401.
        let r = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/{slug}/r/packages/acme/tool/1.0.0"))
                    .body(Body::from(tar.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);

        // 2. A publish token for another repo → 403.
        let r = app
            .clone()
            .oneshot(put_pkg(
                &format!("/{slug}/r/packages/acme/tool/1.0.0"),
                &other_token,
                tar.clone(),
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);

        // 3. Valid publish → 201, and the version is persisted with the right blob.
        let r = app
            .clone()
            .oneshot(put_pkg(
                &format!("/{slug}/r/packages/acme/tool/1.0.0"),
                &token,
                tar.clone(),
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::CREATED);

        let expected = archive_targz(&tar, "acme/tool", &tmp_store(), 1 << 30).unwrap();
        let versions = cat.package_versions(repo_id, "acme/tool").await.unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].dist_blob_sha256, Some(expected.blob));

        // 4. The version serves via p2 and its dist downloads (with a read token).
        let r = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/{slug}/r/p2/acme/tool.json"))
                    .header(header::AUTHORIZATION, format!("Bearer {read}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        assert!(body_text(r).await.contains("1.0.0"));

        let dist_uri = format!("/{slug}/r/dist/acme/tool/{}.zip", hex(&expected.blob));
        let r = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&dist_uri)
                    .header(header::AUTHORIZATION, format!("Bearer {read}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);

        // 5. Idempotent re-push of identical bytes → 200; divergent bytes → 409.
        let r = app
            .clone()
            .oneshot(put_pkg(
                &format!("/{slug}/r/packages/acme/tool/1.0.0"),
                &token,
                tar.clone(),
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);

        let tar2 = targz(&[
            ("composer.json", cj, 0o644),
            ("src/A.php", b"CHANGED", 0o644),
        ]);
        let r = app
            .clone()
            .oneshot(put_pkg(
                &format!("/{slug}/r/packages/acme/tool/1.0.0"),
                &token,
                tar2,
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::CONFLICT);

        // 6. Chunked upload of a new version reassembles to the same bytes as a
        //    single-shot of the same tree.
        let init = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/{slug}/r/packages/acme/tool/2.0.0/uploads"))
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(init.status(), StatusCode::OK);
        let init: serde_json::Value = serde_json::from_str(&body_text(init).await).unwrap();
        let upload_id = init["upload_id"].as_str().unwrap().to_owned();

        // Two parts split down the middle.
        let mid = tar.len() / 2;
        for (i, slice) in [&tar[..mid], &tar[mid..]].iter().enumerate() {
            let part = i + 1;
            let r = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("PUT")
                        .uri(format!("/{slug}/r/uploads/{upload_id}/parts/{part}"))
                        .header(header::AUTHORIZATION, format!("Bearer {token}"))
                        .body(Body::from(slice.to_vec()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(r.status(), StatusCode::NO_CONTENT);
        }

        let sha = {
            use sha2::{Digest, Sha256};
            hex(&Sha256::digest(&tar))
        };
        let complete = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/{slug}/r/uploads/{upload_id}/complete"))
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({ "parts": 2, "sha256": sha })).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(complete.status(), StatusCode::CREATED);

        let versions = cat.package_versions(repo_id, "acme/tool").await.unwrap();
        let v2 = versions.iter().find(|v| v.version == "2.0.0").unwrap();
        assert_eq!(v2.dist_blob_sha256, Some(expected.blob));
    }
}
