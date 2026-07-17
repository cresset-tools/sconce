//! Database **snapshot** (dataset) API — a sibling of [`crate::publish`].
//!
//! A workload (the scheduled dump job) uploads a `.jibsdump` for an environment
//! (and optionally a data **profile** — `?profile=small|perf|…`, default `full`),
//! authenticated by the same short-lived **publish token** and staged through the
//! same chunked-upload machinery as a package. Unlike a package the bytes are
//! stored **verbatim** — a dump is opaque, not re-archived — and registered as a
//! [`sconce_catalog::Snapshot`] with a moving per-(environment, profile) `latest`
//! pointer.
//!
//! Downstream, a client fetches `…/snapshots/{env}/latest`, which 302s to a
//! short-lived presigned URL exactly like a dist download.
//!
//! The chunked routes (`…/uploads/{id}/parts|status|abort|complete`) are shared
//! with `publish`; a snapshot session is opened here with `kind = "snapshot"` and
//! [`crate::publish::upload_complete`] dispatches assembly back to [`finish_upload`].

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Json, Response};
use serde_json::{Value, json};
use uuid::Uuid;

use sconce_cas::{AnyBlobStore, BlobId, BlobStore};
use sconce_catalog::UploadSession;

use crate::publish::PublishAuthedRepo;
use crate::{AppError, AppState};

/// How long an unfinished snapshot upload session lives before the sweep aborts it.
const UPLOAD_TTL_SECS: i64 = 24 * 3600;

/// The data profile addressed when a request names none — the complete dump.
const DEFAULT_PROFILE: &str = "full";

/// `?profile=<name>` on the snapshot routes — the data-profile dimension beside
/// the `{env}` path segment (a query param, so the profile-less URLs stay
/// byte-identical and keep meaning `full`).
#[derive(Debug, serde::Deserialize)]
pub(crate) struct ProfileQuery {
    profile: Option<String>,
}

impl ProfileQuery {
    /// The addressed profile: the non-empty `?profile=`, else `full`.
    fn name(&self) -> &str {
        match self.profile.as_deref().map(str::trim) {
            Some(p) if !p.is_empty() => p,
            _ => DEFAULT_PROFILE,
        }
    }
}

/// Lifetime of a presigned snapshot-download redirect — short, but with slack for
/// clock skew between sconce and the object store.
const PRESIGN_SECS: u64 = 300;

/// Ceiling on a whole assembled snapshot (the sum of chunk sizes). Dumps are large,
/// so this is generous; it is buffered in memory during assembly, so it also bounds
/// peak memory. Override with `SCONCE_MAX_SNAPSHOT_BYTES`.
fn max_snapshot_bytes() -> u64 {
    std::env::var("SCONCE_MAX_SNAPSHOT_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2 * 1024 * 1024 * 1024)
}

// ---------------------------------------------------------------------------
// Upload — single-shot + chunked (chunked reuses publish's part routes)
// ---------------------------------------------------------------------------

/// `PUT /{org}/{repo}/snapshots/{env}` — the whole `.jibsdump` as the request body
/// (bounded by the shared upload body limit; larger dumps use the chunked flow).
pub(crate) async fn upload_single(
    PublishAuthedRepo(repo_id): PublishAuthedRepo,
    State(s): State<AppState>,
    Path((_org, _repo, environment)): Path<(String, String, String)>,
    Query(q): Query<ProfileQuery>,
    body: Bytes,
) -> Result<Response, AppError> {
    let bytes = body.to_vec();
    let store = s.store.clone();
    let (blob, size) = crate::blocking(move || {
        let size = i64::try_from(bytes.len()).unwrap_or(i64::MAX);
        store.put(&bytes).map(|id| (id, size))
    })
    .await?;
    register_snapshot(&s, repo_id, &environment, q.name(), blob, size).await?;
    Ok(created_response(&environment, q.name(), &blob))
}

/// `POST /{org}/{repo}/snapshots/{env}/uploads` — open a chunked snapshot session.
/// Parts, status, abort and complete then reuse the shared `…/uploads/{id}/…`
/// routes; `complete` dispatches back to [`finish_upload`] by the session's `kind`.
pub(crate) async fn upload_init(
    PublishAuthedRepo(repo_id): PublishAuthedRepo,
    State(s): State<AppState>,
    Path((_org, _repo, environment)): Path<(String, String, String)>,
    Query(q): Query<ProfileQuery>,
) -> Result<Json<Value>, AppError> {
    let id = s
        .catalog
        .create_snapshot_upload_session(repo_id, &environment, q.name(), UPLOAD_TTL_SECS)
        .await?;
    Ok(Json(json!({
        "upload_id": id,
        "part_size_limit": crate::publish::max_upload_bytes(),
        "max_snapshot_bytes": max_snapshot_bytes(),
    })))
}

/// Finish a chunked **snapshot** upload: assemble the staged parts, verify the
/// declared sha256, store the assembled dump verbatim in the CAS, and register it.
/// Called by [`crate::publish::upload_complete`] once it has validated the part
/// manifest (contiguous `1..=parts`) shared with package uploads.
pub(crate) async fn finish_upload(
    s: &AppState,
    session: &UploadSession,
    ids: &[BlobId],
    expected_sha: [u8; 32],
    total: u64,
) -> Result<Response, AppError> {
    if total > max_snapshot_bytes() {
        return Err(AppError::PayloadTooLarge);
    }
    let environment = session.environment.clone().unwrap_or_default();
    let profile = session
        .profile
        .clone()
        .unwrap_or_else(|| DEFAULT_PROFILE.to_string());
    let store = s.store.clone();
    let ids = ids.to_vec();
    let cap = max_snapshot_bytes();
    let (blob, size) =
        tokio::task::spawn_blocking(move || assemble_snapshot(&store, &ids, expected_sha, cap))
            .await
            .map_err(|e| AppError::Storage(std::io::Error::other(e)))??;
    register_snapshot(s, session.repo_id, &environment, &profile, blob, size).await?;
    Ok(created_response(&environment, &profile, &blob))
}

/// Fetch the staged chunks in order, verify the assembled sha256, and store the
/// whole `.jibsdump` as one CAS blob (verbatim — no re-archive). The individual
/// part blobs are left at refcount 0 for the orphan GC to reclaim.
fn assemble_snapshot(
    store: &AnyBlobStore,
    ids: &[BlobId],
    expected_sha: [u8; 32],
    cap: u64,
) -> Result<(BlobId, i64), AppError> {
    use sha2::{Digest, Sha256};
    let mut input = Vec::new();
    let mut hasher = Sha256::new();
    for id in ids {
        let bytes = store.get(id)?.ok_or(AppError::Gone)?;
        hasher.update(&bytes);
        input.extend_from_slice(&bytes);
        if u64::try_from(input.len()).unwrap_or(u64::MAX) > cap {
            return Err(AppError::PayloadTooLarge);
        }
    }
    if hasher.finalize().as_slice() != expected_sha {
        return Err(AppError::BadRequest(
            "assembled upload does not match the declared sha256".into(),
        ));
    }
    let size = i64::try_from(input.len()).unwrap_or(i64::MAX);
    let blob = store.put(&input)?;
    Ok((blob, size))
}

/// Record the blob (size + `last_seen_at`, before the GC grace window), insert the
/// snapshot row (which refcounts the blob via trigger), and move `latest`.
async fn register_snapshot(
    s: &AppState,
    repo_id: Uuid,
    environment: &str,
    profile: &str,
    blob: BlobId,
    size: i64,
) -> Result<Uuid, AppError> {
    s.catalog.upsert_blob(blob.as_bytes(), size).await?;
    let id = s
        .catalog
        .create_snapshot(repo_id, environment, profile, blob.as_bytes(), size, None)
        .await?;
    s.catalog
        .advance_latest(repo_id, environment, profile, id)
        .await?;
    Ok(id)
}

fn created_response(environment: &str, profile: &str, blob: &BlobId) -> Response {
    (
        StatusCode::CREATED,
        Json(json!({
            "status": "created",
            "environment": environment,
            "profile": profile,
            "digest": blob.to_hex(),
        })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Download
// ---------------------------------------------------------------------------

/// `GET /{org}/{repo}/snapshots/{env}/latest[?profile=<name>]` — download the
/// environment's current latest snapshot for a data profile (`full` when the
/// query names none). Gated on a repo **read** token.
pub(crate) async fn download_latest(
    State(s): State<AppState>,
    Path((org, repo, environment)): Path<(String, String, String)>,
    Query(q): Query<ProfileQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let repo_id = authorize_read(&s, &org, &repo, &headers).await?;
    let snapshot = s
        .catalog
        .resolve_latest(repo_id, &environment, q.name())
        .await?
        .ok_or(AppError::NotFound)?;
    serve_blob(&s, snapshot.blob_sha256).await
}

/// `GET /{org}/{repo}/snapshots/{env}/{digest}` — download a **pinned** snapshot by
/// its 64-hex blob digest, for reproducible pulls (a lockfile / CI parity can pin
/// the exact bytes a dev used). The digest must name a snapshot registered in this
/// repo+environment — so a read token can't fish arbitrary CAS blobs by sha. Gated
/// on a repo **read** token.
pub(crate) async fn download_digest(
    State(s): State<AppState>,
    Path((org, repo, environment, digest)): Path<(String, String, String, String)>,
    Query(q): Query<ProfileQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let repo_id = authorize_read(&s, &org, &repo, &headers).await?;
    let sha = crate::parse_hex32(&digest).ok_or(AppError::NotFound)?;
    let snapshot = s
        .catalog
        .resolve_snapshot_by_digest(repo_id, &environment, q.name(), &sha)
        .await?
        .ok_or(AppError::NotFound)?;
    serve_blob(&s, snapshot.blob_sha256).await
}

/// Resolve `(org, repo)` and require a valid repo **read** token (rejects license
/// keys and publish tokens, so only a serving credential can pull prod data).
async fn authorize_read(
    s: &AppState,
    org: &str,
    repo: &str,
    headers: &HeaderMap,
) -> Result<Uuid, AppError> {
    let repo_id = s
        .catalog
        .resolve_repo(org, repo)
        .await?
        .ok_or(AppError::NotFound)?;
    let token = crate::extract_token(headers).ok_or(AppError::Unauthorized)?;
    if !s.catalog.token_valid(repo_id, &token).await? {
        return Err(AppError::Unauthorized);
    }
    Ok(repo_id)
}

/// Serve a snapshot blob: 302 to a short-lived presigned URL on an object-store
/// backend (the dist model — one HEAD first so a dangling blob 404s as sconce, not
/// store XML), or proxy the bytes on a filesystem backend.
async fn serve_blob(s: &AppState, blob_sha256: [u8; 32]) -> Result<Response, AppError> {
    let id = BlobId::from_bytes(blob_sha256);
    if let Some(url) = s.store.presigned_get(&id, PRESIGN_SECS) {
        let store = s.store.clone();
        if !crate::blocking(move || store.exists(&id)).await? {
            return Err(AppError::NotFound);
        }
        return Ok((StatusCode::FOUND, [(header::LOCATION, url)]).into_response());
    }
    let store = s.store.clone();
    match crate::blocking(move || store.get(&id)).await? {
        Some(bytes) => {
            Ok(([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response())
        }
        None => Err(AppError::NotFound),
    }
}
