//! HTTP server for the Composer **v2** wire API.
//!
//! Three routes, mapped onto [`sconce_metadata`] + the [`sconce_cas`] blob store:
//!
//! - `GET /packages.json` — the root document (`metadata-url` + available list).
//! - `GET /p2/{vendor}/{name}.json` — per-package metadata. The `~dev` variant
//!   Composer also requests is served as an empty set (we only mirror tags, no
//!   dev branches yet).
//! - `GET /dist/{vendor}/{name}/{sha256}.zip` — the content-addressed download;
//!   the sha256 in the path resolves the blob in the CAS.
//!
//! No authentication yet — that arrives with the multi-tenant phase. This is the
//! self-hosted, single-repo serving path.

#![forbid(unsafe_code)]

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use sconce_cas::{BlobId, BlobStore, FsBlobStore};
use sconce_catalog::Catalog;
use serde_json::json;

/// Shared handler state.
#[derive(Clone)]
struct AppState {
    catalog: Catalog,
    store: FsBlobStore,
    /// Public base URL used to build absolute metadata/dist URLs.
    base_url: String,
}

/// Build the router for a repository served from `catalog` + `store` at
/// `base_url`.
pub fn router(catalog: Catalog, store: FsBlobStore, base_url: String) -> Router {
    Router::new()
        .route("/packages.json", get(packages_json))
        .route("/p2/{*rest}", get(p2))
        .route("/dist/{*rest}", get(dist))
        .with_state(AppState {
            catalog,
            store,
            base_url,
        })
}

/// Bind `listen` and serve until the process is stopped.
pub async fn serve(
    catalog: Catalog,
    store: FsBlobStore,
    base_url: String,
    listen: std::net::SocketAddr,
) -> std::io::Result<()> {
    let app = router(catalog, store, base_url);
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, app).await
}

async fn packages_json(State(s): State<AppState>) -> Result<Json<serde_json::Value>, AppError> {
    let names = s.catalog.all_package_names().await?;
    Ok(Json(sconce_metadata::render_root(&names, &s.base_url)))
}

async fn p2(
    State(s): State<AppState>,
    Path(rest): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    // `rest` is "vendor/name.json" or "vendor/name~dev.json".
    let stem = rest.strip_suffix(".json").ok_or(AppError::NotFound)?;
    let (package, is_dev) = match stem.strip_suffix("~dev") {
        Some(p) => (p, true),
        None => (stem, false),
    };

    if is_dev {
        // No dev (branch) versions yet — return an empty, valid document.
        return Ok(Json(json!({ "packages": { package: [] } })));
    }

    let versions = s.catalog.package_versions(package).await?;
    Ok(Json(sconce_metadata::render_package(
        package,
        &versions,
        &s.base_url,
    )))
}

async fn dist(State(s): State<AppState>, Path(rest): Path<String>) -> Result<Response, AppError> {
    // `rest` is "vendor/name/<sha256>.zip"; the final segment carries the sha.
    let file = rest.rsplit('/').next().ok_or(AppError::NotFound)?;
    let hex = file.strip_suffix(".zip").ok_or(AppError::NotFound)?;
    let sha = parse_hex32(hex).ok_or(AppError::NotFound)?;

    match s.store.get(&BlobId::from_bytes(sha))? {
        Some(bytes) => Ok(([(header::CONTENT_TYPE, "application/zip")], bytes).into_response()),
        None => Err(AppError::NotFound),
    }
}

/// Parse 64 lowercase/uppercase hex chars into 32 bytes.
fn parse_hex32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Handler error → HTTP status.
#[derive(Debug, thiserror::Error)]
enum AppError {
    #[error("not found")]
    NotFound,
    #[error("catalog error")]
    Catalog(#[from] sconce_catalog::SqlxError),
    #[error("storage error")]
    Storage(#[from] std::io::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::NotFound => StatusCode::NOT_FOUND.into_response(),
            AppError::Catalog(_) | AppError::Storage(_) => {
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex32_roundtrips() {
        let bytes = [0xabu8; 32];
        let hex = "ab".repeat(32);
        assert_eq!(parse_hex32(&hex), Some(bytes));
        assert_eq!(parse_hex32("nothex"), None);
        assert_eq!(parse_hex32(&"a".repeat(63)), None);
    }
}
