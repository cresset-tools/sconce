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
//! Every route requires a valid read token (`Authorization: Bearer <token>` or
//! HTTP basic with the token as the password). A fresh, tokenless install is
//! fully closed — secure by default; create a token with `sconce token create`.
//! Per-token scoping / multi-tenant access control arrives with that phase.

#![forbid(unsafe_code)]

use axum::Router;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use base64::Engine as _;
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
    let state = AppState {
        catalog,
        store,
        base_url,
    };
    Router::new()
        .route("/packages.json", get(packages_json))
        .route("/p2/{*rest}", get(p2))
        .route("/dist/{*rest}", get(dist))
        // Every route requires a valid token — the repo is private. A fresh,
        // tokenless install is fully closed; create one with `sconce token create`.
        .route_layer(middleware::from_fn_with_state(state.clone(), require_token))
        .with_state(state)
}

/// Auth gate: accept a valid token via `Authorization: Bearer <token>` or
/// HTTP basic (token as the password), else 401.
async fn require_token(State(s): State<AppState>, req: Request, next: Next) -> Response {
    match extract_token(req.headers()) {
        Some(token) => match s.catalog.token_valid(&token).await {
            Ok(true) => next.run(req).await,
            Ok(false) => unauthorized(),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        },
        None => unauthorized(),
    }
}

/// Pull a token from the `Authorization` header (Bearer, or basic-auth password).
fn extract_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    if let Some(bearer) = value.strip_prefix("Bearer ") {
        return Some(bearer.trim().to_owned());
    }
    if let Some(basic) = value.strip_prefix("Basic ") {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(basic.trim())
            .ok()?;
        let creds = String::from_utf8(decoded).ok()?;
        // "username:password" — the token is the password (username ignored),
        // matching the Magento/GitLab convention.
        return creds.split_once(':').map(|(_, pass)| pass.to_owned());
    }
    None
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Basic realm=\"sconce\"")],
    )
        .into_response()
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

    // Apply the repo's update policy (cooldown / manual approval / holds) so
    // clients only ever see versions that have cleared the supply-chain gate.
    let (mode, cooldown_days) = s.catalog.update_policy().await?;
    let versions = s
        .catalog
        .visible_versions(package, &mode, cooldown_days)
        .await?;
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

    fn headers_with(auth: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, auth.parse().unwrap());
        h
    }

    #[test]
    fn extracts_bearer_and_basic_tokens() {
        assert_eq!(
            extract_token(&headers_with("Bearer sconce_abc")).as_deref(),
            Some("sconce_abc")
        );
        // basic: base64("anyuser:sconce_xyz") → token is the password.
        let basic = base64::engine::general_purpose::STANDARD.encode("anyuser:sconce_xyz");
        assert_eq!(
            extract_token(&headers_with(&format!("Basic {basic}"))).as_deref(),
            Some("sconce_xyz")
        );
        assert_eq!(extract_token(&HeaderMap::new()), None);
        assert_eq!(extract_token(&headers_with("Weird foo")), None);
    }
}
