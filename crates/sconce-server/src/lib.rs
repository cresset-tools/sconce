//! HTTP server for the Composer **v2** wire API.
//!
//! Multi-tenant: each repository is served under `/{org}/{repo}/…`, mapped onto
//! [`sconce_metadata`] + the [`sconce_cas`] blob store:
//!
//! - `GET /{org}/{repo}/packages.json` — root document (`metadata-url` + list).
//! - `GET /{org}/{repo}/p2/{vendor}/{name}.json` — per-package metadata, filtered
//!   by that repo's update policy. The `~dev` variant is served empty (we only
//!   mirror tags, no dev branches yet).
//! - `GET /{org}/{repo}/dist/{vendor}/{name}/{sha256}.zip` — content-addressed
//!   download; the sha256 resolves the blob in the CAS.
//!
//! Every route requires a credential **valid for that repository**
//! (`Authorization: Bearer <…>` or HTTP basic with the secret as the password).
//! Two credential kinds: a repo **token** unlocks the whole repo; a seller
//! **license key** unlocks only its entitled (purchased) packages — unentitled
//! packages serve an empty document. A credential from one repo can't read
//! another. Unknown repo → 404; missing/invalid credential → 401.

#![forbid(unsafe_code)]

pub mod ci;
pub mod oidc;
pub mod ui;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use base64::Engine as _;
use sconce_cas::{BlobId, BlobStore, FsBlobStore};
use sconce_catalog::Catalog;
use serde_json::json;
use uuid::Uuid;

/// Shared handler state.
#[derive(Clone)]
struct AppState {
    catalog: Catalog,
    store: FsBlobStore,
    /// Public base URL; each repository is served under `<base>/<org>/<repo>`.
    base_url: String,
}

/// Build the router. Repositories are served under `/{org}/{repo}/…`, each
/// gated by a token valid *for that repository*.
pub fn router(catalog: Catalog, store: FsBlobStore, base_url: String) -> Router {
    Router::new()
        .route("/{org}/{repo}/packages.json", get(packages_json))
        .route("/{org}/{repo}/p2/{*rest}", get(p2))
        .route("/{org}/{repo}/dist/{*rest}", get(dist))
        .route("/oauth/ci", post(oauth_ci))
        .with_state(AppState {
            catalog,
            store,
            base_url,
        })
}

/// What a credential is allowed to see in a repository.
enum Access {
    /// A repo read token: every package in the repo.
    Full,
    /// A seller license key: only the entitled (purchased) package names.
    Licensed(std::collections::HashSet<String>),
}

impl Access {
    /// Whether `package` is readable under this access.
    fn allows(&self, package: &str) -> bool {
        match self {
            Access::Full => true,
            Access::Licensed(entitled) => entitled.contains(package),
        }
    }
}

/// Resolve `(org, repo)` to a repository id and the access a credential grants.
/// 404 if the repository is unknown, 401 if the credential is missing/invalid.
///
/// A repo **token** grants [`Access::Full`]; a seller **license key** grants
/// [`Access::Licensed`] to its entitled packages only.
async fn authorize(
    s: &AppState,
    org: &str,
    repo: &str,
    headers: &HeaderMap,
) -> Result<(Uuid, Access, sconce_catalog::PolicyOverride), AppError> {
    let repo_id = s
        .catalog
        .resolve_repo(org, repo)
        .await?
        .ok_or(AppError::NotFound)?;
    let cred = extract_token(headers).ok_or(AppError::Unauthorized)?;

    if let Some(policy) = s.catalog.resolve_token_policy(repo_id, &cred).await? {
        return Ok((repo_id, Access::Full, policy));
    }
    if let Some(license_id) = s.catalog.resolve_license(repo_id, &cred).await? {
        let entitled = s
            .catalog
            .entitled_package_names(license_id)
            .await?
            .into_iter()
            .collect();
        let policy = s.catalog.license_policy(license_id).await?;
        return Ok((repo_id, Access::Licensed(entitled), policy));
    }
    Err(AppError::Unauthorized)
}

/// The absolute base URL for one repository, e.g. `https://host/acme/client-a`.
fn repo_base(base_url: &str, org: &str, repo: &str) -> String {
    format!("{}/{org}/{repo}", base_url.trim_end_matches('/'))
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

async fn packages_json(
    State(s): State<AppState>,
    Path((org, repo)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let (repo_id, access, _policy) = authorize(&s, &org, &repo, &headers).await?;
    let names = match access {
        Access::Full => s.catalog.all_package_names(repo_id).await?,
        Access::Licensed(entitled) => {
            let mut v: Vec<String> = entitled.into_iter().collect();
            v.sort();
            v
        }
    };
    Ok(Json(sconce_metadata::render_root(
        &names,
        &repo_base(&s.base_url, &org, &repo),
    )))
}

async fn p2(
    State(s): State<AppState>,
    Path((org, repo, rest)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let (repo_id, access, policy) = authorize(&s, &org, &repo, &headers).await?;

    // `rest` is "vendor/name.json" or "vendor/name~dev.json".
    let stem = rest.strip_suffix(".json").ok_or(AppError::NotFound)?;
    let (package, is_dev) = match stem.strip_suffix("~dev") {
        Some(p) => (p, true),
        None => (stem, false),
    };

    // A license key only unlocks its entitled packages; everything else (and the
    // dev variant) is an empty document.
    if is_dev || !access.allows(package) {
        return Ok(Json(json!({ "packages": { package: [] } })));
    }

    // Apply the supply-chain gate (cooldown / manual approval / holds) so clients
    // only ever see versions that have cleared it. The presenting credential's
    // policy override can tighten — never loosen — the repo default.
    let (repo_mode, repo_cooldown) = s.catalog.update_policy(repo_id).await?;
    let (mode, cooldown_days) = policy.effective(&repo_mode, repo_cooldown);
    let versions = s
        .catalog
        .visible_versions(repo_id, package, &mode, cooldown_days)
        .await?;
    Ok(Json(sconce_metadata::render_package(
        package,
        &versions,
        &repo_base(&s.base_url, &org, &repo),
    )))
}

async fn dist(
    State(s): State<AppState>,
    Path((org, repo, rest)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    authorize(&s, &org, &repo, &headers).await?;

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
/// CI OIDC exchange request: a repository + the workflow's platform OIDC JWT.
#[derive(serde::Deserialize)]
struct CiExchange {
    repository: String,
    jwt: String,
}

/// Trade a CI OIDC JWT for a short-lived repo token (zero stored secret). The
/// JWT is validated against each of the repo's CI policies (signature via the
/// issuer's JWKS, `iss`/`aud`/`exp`, then the claim matchers); the first match
/// mints a token. 401 if nothing matches.
async fn oauth_ci(
    State(s): State<AppState>,
    Json(req): Json<CiExchange>,
) -> Result<Json<serde_json::Value>, AppError> {
    let (org, repo) = req.repository.split_once('/').ok_or(AppError::NotFound)?;
    let repo_id = s
        .catalog
        .resolve_repo(org, repo)
        .await?
        .ok_or(AppError::NotFound)?;

    for policy in s.catalog.ci_policies(repo_id).await? {
        // A JWKS fetch failure for one issuer shouldn't doom other policies.
        let Ok(jwks) = ci::fetch_jwks(&policy.issuer).await else {
            continue;
        };
        let Ok(claims) = ci::validate_jwt(&req.jwt, &jwks, &policy.issuer, &policy.audience) else {
            continue;
        };
        if !ci::claims_match(&claims, &policy.claims) {
            continue;
        }
        // Matched → mint a short-lived CI token labelled with the workload `sub`.
        let label = claims
            .get("sub")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("ci");
        let token = s
            .catalog
            .create_ci_token(repo_id, label, policy.token_ttl_secs)
            .await?;
        return Ok(Json(json!({
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": policy.token_ttl_secs,
        })));
    }
    Err(AppError::Unauthorized)
}

#[derive(Debug, thiserror::Error)]
enum AppError {
    #[error("not found")]
    NotFound,
    #[error("unauthorized")]
    Unauthorized,
    #[error("catalog error")]
    Catalog(#[from] sconce_catalog::SqlxError),
    #[error("storage error")]
    Storage(#[from] std::io::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::NotFound => StatusCode::NOT_FOUND.into_response(),
            AppError::Unauthorized => unauthorized(),
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
