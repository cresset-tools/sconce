//! Management API (`/api/v1`) — a small REST/JSON surface a seller's commerce
//! front-end (e.g. the Magento module) uses to **provision and manage license
//! keys** without touching the database or the admin UI. Distinct from the
//! Composer wire API (which serves packages) and the admin UI (session auth):
//! every route here authenticates with a repo-scoped **service token** presented
//! as `Authorization: Bearer <token>` and speaks JSON.
//!
//! Endpoints (all under `/api/v1/repos/{org}/{repo}`):
//! - `GET editions` — list editions (for mapping a product to a SKU).
//! - `POST license-keys` — issue against an edition (`Idempotency-Key` = order id).
//! - `GET license-keys/{id}` — inspect: entitlements, bound, install info.
//! - `POST license-keys/{id}/renew` — extend the update bound.
//! - `DELETE license-keys/{id}` — revoke.

use axum::extract::{FromRequestParts, Path, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use uuid::Uuid;

use super::{AppState, extract_token, repo_base};
use sconce_catalog::LicenseDetail;

/// A management-API failure, rendered as `{"error": "..."}` with a status.
pub(crate) enum ApiError {
    /// Missing or invalid service token.
    Unauthorized,
    /// A valid token, but for a different repository than the path.
    Forbidden,
    NotFound(&'static str),
    BadRequest(String),
    Db(sconce_catalog::SqlxError),
}

impl From<sconce_catalog::SqlxError> for ApiError {
    fn from(e: sconce_catalog::SqlxError) -> Self {
        ApiError::Db(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            ApiError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "missing or invalid service token".to_owned(),
            ),
            ApiError::Forbidden => (
                StatusCode::FORBIDDEN,
                "this service token is not valid for that repository".to_owned(),
            ),
            ApiError::NotFound(what) => (StatusCode::NOT_FOUND, format!("{what} not found")),
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            ApiError::Db(e) => {
                tracing::error!(error = %e, "management API database error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal error".to_owned(),
                )
            }
        };
        (status, Json(json!({ "error": msg }))).into_response()
    }
}

/// Authenticate a request: the bearer service token must resolve to the same
/// repository the path names. Returns that repo id.
async fn authed_repo(
    s: &AppState,
    headers: &HeaderMap,
    org: &str,
    repo: &str,
) -> Result<Uuid, ApiError> {
    let token = extract_token(headers).ok_or(ApiError::Unauthorized)?;
    let token_repo = s
        .catalog
        .resolve_service_token(&token)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    let path_repo = s
        .catalog
        .resolve_repo(org, repo)
        .await?
        .ok_or(ApiError::NotFound("repository"))?;
    if token_repo == path_repo {
        Ok(path_repo)
    } else {
        Err(ApiError::Forbidden)
    }
}

/// The repository a management-API request is authenticated for, as an axum
/// extractor. Taking `AuthedRepo(repo_id)` as a handler argument performs the
/// full bearer-token check ([`authed_repo`]) before the handler body runs — so a
/// handler on this surface **cannot** serve a request without authenticating: the
/// auth is in the type signature, not a line each handler must remember to call.
pub(crate) struct AuthedRepo(pub(crate) Uuid);

impl FromRequestParts<AppState> for AuthedRepo {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Read `{org}`/`{repo}` by name so this works for every /api/v1 route
        // regardless of whether it also has an `{id}` segment.
        let Path(params) = Path::<HashMap<String, String>>::from_request_parts(parts, state)
            .await
            .map_err(|_| ApiError::NotFound("repository"))?;
        let org = params.get("org").ok_or(ApiError::NotFound("repository"))?;
        let repo = params.get("repo").ok_or(ApiError::NotFound("repository"))?;
        authed_repo(state, &parts.headers, org, repo)
            .await
            .map(AuthedRepo)
    }
}

/// The JSON body for a license — shared by issue / inspect / renew. Carries the
/// Composer install info so the front-end can render buyer instructions.
fn license_json(s: &AppState, org: &str, repo: &str, d: &LicenseDetail) -> Value {
    let url = repo_base(&s.base_url, org, repo);
    let host = url
        .split_once("://")
        .map_or(url.as_str(), |(_, rest)| rest)
        .split('/')
        .next()
        .unwrap_or("")
        .to_owned();
    json!({
        "id": d.id.to_string(),
        "buyer": d.buyer,
        "status": d.status,
        "edition": d.edition,
        "packages": d.packages,
        // Recovered plaintext key (null if no secret key is configured). Auth
        // never uses this — it's for showing the buyer their key.
        "key": d.key,
        "bound": { "until": d.bound.until, "major": d.bound.major },
        "install": {
            "repository_url": url,
            "host": host,
            "auth": "http-basic — the license key is the password (username ignored)",
        },
    })
}

/// Pull the `Idempotency-Key` header (the commerce order id), if present.
fn idempotency_key(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn parse_license_id(id: &str) -> Result<Uuid, ApiError> {
    id.parse::<Uuid>()
        .map_err(|_| ApiError::BadRequest("invalid license id".to_owned()))
}

#[derive(Deserialize)]
pub(crate) struct IssueReq {
    /// Edition name or slug to issue against.
    edition: String,
    /// Buyer reference (email / order id / company).
    buyer: Option<String>,
}

/// `POST /api/v1/repos/{org}/{repo}/license-keys` — issue a key against an
/// edition. Idempotent on the `Idempotency-Key` header: a repeat returns the
/// existing license (200, no `key`) instead of a duplicate; a fresh issue is
/// `201` and includes the one-time `key`.
pub(crate) async fn issue_license(
    State(s): State<AppState>,
    Path((org, repo)): Path<(String, String)>,
    AuthedRepo(repo_id): AuthedRepo,
    headers: HeaderMap,
    Json(req): Json<IssueReq>,
) -> Result<Response, ApiError> {
    let idem = idempotency_key(&headers);
    let edition_id = s
        .catalog
        .find_edition(repo_id, req.edition.trim())
        .await?
        .ok_or_else(|| ApiError::BadRequest(format!("no edition '{}' in {org}/{repo}", req.edition)))?;
    let buyer = req.buyer.as_deref().map(str::trim).filter(|b| !b.is_empty());
    let issued = s
        .catalog
        .issue_from_edition(repo_id, edition_id, buyer, idem)
        .await?
        .ok_or_else(|| ApiError::BadRequest(format!("edition '{}' is inactive", req.edition)))?;
    let detail = s
        .catalog
        .license_detail(repo_id, issued.id)
        .await?
        .ok_or(ApiError::NotFound("license"))?;
    let mut body = license_json(&s, &org, &repo, &detail);
    body["created"] = json!(issued.created);
    // The plaintext key exists only on first creation (never re-derivable).
    if let Some(key) = issued.key {
        body["key"] = json!(key);
    }
    let status = if issued.created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(body)).into_response())
}

/// `GET /api/v1/repos/{org}/{repo}/license-keys/{id}` — inspect a key.
pub(crate) async fn inspect_license(
    State(s): State<AppState>,
    Path((org, repo, id)): Path<(String, String, String)>,
    AuthedRepo(repo_id): AuthedRepo,
) -> Result<Json<Value>, ApiError> {
    let detail = s
        .catalog
        .license_detail(repo_id, parse_license_id(&id)?)
        .await?
        .ok_or(ApiError::NotFound("license"))?;
    Ok(Json(license_json(&s, &org, &repo, &detail)))
}

/// `POST /api/v1/repos/{org}/{repo}/license-keys/{id}/renew` — extend the time
/// bound by the edition's period (subscription renewal). `400` if the key isn't
/// time-bounded (version/perpetual editions renew by issuing a new edition) or is
/// revoked. Idempotent on the `Idempotency-Key` header: a retried renewal webhook
/// returns the current bound instead of extending the key a second time.
pub(crate) async fn renew_license(
    State(s): State<AppState>,
    Path((org, repo, id)): Path<(String, String, String)>,
    AuthedRepo(repo_id): AuthedRepo,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let idem = idempotency_key(&headers);
    let lic = parse_license_id(&id)?;
    s.catalog
        .renew_license(repo_id, lic, idem)
        .await?
        .ok_or_else(|| {
            ApiError::BadRequest(
                "license not found, revoked, or not issued from a time-bounded edition \
                 (renew a version/perpetual key by issuing a new edition)"
                    .to_owned(),
            )
        })?;
    let detail = s
        .catalog
        .license_detail(repo_id, lic)
        .await?
        .ok_or(ApiError::NotFound("license"))?;
    Ok(Json(license_json(&s, &org, &repo, &detail)))
}

/// `DELETE /api/v1/repos/{org}/{repo}/license-keys/{id}` — revoke a key.
pub(crate) async fn revoke_license(
    State(s): State<AppState>,
    Path((_org, _repo, id)): Path<(String, String, String)>,
    AuthedRepo(repo_id): AuthedRepo,
) -> Result<Response, ApiError> {
    if s.catalog.revoke_license(repo_id, parse_license_id(&id)?).await? {
        Ok(StatusCode::NO_CONTENT.into_response())
    } else {
        Err(ApiError::NotFound("license"))
    }
}

/// `GET /api/v1/repos/{org}/{repo}/editions` — list editions, for mapping a
/// commerce product to a SKU.
pub(crate) async fn list_editions(
    State(s): State<AppState>,
    Path((_org, _repo)): Path<(String, String)>,
    AuthedRepo(repo_id): AuthedRepo,
) -> Result<Json<Value>, ApiError> {
    let editions: Vec<Value> = s
        .catalog
        .list_editions(repo_id)
        .await?
        .iter()
        .map(|e| {
            json!({
                "id": e.id.to_string(),
                "name": e.name,
                "slug": e.slug,
                "target_set": e.set_name,
                "bound": e.bound.label(),
                "snapshot": e.snapshot,
                "active": e.active,
            })
        })
        .collect();
    Ok(Json(json!({ "editions": editions })))
}
