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
//! - `POST license-keys/{id}/renew` — extend the update bound (standalone keys).
//! - `POST license-keys/{id}/editions` — attach an edition to a key (a repeat
//!   buyer accumulates purchases onto one key; the edition's bound lands on the
//!   entitlement edge, 0047).
//! - `POST license-keys/{id}/editions/{edition}/renew` — extend one edition's
//!   entitlement-edge time bound (renewal on an accumulated key).
//! - `DELETE license-keys/{id}/editions/{edition}` — detach an edition (refund
//!   of one line item on a shared key).
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
use sconce_catalog::{EditionAdd, LicenseDetail};

/// A management-API failure, rendered as `{"error": "..."}` with a status.
pub(crate) enum ApiError {
    /// Missing or invalid service token.
    Unauthorized,
    /// A valid token, but for a different repository than the path.
    Forbidden,
    NotFound(&'static str),
    BadRequest(String),
    /// The request is valid but conflicts with the resource's state (e.g. an
    /// edition that can't be merged onto a shared key).
    Conflict(String),
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
            ApiError::Conflict(m) => (StatusCode::CONFLICT, m),
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
    /// Issue an **account key**: the key itself is unbounded and the edition's
    /// bound lands on the entitlement edge (0047), so later purchases of any
    /// edition can merge onto it. Front-ends that accumulate purchases onto one
    /// key per customer should always set this. Default `false` = legacy
    /// standalone shape (bound on the key).
    #[serde(default)]
    account: bool,
}

/// `POST /api/v1/repos/{org}/{repo}/license-keys` — issue a key against an
/// edition. Idempotent on the `Idempotency-Key` header: a repeat returns the
/// existing license (200, no `key`) instead of a duplicate; a fresh issue is
/// `201` and includes the one-time `key`. With `"account": true` the key is
/// minted unbounded and the edition's bound lands on its entitlement edge.
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
        .ok_or_else(|| {
            ApiError::BadRequest(format!("no edition '{}' in {org}/{repo}", req.edition))
        })?;
    let buyer = req
        .buyer
        .as_deref()
        .map(str::trim)
        .filter(|b| !b.is_empty());
    let issued = if req.account {
        s.catalog
            .issue_account_key_from_edition(repo_id, edition_id, buyer, idem)
            .await?
    } else {
        s.catalog
            .issue_from_edition(repo_id, edition_id, buyer, idem)
            .await?
    }
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

/// `POST /api/v1/repos/{org}/{repo}/license-keys/{id}/editions/{edition}/renew`
/// — extend one edition's **entitlement-edge** time bound by its period: the
/// renewal path for accumulated keys, where each purchase carries its own bound
/// (0047) and the key itself stays unbounded. `400` if the key is
/// missing/revoked, the edition isn't time-bounded, or the key has no
/// explicitly-bounded edge for it (a standalone key renews via `…/renew`).
/// Idempotent on the `Idempotency-Key` header like key-level renewal.
pub(crate) async fn renew_license_edition(
    State(s): State<AppState>,
    Path((org, repo, id, edition)): Path<(String, String, String, String)>,
    AuthedRepo(repo_id): AuthedRepo,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let idem = idempotency_key(&headers);
    let lic = parse_license_id(&id)?;
    let edition_id = s
        .catalog
        .find_edition(repo_id, edition.trim())
        .await?
        .ok_or_else(|| ApiError::BadRequest(format!("no edition '{edition}' in {org}/{repo}")))?;
    let new_until = s
        .catalog
        .renew_license_edition(repo_id, lic, edition_id, idem)
        .await?
        .ok_or_else(|| {
            ApiError::BadRequest(
                "license not found or revoked, edition not time-bounded, or no bounded \
                 entitlement for it on this key (a standalone key renews via /renew)"
                    .to_owned(),
            )
        })?;
    let detail = s
        .catalog
        .license_detail(repo_id, lic)
        .await?
        .ok_or(ApiError::NotFound("license"))?;
    let mut body = license_json(&s, &org, &repo, &detail);
    body["edition_bound"] = json!({ "edition": edition, "until": new_until });
    Ok(Json(body))
}

#[derive(Deserialize)]
pub(crate) struct AddEditionReq {
    /// Edition name or slug to attach to the key.
    edition: String,
}

/// `POST /api/v1/repos/{org}/{repo}/license-keys/{id}/editions` — attach an
/// edition's content to an existing key, so a repeat buyer accumulates their
/// purchases onto one key (one Composer auth entry unlocks everything they own).
/// A time/version-bounded edition merges too: its bound lands on the entitlement
/// edge (0047), serving each package under its own ceiling. `200` with the
/// updated license on success (or an idempotent replay). `409` when the edition
/// can't be merged onto this key (the key itself is bounded — merge targets are
/// unbounded account keys — or a snapshot edition) — the caller should issue a
/// standalone key instead. `404` if the key isn't in this repo, `400` for an
/// unknown/inactive edition.
pub(crate) async fn add_license_edition(
    State(s): State<AppState>,
    Path((org, repo, id)): Path<(String, String, String)>,
    AuthedRepo(repo_id): AuthedRepo,
    Json(req): Json<AddEditionReq>,
) -> Result<Response, ApiError> {
    let license_id = parse_license_id(&id)?;
    let edition_id = s
        .catalog
        .find_edition(repo_id, req.edition.trim())
        .await?
        .ok_or_else(|| {
            ApiError::BadRequest(format!("no edition '{}' in {org}/{repo}", req.edition))
        })?;
    match s
        .catalog
        .add_edition_to_license(repo_id, license_id, edition_id)
        .await?
    {
        EditionAdd::Added => {
            let detail = s
                .catalog
                .license_detail(repo_id, license_id)
                .await?
                .ok_or(ApiError::NotFound("license"))?;
            Ok((StatusCode::OK, Json(license_json(&s, &org, &repo, &detail))).into_response())
        }
        EditionAdd::Standalone => Err(ApiError::Conflict(format!(
            "edition '{}' can't be merged onto this key (issue a standalone key instead)",
            req.edition
        ))),
        EditionAdd::NoKey => Err(ApiError::NotFound("license")),
        EditionAdd::NoEdition => Err(ApiError::BadRequest(format!(
            "edition '{}' is inactive",
            req.edition
        ))),
    }
}

/// `DELETE /api/v1/repos/{org}/{repo}/license-keys/{id}/editions/{edition}` —
/// detach an edition's content from a key (a refund of one line item on a shared
/// key). `204` whether or not the entitlement was present (idempotent); `404` if
/// the key isn't in this repo. Never revokes the key even if it now entitles
/// nothing — the caller revokes once its last line item is refunded.
pub(crate) async fn remove_license_edition(
    State(s): State<AppState>,
    Path((_org, _repo, id, edition)): Path<(String, String, String, String)>,
    AuthedRepo(repo_id): AuthedRepo,
) -> Result<Response, ApiError> {
    let license_id = parse_license_id(&id)?;
    // An unknown edition can't have entitled the key, so removing it is a no-op.
    let Some(edition_id) = s.catalog.find_edition(repo_id, edition.trim()).await? else {
        return Ok(StatusCode::NO_CONTENT.into_response());
    };
    if s.catalog
        .remove_edition_from_license(repo_id, license_id, edition_id)
        .await?
    {
        Ok(StatusCode::NO_CONTENT.into_response())
    } else {
        Err(ApiError::NotFound("license"))
    }
}

/// `DELETE /api/v1/repos/{org}/{repo}/license-keys/{id}` — revoke a key.
pub(crate) async fn revoke_license(
    State(s): State<AppState>,
    Path((_org, _repo, id)): Path<(String, String, String)>,
    AuthedRepo(repo_id): AuthedRepo,
) -> Result<Response, ApiError> {
    if s.catalog
        .revoke_license(repo_id, parse_license_id(&id)?)
        .await?
    {
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
