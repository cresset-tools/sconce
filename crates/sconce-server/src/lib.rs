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

mod api;
pub mod ci;
pub mod csrf;
pub mod mail;
pub mod oidc;
mod publish;
pub mod ratelimit;
pub mod ui;

use axum::Router;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Json, Redirect, Response};
use axum::routing::{delete, get, post, put};
use base64::Engine as _;
use sconce_cas::{AnyBlobStore, BlobId, BlobStore};
use sconce_catalog::Catalog;
use serde_json::json;
use uuid::Uuid;

/// Shared handler state.
#[derive(Clone)]
struct AppState {
    catalog: Catalog,
    store: AnyBlobStore,
    /// Public base URL; each repository is served under `<base>/<org>/<repo>`.
    base_url: String,
}

/// Build the router. Repositories are served under `/{org}/{repo}/…`, each
/// gated by a token valid *for that repository*.
pub fn router(catalog: Catalog, store: AnyBlobStore, base_url: String) -> Router {
    // Uploads carry package bytes, so they need a much larger body cap than axum's
    // 2 MiB default — applied per-route so the read/serving routes keep the default.
    let max_upload = publish::max_upload_bytes();
    let upload_limit = DefaultBodyLimit::max(usize::try_from(max_upload).unwrap_or(usize::MAX));
    Router::new()
        .route("/{org}/{repo}/packages.json", get(packages_json))
        .route("/{org}/{repo}/p2/{*rest}", get(p2))
        .route("/{org}/{repo}/dist/{*rest}", get(dist))
        .route("/oauth/ci", post(oauth_ci))
        .route("/oauth/ci-publish", post(oauth_ci_publish))
        // Publish (push) API — single-shot + chunked/resumable uploads.
        .route(
            "/{org}/{repo}/packages/{vendor}/{name}/{version}",
            put(publish::publish_single).layer(upload_limit),
        )
        .route(
            "/{org}/{repo}/packages/{vendor}/{name}/{version}/uploads",
            post(publish::upload_init),
        )
        .route(
            "/{org}/{repo}/uploads/{upload_id}/parts/{n}",
            put(publish::upload_part).layer(upload_limit),
        )
        .route(
            "/{org}/{repo}/uploads/{upload_id}",
            get(publish::upload_status).delete(publish::upload_abort),
        )
        .route(
            "/{org}/{repo}/uploads/{upload_id}/complete",
            post(publish::upload_complete),
        )
        // Management API (service-token auth) — provisioning for commerce
        // front-ends like the Magento module. See `api`.
        .route(
            "/api/v1/repos/{org}/{repo}/editions",
            get(api::list_editions),
        )
        .route(
            "/api/v1/repos/{org}/{repo}/license-keys",
            post(api::issue_license),
        )
        .route(
            "/api/v1/repos/{org}/{repo}/license-keys/{id}",
            get(api::inspect_license).delete(api::revoke_license),
        )
        .route(
            "/api/v1/repos/{org}/{repo}/license-keys/{id}/renew",
            post(api::renew_license),
        )
        .route(
            "/api/v1/repos/{org}/{repo}/license-keys/{id}/editions",
            post(api::add_license_edition),
        )
        .route(
            "/api/v1/repos/{org}/{repo}/license-keys/{id}/editions/{edition}",
            delete(api::remove_license_edition),
        )
        .route("/healthz", get(healthz))
        .with_state(AppState {
            catalog,
            store,
            base_url,
        })
}

/// Unauthenticated health probe for load balancers / orchestrators: `200 ok`
/// when Postgres answers, `503` otherwise. Reveals nothing tenant-scoped.
async fn healthz(State(s): State<AppState>) -> Response {
    match s.catalog.ping().await {
        Ok(()) => (StatusCode::OK, "ok").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "health check failed: database unreachable");
            (StatusCode::SERVICE_UNAVAILABLE, "database unreachable").into_response()
        }
    }
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

/// Resolve `(org, repo)` to its canonical location, **301-redirecting** a request
/// that used an old (renamed) slug so existing `composer.lock` URLs keep working.
/// `suffix` is the per-endpoint path tail (e.g. `packages.json`, `p2/v/n.json`).
/// `Ok(Ok(loc))` = serve `loc.repo_id`; `Ok(Err(redirect))` = send the 301.
async fn locate(
    s: &AppState,
    org: &str,
    repo: &str,
    suffix: &str,
) -> Result<Result<sconce_catalog::RepoLocation, Response>, AppError> {
    let loc = s
        .catalog
        .resolve_repo_canonical(org, repo)
        .await?
        .ok_or(AppError::NotFound)?;
    if loc.moved {
        let to = format!("/{}/{}/{suffix}", loc.org_slug, loc.repo_slug);
        return Ok(Err(Redirect::permanent(&to).into_response()));
    }
    Ok(Ok(loc))
}

/// The access a credential grants to an already-resolved repo. 401 if the
/// credential is missing/invalid. A repo **token** grants [`Access::Full`]; a
/// seller **license key** grants [`Access::Licensed`] to its entitled packages.
async fn authorize(
    s: &AppState,
    repo_id: Uuid,
    headers: &HeaderMap,
) -> Result<
    (
        Access,
        sconce_catalog::PolicyOverride,
        sconce_catalog::LicenseBound,
    ),
    AppError,
> {
    let cred = extract_token(headers).ok_or(AppError::Unauthorized)?;

    if let Some(policy) = s.catalog.resolve_token_policy(repo_id, &cred).await? {
        // A repo token has no perpetual-fallback bound (unbounded).
        return Ok((
            Access::Full,
            policy,
            sconce_catalog::LicenseBound::default(),
        ));
    }
    if let Some(license_id) = s.catalog.resolve_license(repo_id, &cred).await? {
        let entitled = s
            .catalog
            .entitled_package_names(license_id)
            .await?
            .into_iter()
            .collect();
        let policy = s.catalog.license_policy(license_id).await?;
        let bound = s.catalog.license_bound(license_id).await?;
        return Ok((Access::Licensed(entitled), policy, bound));
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
    store: AnyBlobStore,
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
) -> Result<Response, AppError> {
    let loc = match locate(&s, &org, &repo, "packages.json").await? {
        Ok(loc) => loc,
        Err(redirect) => return Ok(redirect),
    };
    let (access, _policy, _bound) = authorize(&s, loc.repo_id, &headers).await?;
    let names = match access {
        Access::Full => s.catalog.all_package_names(loc.repo_id).await?,
        Access::Licensed(entitled) => {
            let mut v: Vec<String> = entitled.into_iter().collect();
            v.sort();
            v
        }
    };
    Ok(Json(sconce_metadata::render_root(
        &names,
        &repo_base(&s.base_url, &loc.org_slug, &loc.repo_slug),
    ))
    .into_response())
}

async fn p2(
    State(s): State<AppState>,
    Path((org, repo, rest)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let loc = match locate(&s, &org, &repo, &format!("p2/{rest}")).await? {
        Ok(loc) => loc,
        Err(redirect) => return Ok(redirect),
    };
    let (access, policy, bound) = authorize(&s, loc.repo_id, &headers).await?;

    // `rest` is "vendor/name.json" or "vendor/name~dev.json".
    let stem = rest.strip_suffix(".json").ok_or(AppError::NotFound)?;
    let (package, is_dev) = match stem.strip_suffix("~dev") {
        Some(p) => (p, true),
        None => (stem, false),
    };

    // A license key only unlocks its entitled packages; everything else (and the
    // dev variant) is an empty document.
    if is_dev || !access.allows(package) {
        return Ok(Json(json!({ "packages": { package: [] } })).into_response());
    }

    // Apply the supply-chain gate (cooldown / manual approval / holds) so clients
    // only ever see versions that have cleared it. The presenting credential's
    // policy override can tighten — never loosen — the repo default. A license's
    // perpetual-fallback bound additionally caps which versions it may install.
    let (repo_mode, repo_cooldown) = s.catalog.update_policy(loc.repo_id).await?;
    let (mode, cooldown_days) = policy.effective(&repo_mode, repo_cooldown);
    // A granted package can carry its own (tighter) policy — fold it in after the
    // credential's, before serving.
    let (mode, cooldown_days) = s
        .catalog
        .grant_policy(loc.repo_id, package)
        .await?
        .effective(&mode, cooldown_days);
    let versions = s
        .catalog
        .visible_versions(
            loc.repo_id,
            package,
            &mode,
            cooldown_days,
            bound.until_unix,
            bound.major,
        )
        .await?;
    Ok(Json(sconce_metadata::render_package(
        package,
        &versions,
        &repo_base(&s.base_url, &loc.org_slug, &loc.repo_slug),
    ))
    .into_response())
}

async fn dist(
    State(s): State<AppState>,
    Path((org, repo, rest)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let loc = match locate(&s, &org, &repo, &format!("dist/{rest}")).await? {
        Ok(loc) => loc,
        Err(redirect) => return Ok(redirect),
    };
    let _ = authorize(&s, loc.repo_id, &headers).await?;

    // `rest` is "vendor/name/<sha256>.zip"; the final segment carries the sha.
    let file = rest.rsplit('/').next().ok_or(AppError::NotFound)?;
    let hex = file.strip_suffix(".zip").ok_or(AppError::NotFound)?;
    let sha = parse_hex32(hex).ok_or(AppError::NotFound)?;
    let id = BlobId::from_bytes(sha);

    // Object-store backend: authorize (above), then hand the client a
    // freshly-minted, short-lived presigned URL and let it pull bytes straight
    // from the store. The stable sconce URL is what `composer.lock` pins; the
    // signed URL is never persisted anywhere. (The GitHub release-asset model —
    // see ROADMAP "Dist serving".) One HEAD first so a dangling sha 404s as
    // sconce rather than as store XML behind the redirect.
    if let Some(url) = s.store.presigned_get(&id, DIST_PRESIGN_SECS) {
        let store = s.store.clone();
        if !blocking(move || store.exists(&id)).await? {
            return Err(AppError::NotFound);
        }
        return Ok((StatusCode::FOUND, [(header::LOCATION, url)]).into_response());
    }

    let store = s.store.clone();
    match blocking(move || store.get(&id)).await? {
        Some(bytes) => Ok(([(header::CONTENT_TYPE, "application/zip")], bytes).into_response()),
        None => Err(AppError::NotFound),
    }
}

/// Run one blocking store operation (disk or S3 round-trip via ureq) off the
/// async executor.
pub(crate) async fn blocking<T: Send + 'static>(
    op: impl FnOnce() -> std::io::Result<T> + Send + 'static,
) -> Result<T, AppError> {
    tokio::task::spawn_blocking(op)
        .await
        .map_err(|e| AppError::Storage(std::io::Error::other(e)))?
        .map_err(AppError::Storage)
}

/// Lifetime of a presigned dist redirect. Short — Composer follows the 302
/// immediately — but with slack for clock skew between sconce and the store.
const DIST_PRESIGN_SECS: u64 = 300;

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

/// Validate a CI OIDC JWT against the repo's policies of a given `capability`
/// (signature via the issuer's JWKS, `iss`/`aud`/`exp`, then the claim matchers).
/// Returns the first matching `(repo_id, workload label, token ttl)`, or `None`.
async fn ci_match(
    s: &AppState,
    req: &CiExchange,
    capability: &str,
) -> Result<Option<(Uuid, String, i64)>, AppError> {
    let (org, repo) = req.repository.split_once('/').ok_or(AppError::NotFound)?;
    let repo_id = s
        .catalog
        .resolve_repo(org, repo)
        .await?
        .ok_or(AppError::NotFound)?;

    for policy in s.catalog.ci_policies(repo_id).await? {
        // Each exchange only considers policies that grant its capability, so a
        // serving policy can never mint a publish token and vice versa.
        if policy.capability != capability {
            continue;
        }
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
        let label = claims
            .get("sub")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("ci")
            .to_owned();
        return Ok(Some((repo_id, label, policy.token_ttl_secs)));
    }
    Ok(None)
}

/// Trade a CI OIDC JWT for a short-lived **read** token (zero stored secret) — the
/// serving credential a Composer client uses. 401 if no `read` policy matches.
async fn oauth_ci(
    State(s): State<AppState>,
    Json(req): Json<CiExchange>,
) -> Result<Json<serde_json::Value>, AppError> {
    match ci_match(&s, &req, "read").await? {
        Some((repo_id, label, ttl)) => {
            let token = s.catalog.create_ci_token(repo_id, &label, ttl).await?;
            Ok(Json(json!({
                "access_token": token,
                "token_type": "Bearer",
                "expires_in": ttl,
            })))
        }
        None => Err(AppError::Unauthorized),
    }
}

/// Trade a CI OIDC JWT for a short-lived **publish** token (zero stored secret) —
/// the credential the publish API requires. 401 if no `publish` policy matches.
async fn oauth_ci_publish(
    State(s): State<AppState>,
    Json(req): Json<CiExchange>,
) -> Result<Json<serde_json::Value>, AppError> {
    match ci_match(&s, &req, "publish").await? {
        Some((repo_id, label, ttl)) => {
            let token = s.catalog.create_publish_token(repo_id, &label, ttl).await?;
            Ok(Json(json!({
                "access_token": token,
                "token_type": "Bearer",
                "expires_in": ttl,
            })))
        }
        None => Err(AppError::Unauthorized),
    }
}

#[derive(Debug, thiserror::Error)]
enum AppError {
    #[error("not found")]
    NotFound,
    #[error("unauthorized")]
    Unauthorized,
    /// A valid publish token, but for a different repository than the path.
    #[error("forbidden")]
    Forbidden,
    #[error("bad request: {0}")]
    BadRequest(String),
    /// The upload session or version is in a state that rejects the request
    /// (e.g. a closed session, or a version already published with other bytes).
    #[error("conflict: {0}")]
    Conflict(String),
    /// The assembled package exceeds `SCONCE_MAX_PACKAGE_BYTES`.
    #[error("payload too large")]
    PayloadTooLarge,
    /// A staged upload chunk was reclaimed before the upload completed.
    #[error("gone")]
    Gone,
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
            AppError::Forbidden => StatusCode::FORBIDDEN.into_response(),
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, m).into_response(),
            AppError::Conflict(m) => (StatusCode::CONFLICT, m).into_response(),
            AppError::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE.into_response(),
            AppError::Gone => StatusCode::GONE.into_response(),
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
