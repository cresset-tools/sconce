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
mod snapshots;
pub mod ui;

use axum::Router;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
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
    /// sha256 of each shared secret a first-party relay may present (as
    /// `Authorization: Bearer`) to the token-introspection endpoint. A *set*
    /// (not one value) so a secret can be rotated with an overlap window — see
    /// `parse_introspect_secrets`. Loaded once from `SCONCE_INTROSPECT_SECRET`;
    /// empty (unset/blank) fails every call closed. Stored as digests so the
    /// plaintext secrets don't linger in memory.
    introspect_secrets: Vec<[u8; 32]>,
}

/// Build the router. Repositories are served under `/{org}/{repo}/…`, each
/// gated by a token valid *for that repository*.
pub fn router(catalog: Catalog, store: AnyBlobStore, base_url: String) -> Router {
    // Uploads carry package bytes, so they need a much larger body cap than axum's
    // 2 MiB default — applied per-route so the read/serving routes keep the default.
    let max_upload = publish::max_upload_bytes();
    let upload_limit = DefaultBodyLimit::max(usize::try_from(max_upload).unwrap_or(usize::MAX));
    // Relay-introspection secrets, loaded once at startup. Accept a *set*
    // (comma- or whitespace-separated) so a secret can be rotated with zero
    // downtime: add the new one here and restart, roll the relay onto it, then
    // drop the old one and restart — at no point is the relay's live secret
    // rejected. Blank/unset → the endpoint fails closed (see `oauth_introspect`).
    let introspect_secrets = std::env::var("SCONCE_INTROSPECT_SECRET")
        .ok()
        .map(|raw| parse_introspect_secrets(&raw))
        .unwrap_or_default();
    Router::new()
        .route("/{org}/{repo}/packages.json", get(packages_json))
        .route("/{org}/{repo}/p2/{*rest}", get(p2))
        .route("/{org}/{repo}/dist/{*rest}", get(dist))
        .route("/oauth/ci", post(oauth_ci))
        .route("/oauth/ci-publish", post(oauth_ci_publish))
        // Device authorization grant (RFC 8628) for `bougie login`: the CLI starts
        // a flow + polls here; the human approves on the dashboard (see ui.rs).
        .route("/oauth/device", post(oauth_device))
        .route("/oauth/device/token", post(oauth_device_token))
        // Token introspection (RFC 7662 style) for a first-party relay: verify a
        // `bougie login` org-session token. Caller-authenticated by a shared
        // secret; never exposed to end users.
        .route("/oauth/introspect", post(oauth_introspect))
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
        // Snapshot (dataset) API — single-shot + chunked upload (the chunked flow
        // reuses the shared `…/uploads/{id}/…` routes above), and a latest-download
        // that 302s to a presigned URL like `dist`.
        .route(
            "/{org}/{repo}/snapshots/{env}",
            put(snapshots::upload_single).layer(upload_limit),
        )
        .route(
            "/{org}/{repo}/snapshots/{env}/uploads",
            post(snapshots::upload_init),
        )
        .route(
            "/{org}/{repo}/snapshots/{env}/latest",
            get(snapshots::download_latest),
        )
        // Metadata about the latest snapshot without downloading it — backs
        // `bougie db status`'s staleness check (compare the local seed marker's
        // digest against the registry's latest).
        .route(
            "/{org}/{repo}/snapshots/{env}/latest/info",
            get(snapshots::latest_info),
        )
        .route(
            "/{org}/{repo}/snapshots/{env}/{digest}",
            get(snapshots::download_digest),
        )
        // Repo discovery for `bougie login`: list the repositories an org-scoped
        // read token can access, so the CLI auto-provisions a project's Composer
        // `repositories` without pasted URLs. Org-session-bearer auth (distinct
        // from the repo-scoped, service-token `/api/v1/repos/{org}/{repo}/…` below).
        .route("/api/v1/repos", get(list_org_repos))
        // Team manifest: a project's team config keyed by its git remote, so a
        // clone fetches its config from login + remote alone. Org-session-bearer
        // auth; returns config only for a remote owned by the token's own org.
        .route("/api/v1/manifest", get(get_manifest))
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
        .route(
            "/api/v1/repos/{org}/{repo}/license-keys/{id}/editions/{edition}/renew",
            post(api::renew_license_edition),
        )
        .route(
            "/api/v1/repos/{org}/{repo}/license-keys/{id}/merge",
            post(api::merge_license),
        )
        .route("/healthz", get(healthz))
        .with_state(AppState {
            catalog,
            store,
            base_url,
            introspect_secrets,
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
    /// A repo read token: every package in the repo, unbounded.
    Full,
    /// A seller license key: only the entitled (purchased) package names, each
    /// under its own perpetual-fallback bound (per-entitlement bounds, 0047 —
    /// one accumulated key can carry a perpetual tool beside an annual one).
    Licensed(std::collections::HashMap<String, sconce_catalog::LicenseBound>),
}

impl Access {
    /// Whether `package` is readable under this access.
    fn allows(&self, package: &str) -> bool {
        match self {
            Access::Full => true,
            Access::Licensed(entitled) => entitled.contains_key(package),
        }
    }

    /// The update bound `package` is served under (unbounded for a repo token
    /// or an unknown package — the latter never reaches version serving, since
    /// [`Self::allows`] gates it first).
    fn bound_for(&self, package: &str) -> sconce_catalog::LicenseBound {
        match self {
            Access::Full => sconce_catalog::LicenseBound::default(),
            Access::Licensed(entitled) => entitled.get(package).cloned().unwrap_or_default(),
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
/// seller **license key** grants [`Access::Licensed`] to its entitled packages,
/// each under its own effective update bound (per-entitlement bounds, 0047).
async fn authorize(
    s: &AppState,
    repo_id: Uuid,
    headers: &HeaderMap,
) -> Result<(Access, sconce_catalog::PolicyOverride), AppError> {
    let cred = extract_token(headers).ok_or(AppError::Unauthorized)?;

    if let Some(policy) = s.catalog.resolve_token_policy(repo_id, &cred).await? {
        return Ok((Access::Full, policy));
    }
    if let Some(license_id) = s.catalog.resolve_license(repo_id, &cred).await? {
        let entitled = s
            .catalog
            .entitled_package_bounds(license_id)
            .await?
            .into_iter()
            .collect();
        let policy = s.catalog.license_policy(license_id).await?;
        return Ok((Access::Licensed(entitled), policy));
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
    let (access, _policy) = authorize(&s, loc.repo_id, &headers).await?;
    let names = match access {
        Access::Full => s.catalog.all_package_names(loc.repo_id).await?,
        Access::Licensed(entitled) => {
            let mut v: Vec<String> = entitled.into_keys().collect();
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
    let (access, policy) = authorize(&s, loc.repo_id, &headers).await?;

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
    // perpetual-fallback bound additionally caps which versions it may install —
    // resolved **per package** (0047), so an accumulated key serves each
    // purchase under its own ceiling.
    let bound = access.bound_for(package);
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

/// Device authorization TTLs (RFC 8628): the approval window, how often the CLI
/// polls, and how long the minted read token lives (dev machines re-login rarely,
/// so a longer, bounded TTL than a CI token).
const DEVICE_FLOW_TTL_SECS: i64 = 600;
const DEVICE_POLL_INTERVAL_SECS: i64 = 5;
const DEVICE_TOKEN_TTL_SECS: i64 = 90 * 24 * 60 * 60;

#[derive(serde::Deserialize)]
struct DeviceTokenRequest {
    device_code: String,
}

/// Start a device-authorization flow — `bougie login` POSTs here to begin. Returns
/// the device/user codes and where the human goes to approve (the dashboard). No
/// auth: the flow is inert until a signed-in org member approves it in the browser.
async fn oauth_device(State(s): State<AppState>) -> Result<Json<serde_json::Value>, AppError> {
    let (device_code, user_code) = s.catalog.start_device_flow(DEVICE_FLOW_TTL_SECS).await?;
    // The approval page lives on the dashboard (UI router), which may be a
    // different origin than this wire endpoint; prefer its configured URL, fall
    // back to this server's base_url for a single-binary deploy.
    let dashboard = std::env::var("SCONCE_UI_BASE_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| s.base_url.clone());
    let dashboard = dashboard.trim_end_matches('/');
    Ok(Json(json!({
        "device_code": device_code,
        "user_code": user_code,
        "verification_uri": format!("{dashboard}/device"),
        "verification_uri_complete": format!("{dashboard}/device?code={user_code}"),
        "expires_in": DEVICE_FLOW_TTL_SECS,
        "interval": DEVICE_POLL_INTERVAL_SECS,
    })))
}

/// Poll a device-authorization flow (the RFC 8628 token endpoint) — `bougie login`
/// POSTs `{device_code}` here on an interval. Pending → 400 `authorization_pending`;
/// approved → an org-scoped read token; expired/denied → the matching RFC error.
async fn oauth_device_token(
    State(s): State<AppState>,
    Json(req): Json<DeviceTokenRequest>,
) -> Response {
    let device_error =
        |status: StatusCode, code: &str| (status, Json(json!({ "error": code }))).into_response();
    match s.catalog.poll_device_flow(&req.device_code).await {
        Ok(sconce_catalog::DeviceFlowPoll::Approved { org_id }) => {
            match s
                .catalog
                .create_session_token(org_id, "bougie login", DEVICE_TOKEN_TTL_SECS)
                .await
            {
                Ok(token) => Json(json!({
                    "access_token": token,
                    "token_type": "Bearer",
                    "expires_in": DEVICE_TOKEN_TTL_SECS,
                }))
                .into_response(),
                Err(_) => device_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
            }
        }
        Ok(sconce_catalog::DeviceFlowPoll::Pending) => {
            device_error(StatusCode::BAD_REQUEST, "authorization_pending")
        }
        Ok(sconce_catalog::DeviceFlowPoll::Denied) => {
            device_error(StatusCode::BAD_REQUEST, "access_denied")
        }
        Ok(sconce_catalog::DeviceFlowPoll::Expired) => {
            device_error(StatusCode::BAD_REQUEST, "expired_token")
        }
        Err(_) => device_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    }
}

#[derive(serde::Deserialize)]
struct IntrospectRequest {
    token: String,
}

/// sha256 of a relay secret. Hashing before comparison means unequal secret
/// *lengths* never leak through the compare (the digests are always 32 bytes).
fn secret_digest(secret: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(secret.as_bytes()));
    out
}

/// Constant-time equality for two fixed-size digests: fold every byte, no
/// data-dependent branch or early exit, so timing reveals nothing about how
/// many bytes matched.
fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Parse `SCONCE_INTROSPECT_SECRET` into the sha256 digest of each accepted
/// secret. Splitting on commas *and* whitespace lets an operator list more than
/// one during a rotation overlap window; blanks are dropped, and an empty result
/// leaves the endpoint fail-closed.
fn parse_introspect_secrets(raw: &str) -> Vec<[u8; 32]> {
    raw.split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(secret_digest)
        .collect()
}

/// RFC 7662-style token introspection for a **first-party relay** (e.g. the
/// tunnel relay fronting `bougie server` tunnels): verify a `bougie login`
/// org-scoped session token and report the org it authenticates.
///
/// Caller auth is a shared secret presented as `Authorization: Bearer
/// <SCONCE_INTROSPECT_SECRET>`, checked in constant time against the accepted
/// set (more than one during a rotation overlap). The set is loaded once at
/// startup; if it's empty the endpoint fails **closed** — every call is `401`,
/// never allow-all. Not an end-user endpoint. On success (HTTP 200):
/// `{ "active": true, "org_id": "<uuid>", "expires_at": <unix-secs?> }`, and
/// `{ "active": false }` for an unknown / expired / repo-scoped token.
async fn oauth_introspect(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<IntrospectRequest>,
) -> Response {
    // Fail closed when no relay secret is configured.
    if s.introspect_secrets.is_empty() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    // Strictly require the secret as a bearer token (not basic-auth).
    let Some(presented) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    // Constant-time membership test against the accepted set. Hash first so
    // unequal lengths don't leak, then fold over every entry (`|=`, never
    // short-circuiting) so the time taken depends only on how many secrets are
    // configured — not on which one matched or what was presented.
    let got = secret_digest(presented);
    let mut matched = false;
    for expected in &s.introspect_secrets {
        matched |= ct_eq(&got, expected);
    }
    if !matched {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match s.catalog.resolve_org_session_token(&req.token).await {
        Ok(Some(tok)) => {
            let mut body = json!({
                "active": true,
                "org_id": tok.org_id.to_string(),
            });
            if let Some(exp) = tok.expires_at_unix {
                body["expires_at"] = json!(exp);
            }
            Json(body).into_response()
        }
        Ok(None) => Json(json!({ "active": false })).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// `GET /api/v1/repos` — the repositories an org-scoped read token can access,
/// each with its full Composer URL. `bougie login` calls this with the token it
/// just minted to auto-provision a project's `repositories`. Repo-scoped tokens
/// (no `org_id`) authenticate nothing here → 401.
async fn list_org_repos(
    State(s): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let cred = extract_token(&headers).ok_or(AppError::Unauthorized)?;
    let tok = s
        .catalog
        .resolve_org_session_token(&cred)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let repos = s.catalog.repos_for_org(tok.org_id).await?;
    let list: Vec<serde_json::Value> = repos
        .iter()
        .map(|r| {
            json!({
                "org": r.org,
                "repo": r.repo,
                "url": repo_base(&s.base_url, &r.org, &r.repo),
            })
        })
        .collect();
    Ok(Json(json!({ "repositories": list })))
}

/// Query params for [`get_manifest`].
#[derive(Debug, serde::Deserialize)]
struct ManifestQuery {
    /// The project's git remote URL, any form — normalized server-side.
    remote: String,
}

/// `GET /api/v1/manifest?remote=<git-url>` — a project's team config, keyed by
/// its git remote. Org-session-bearer auth, like `/api/v1/repos`. The manifest
/// is returned only when the remote is registered to the token's *own* org, so
/// a token can't read another team's config; an unregistered remote (or one
/// owned by a different org) is a 404. The body is forward-compatible: today the
/// org identity plus its Composer repositories; pinned service versions, policy,
/// and the default data profile slot in later.
async fn get_manifest(
    State(s): State<AppState>,
    Query(q): Query<ManifestQuery>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let cred = extract_token(&headers).ok_or(AppError::Unauthorized)?;
    let tok = s
        .catalog
        .resolve_org_session_token(&cred)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let remote = sconce_catalog::normalize_git_remote(&q.remote);
    // The remote must be registered AND owned by the token's org.
    if s.catalog.org_for_remote(&remote).await? != Some(tok.org_id) {
        return Err(AppError::NotFound);
    }
    let org = s
        .catalog
        .org_slug_by_id(tok.org_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let repos = s.catalog.repos_for_org(tok.org_id).await?;
    let repositories: Vec<serde_json::Value> = repos
        .iter()
        .map(|r| {
            json!({
                "org": r.org,
                "repo": r.repo,
                "url": repo_base(&s.base_url, &r.org, &r.repo),
            })
        })
        .collect();
    let mut body = json!({
        "schema_version": 1,
        "org": org,
        "remote": remote,
        "repositories": repositories,
    });
    // The database snapshot source, when the remote has one configured (`sconce
    // remote-snapshot`). Lets `bougie db pull` default `--repo`/`--env`/
    // `--profile` from the manifest instead of the dev naming the dataset repo.
    // `profile` is the team's default data profile (`full` unless set). Omitted
    // when unset.
    if let Some((snap_org, snap_repo, snap_env, snap_profile)) =
        s.catalog.snapshot_for_remote(&remote).await?
    {
        body["snapshot"] = json!({
            "repo": format!("{snap_org}/{snap_repo}"),
            "env": snap_env,
            "profile": snap_profile,
        });
    }
    // Named database sources the team advertises (`sconce remote-source`), for
    // `bougie db get --source <name>`. Each carries the jibs SSH target and
    // optional connection refinements (never a credential). Omitted when none.
    let sources = s.catalog.sources_for_remote(&remote).await?;
    if !sources.is_empty() {
        let map: serde_json::Map<String, serde_json::Value> = sources
            .into_iter()
            .map(|src| {
                let mut obj = serde_json::Map::new();
                obj.insert("host".to_string(), json!(src.host));
                if let Some(remote_mysql) = src.remote_mysql {
                    obj.insert("remote_mysql".to_string(), json!(remote_mysql));
                }
                if let Some(identity) = src.identity {
                    obj.insert("identity".to_string(), json!(identity));
                }
                if let Some(port) = src.port {
                    obj.insert("port".to_string(), json!(port));
                }
                (src.name, serde_json::Value::Object(obj))
            })
            .collect();
        body["sources"] = serde_json::Value::Object(map);
    }
    Ok(Json(body))
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

    #[test]
    fn parses_introspect_secret_set() {
        // Unset/blank → empty → endpoint stays fail-closed.
        assert!(parse_introspect_secrets("").is_empty());
        assert!(parse_introspect_secrets("   ").is_empty());
        assert!(parse_introspect_secrets(" , ,\n").is_empty());

        // A single secret hashes to its own digest.
        let one = parse_introspect_secrets("s3cr3t");
        assert_eq!(one, vec![secret_digest("s3cr3t")]);

        // Comma- and whitespace-separated (rotation overlap) both split; blanks drop.
        let many = parse_introspect_secrets(" old ,new\tthird ");
        assert_eq!(
            many,
            vec![
                secret_digest("old"),
                secret_digest("new"),
                secret_digest("third"),
            ]
        );
    }

    #[test]
    fn ct_eq_matches_only_identical_digests() {
        let a = secret_digest("relay-secret");
        assert!(ct_eq(&a, &secret_digest("relay-secret")));
        assert!(!ct_eq(&a, &secret_digest("relay-secre")));
        assert!(!ct_eq(&a, &secret_digest("wrong")));
        // A presented secret matches iff it's in the accepted set.
        let set = parse_introspect_secrets("old,new");
        let hit = secret_digest("new");
        assert!(set.iter().any(|e| ct_eq(&hit, e)));
        assert!(!set.iter().any(|e| ct_eq(&secret_digest("other"), e)));
    }
}
