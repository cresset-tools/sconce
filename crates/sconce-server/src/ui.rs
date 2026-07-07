//! Admin web UI — a server-rendered management console over the catalog.
//!
//! Two modes (see [`router`]):
//! - **multi-tenant** (default): user accounts with login sessions; each user
//!   sees only the tenants (organizations) they belong to, and a superadmin
//!   sees all. Bootstrap the first user with `sconce user-create --superadmin`.
//! - **single-tenant** (`--single-tenant`): no accounts; an optional
//!   `--admin-password` (HTTP basic) gates the whole UI, which acts as one
//!   all-access tenant. Bind to localhost when no password is set.
//!
//! This is the operator surface; the public Composer wire API in [`crate`] is
//! separately token/license-gated and unaffected.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::time::Duration;

use askama::Template;
use axum::Router;
use axum::extract::{ConnectInfo, Extension, Form, Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use base64::Engine as _;
use sconce_catalog::Catalog;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

/// Typed Askama page-body templates (replacing hand-built HTML strings).
mod views;

#[derive(Clone)]
struct Ui {
    catalog: Catalog,
    public_base_url: String,
    /// Single-tenant mode: no accounts, gated by `admin_password` (or open).
    single_tenant: bool,
    admin_password: Option<String>,
    /// For encrypting upstream credentials (from `SCONCE_SECRET_KEY`); `None`
    /// means credentials can't be stored, only credential-free upstreams.
    secret_key: Option<sconce_catalog::secret::SecretKey>,
    /// Public base URL of *this admin UI* (from `SCONCE_UI_BASE_URL`), used to
    /// build absolute links in emails (the password-reset link). Distinct from
    /// `public_base_url`, which is the Composer wire endpoint.
    dashboard_url: String,
    /// Sends transactional email (password-reset links). Configured from the
    /// environment; the dev backend prints to stderr.
    mailer: crate::mail::Mailer,
    /// Throttles the credential endpoints (login / forgot / reset / basic
    /// auth) against online brute force and reset-mail bombing. Disable with
    /// `SCONCE_RATE_LIMIT=off` when a load balancer rate-limits upstream.
    limiter: crate::ratelimit::RateLimiter,
    /// Add `Secure` to session cookies. Derived from `dashboard_url`: an
    /// https dashboard must never have its session sent over plain http, while
    /// forcing `Secure` on an http deployment (localhost, LAN self-host) would
    /// make browsers drop the cookie and lock everyone out.
    cookie_secure: bool,
}

/// The viewer's access, resolved per request.
#[derive(Clone)]
struct CurrentUser {
    /// The user id, or `None` for single-tenant all-access (no real account).
    id: Option<Uuid>,
    is_superadmin: bool,
    /// Orgs the user is a member of (read access).
    tenants: HashSet<Uuid>,
    /// Orgs the user administers (manage access; subset of `tenants`).
    admin_tenants: HashSet<Uuid>,
}

impl CurrentUser {
    fn all_access() -> Self {
        Self {
            id: None,
            is_superadmin: true,
            tenants: HashSet::new(),
            admin_tenants: HashSet::new(),
        }
    }
    /// Read access to an org (member or above).
    fn can(&self, org_id: Uuid) -> bool {
        self.is_superadmin || self.tenants.contains(&org_id)
    }
    /// Manage access to an org (admin role or superadmin).
    fn can_admin(&self, org_id: Uuid) -> bool {
        self.is_superadmin || self.admin_tenants.contains(&org_id)
    }
}

/// Build the admin UI router.
#[allow(clippy::too_many_lines)]
pub fn router(
    catalog: Catalog,
    public_base_url: String,
    single_tenant: bool,
    admin_password: Option<String>,
) -> Router {
    let dashboard_url = std::env::var("SCONCE_UI_BASE_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "http://127.0.0.1:8081".to_owned());
    let cookie_secure = dashboard_url.starts_with("https://");
    let state = Ui {
        catalog,
        public_base_url,
        single_tenant,
        admin_password,
        secret_key: sconce_catalog::secret::SecretKey::from_env().ok(),
        dashboard_url,
        mailer: crate::mail::Mailer::from_env(),
        limiter: crate::ratelimit::RateLimiter::from_env(),
        cookie_secure,
    };
    Router::new()
        .route("/", get(index))
        .route("/repositories", get(repositories_page))
        .route("/assets/{*path}", get(asset))
        .route("/healthz", get(ui_healthz))
        .route("/login", get(login_form).post(login))
        .route("/forgot", get(forgot_form).post(forgot_submit))
        .route("/reset", get(reset_form).post(reset_submit))
        .route("/auth/start", get(auth_start))
        .route("/auth/route", post(auth_route))
        .route("/auth/callback", get(auth_callback))
        .route(
            "/scim/v2/Users",
            get(scim_list_users).post(scim_create_user),
        )
        .route(
            "/scim/v2/Users/{id}",
            get(scim_get_user)
                .patch(scim_patch_user)
                .put(scim_put_user)
                .delete(scim_delete_user),
        )
        .route("/logout", post(logout))
        .route("/account", get(account_page))
        .route("/account/revoke", post(revoke_my_session))
        .route("/users", get(users_page).post(create_user))
        .route("/activity", get(activity_page))
        .route("/console", get(console_page))
        .route("/users/grant", post(grant_tenant))
        .route("/users/remove", post(remove_member))
        .route("/orgs", post(create_org))
        .route("/orgs/new", get(new_org_page))
        .route("/repos/new", get(new_repo_page))
        .route("/o/{org}", get(org_overview_page))
        .route(
            "/o/{org}/settings",
            get(org_settings_page).post(save_org_settings),
        )
        .route("/o/{org}/rename", post(rename_org_action))
        .route("/o/{org}/sets", get(sets_page).post(create_set))
        .route("/o/{org}/sets/{id}", get(set_editor_page))
        .route("/o/{org}/sets/{id}/delete", post(delete_set))
        .route("/o/{org}/sets/{id}/member", post(add_set_member))
        .route("/o/{org}/sets/{id}/member/remove", post(remove_set_member))
        .route("/o/{org}/sets/{id}/rule", post(add_set_rule))
        .route("/o/{org}/sets/{id}/rule/remove", post(remove_set_rule))
        .route("/o/{org}/oidc", post(save_oidc))
        .route("/o/{org}/scim-token", post(gen_scim_token))
        .route("/repos", post(create_repo))
        .route("/r/{org}/{repo}", get(repo_page))
        .route(
            "/r/{org}/{repo}/settings",
            get(repo_settings_page).post(save_repo_settings),
        )
        .route("/r/{org}/{repo}/rename", post(rename_repo_action))
        .route("/r/{org}/{repo}/delete", post(delete_repo_action))
        .route("/r/{org}/{repo}/policy", post(set_policy))
        .route("/r/{org}/{repo}/version", post(version_action))
        .route("/r/{org}/{repo}/approve-bulk", post(approve_bulk))
        .route("/r/{org}/{repo}/hold-bulk", post(hold_bulk))
        .route("/r/{org}/{repo}/token", post(create_token))
        .route("/r/{org}/{repo}/token/revoke", post(revoke_token))
        .route("/r/{org}/{repo}/token/policy", post(set_token_policy))
        .route("/r/{org}/{repo}/license/policy", post(set_license_policy))
        .route(
            "/r/{org}/{repo}/license/bound",
            post(set_license_bound_action),
        )
        .route("/r/{org}/{repo}/license/set", post(entitle_license_set))
        .route(
            "/r/{org}/{repo}/license/set/remove",
            post(remove_license_set),
        )
        .route("/r/{org}/{repo}/license/issue", post(issue_license_edition))
        .route("/r/{org}/{repo}/editions", post(create_edition_action))
        .route(
            "/r/{org}/{repo}/editions/deactivate",
            post(deactivate_edition),
        )
        .route("/r/{org}/{repo}/license", post(create_license))
        .route("/r/{org}/{repo}/grant", post(create_grant))
        .route(
            "/r/{org}/{repo}/grant/policy",
            post(set_grant_policy_action),
        )
        .route("/r/{org}/{repo}/autogrant", post(add_autogrant))
        .route("/r/{org}/{repo}/autogrant/remove", post(remove_autogrant))
        .route("/r/{org}/{repo}/upstream", post(create_upstream))
        .route("/r/{org}/{repo}/upstream/remove", post(remove_upstream))
        .route("/r/{org}/{repo}/upstream/sync", post(sync_upstream))
        .route(
            "/r/{org}/{repo}/upstream/sync-all",
            post(sync_all_upstreams),
        )
        .route("/r/{org}/{repo}/deps/resolve", post(resolve_deps))
        .route("/r/{org}/{repo}/deps/add", post(add_dep))
        .route("/r/{org}/{repo}/package/archive", post(package_archive))
        .route("/r/{org}/{repo}/p/{*pkg}", get(package_detail_page))
        .route("/r/{org}/{repo}/ci", post(add_ci))
        .route("/r/{org}/{repo}/ci/remove", post(remove_ci))
        .fallback(not_found_page)
        .route_layer(middleware::from_fn_with_state(state.clone(), auth))
        // Outermost (added last = runs first): reject cross-origin form posts
        // before auth ever sees them. See [`crate::csrf`].
        .route_layer(middleware::from_fn(crate::csrf::guard))
        .with_state(state)
}

/// Bind `listen` and serve the admin UI.
pub async fn serve(
    catalog: Catalog,
    public_base_url: String,
    single_tenant: bool,
    admin_password: Option<String>,
    listen: std::net::SocketAddr,
) -> std::io::Result<()> {
    let app = router(catalog, public_base_url, single_tenant, admin_password);
    let listener = tokio::net::TcpListener::bind(listen).await?;
    // Expose the peer address to handlers: rate limiting keys on it whenever
    // no reverse proxy supplied an `X-Forwarded-For`.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
}

/// Auth gate. Single-tenant: optional HTTP basic, then all-access. Multi-tenant:
/// require a login session (except for `/login`), resolving the user's tenants.
async fn auth(State(s): State<Ui>, mut req: Request, next: Next) -> Response {
    let path = req.uri().path();
    // Vendored fonts are public (the sign-in page needs them, pre-auth).
    if path.starts_with("/assets/") {
        return next.run(req).await;
    }
    // SCIM has its own bearer-token auth (in-handler), independent of UI mode.
    if path.starts_with("/scim/") {
        return next.run(req).await;
    }
    // Health probes come from load balancers, not browsers.
    if path == "/healthz" {
        return next.run(req).await;
    }
    if s.single_tenant {
        if let Some(expected) = &s.admin_password {
            // Throttle *failures* only — every page load re-sends the basic
            // password, so counting successful requests would lock the admin
            // out of normal browsing.
            let peer = req
                .extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|c| c.0);
            let key = format!("basic:ip:{}", client_ip(req.headers(), peer));
            if s.limiter
                .at_limit(&key, BASIC_MAX_FAILURES_PER_IP, BASIC_WINDOW)
            {
                return too_many_attempts();
            }
            if basic_password(req.headers()).as_deref() != Some(expected.as_str()) {
                s.limiter.record(&key);
                return basic_challenge();
            }
        }
        req.extensions_mut().insert(CurrentUser::all_access());
        return next.run(req).await;
    }

    let path = req.uri().path();
    if path == "/login" || path == "/forgot" || path == "/reset" || path.starts_with("/auth/") {
        return next.run(req).await;
    }
    let user = match session_cookie(req.headers()) {
        Some(token) => s.catalog.resolve_session(&token).await.ok().flatten(),
        None => None,
    };
    match user {
        Some(u) => {
            req.extensions_mut().insert(CurrentUser {
                id: Some(u.id),
                is_superadmin: u.is_superadmin,
                tenants: u.tenant_org_ids.into_iter().collect(),
                admin_tenants: u.admin_org_ids.into_iter().collect(),
            });
            next.run(req).await
        }
        None => Redirect::to("/login").into_response(),
    }
}

/// Unauthenticated health probe (mirrors the wire server's `/healthz`):
/// `200 ok` when Postgres answers, `503` otherwise.
async fn ui_healthz(State(s): State<Ui>) -> Response {
    match s.catalog.ping().await {
        Ok(()) => (StatusCode::OK, "ok").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "health check failed: database unreachable");
            (StatusCode::SERVICE_UNAVAILABLE, "database unreachable").into_response()
        }
    }
}

// ----- credential plumbing -----

fn basic_password(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let b64 = value.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    let creds = String::from_utf8(decoded).ok()?;
    creds.split_once(':').map(|(_, p)| p.to_owned())
}

fn basic_challenge() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Basic realm=\"sconce admin\"")],
    )
        .into_response()
}

fn session_cookie(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    raw.split(';')
        .map(str::trim)
        .find_map(|c| c.strip_prefix("sconce_session="))
        .map(str::to_owned)
}

fn redirect_with_cookie(to: &str, cookie: &str) -> Response {
    let mut resp = Redirect::to(to).into_response();
    if let Ok(v) = HeaderValue::from_str(cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    resp
}

/// `Set-Cookie` value establishing a login session (7 days, matching the
/// server-side `expires_at`). See [`Ui::cookie_secure`] for the `Secure` rule.
fn session_set_cookie(token: &str, secure: bool) -> String {
    let secure = if secure { "; Secure" } else { "" };
    format!("sconce_session={token}; HttpOnly; Path=/; SameSite=Lax; Max-Age=604800{secure}")
}

/// `Set-Cookie` value clearing the session (logout).
fn session_clear_cookie(secure: bool) -> String {
    let secure = if secure { "; Secure" } else { "" };
    format!("sconce_session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0{secure}")
}

// ----- credential-endpoint rate limits -----
//
// Throttling, not lockout (see [`crate::ratelimit`]): steady-state an attacker
// gets `max` guesses per window, a blocked legitimate user recovers as soon as
// an old attempt ages out. Per-key attempt counts, so the per-email caps also
// bound a *distributed* guessing attack on one account.

/// Login attempts per client address per window.
const LOGIN_MAX_PER_IP: usize = 10;
/// Login attempts per target account per window (any address).
const LOGIN_MAX_PER_EMAIL: usize = 5;
const LOGIN_WINDOW: Duration = Duration::from_mins(5);
/// Reset-link requests per client address per window — this endpoint sends
/// email, so the cap also bounds outbound mail abuse.
const FORGOT_MAX_PER_IP: usize = 5;
/// Reset-link requests per target address per window (inbox-bombing bound).
const FORGOT_MAX_PER_EMAIL: usize = 3;
const FORGOT_WINDOW: Duration = Duration::from_mins(15);
/// Reset-form submissions per client address per window (token guessing is
/// already infeasible — 128-bit tokens — this just keeps it boring).
const RESET_MAX_PER_IP: usize = 10;
const RESET_WINDOW: Duration = Duration::from_mins(5);
/// Wrong single-tenant basic passwords per client address per window.
const BASIC_MAX_FAILURES_PER_IP: usize = 10;
const BASIC_WINDOW: Duration = Duration::from_mins(5);

/// Best client identity available for rate limiting: the rightmost
/// `X-Forwarded-For` entry — the one appended by the *nearest* proxy, the only
/// hop this server can trust behind the documented TLS-terminating reverse
/// proxy (earlier entries are client-supplied and spoofable) — else the socket
/// peer address.
fn client_ip(headers: &HeaderMap, peer: Option<SocketAddr>) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit(',').next())
        .map(|ip| ip.trim().to_owned())
        .filter(|ip| !ip.is_empty())
        .unwrap_or_else(|| peer.map_or_else(|| "unknown".to_owned(), |p| p.ip().to_string()))
}

fn too_many_attempts() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        status_page(
            "Slow down",
            "Too many attempts. Wait a few minutes and try again.",
        ),
    )
        .into_response()
}

fn e500<E>(_: E) -> StatusCode {
    StatusCode::INTERNAL_SERVER_ERROR
}

/// Map an entitlement-gated failure: a plan denial or SKU-cap is `403`, a query
/// error `500`.
fn ent_status(e: &sconce_catalog::EntitlementError) -> StatusCode {
    match e {
        sconce_catalog::EntitlementError::Denied(_)
        | sconce_catalog::EntitlementError::SkuCapReached(_) => StatusCode::FORBIDDEN,
        sconce_catalog::EntitlementError::Sqlx(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// Human-readable byte count (base-1024) for the storage-usage display.
fn human_bytes(bytes: i64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    #[allow(clippy::cast_precision_loss)]
    let mut size = bytes.max(0) as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}

/// Full HTML scaffold shared by every page. The stylesheet is served from
/// `/assets/app.css` and the Geist woff2 from `/assets/fonts` (embedded, no CDN).
fn doc(title: &str, inner: &str) -> Html<String> {
    doc_js(title, inner, "")
}

/// Like [`doc`], but loads a single external page script at the very bottom of
/// `<body>`. `script_src` is an `/assets/*.js` URL (or empty for none); the page
/// JS is served as a static asset, not inlined.
fn doc_js(title: &str, inner: &str, script_src: &str) -> Html<String> {
    let doc = views::Doc {
        title: title.to_owned(),
        body: inner.to_owned(),
        script_src: script_src.to_owned(),
    };
    Html(doc.render().unwrap_or_default())
}

/// An authenticated app page, wrapped in the sidebar `AppShell` (left nav + top
/// breadcrumb bar + content).
fn shell(s: &Ui, user: &CurrentUser, title: &str, body: &str) -> Html<String> {
    shell_js(s, user, title, body, "")
}

/// Like [`shell`], but with one page `<script>` block at the bottom of `<body>`.
fn shell_js(s: &Ui, user: &CurrentUser, title: &str, body: &str, script: &str) -> Html<String> {
    let shell = views::Shell {
        sidebar: sidebar(s, user, title),
        here: title.to_owned(),
        body: body.to_owned(),
    };
    doc_js(title, &shell.render().unwrap_or_default(), script)
}

/// A compact relative-time label ("just now", "6m", "2h", "3d", "5w") from an
/// age in seconds — for the upstreams last-sync column.
fn ago(secs: i64) -> String {
    let s = secs.max(0);
    if s < 60 {
        "just now".to_owned()
    } else if s < 3_600 {
        format!("{}m", s / 60)
    } else if s < 86_400 {
        format!("{}h", s / 3_600)
    } else if s < 604_800 {
        format!("{}d", s / 86_400)
    } else {
        format!("{}w", s / 604_800)
    }
}

/// The left sidebar: brand/org block, route-grounded nav (active state derived
/// from `title`), and the user/role + log-out footer.
fn sidebar(s: &Ui, user: &CurrentUser, title: &str) -> String {
    let on_home = title == "Home";
    let on_members = title == "Users";
    let on_activity = title == "Activity";
    let on_console = title == "Instance console";
    // Everything else (an org, a repo, settings, a package…) is repo-browsing
    // context, so the Repositories item stays lit there.
    let on_repos = !on_home && !on_members && !on_activity && !on_console;
    let view = views::Sidebar {
        single_tenant: s.single_tenant,
        is_superadmin: user.is_superadmin,
        // Members lives in multi-tenant and is superadmin-managed.
        show_members: !s.single_tenant && user.is_superadmin,
        // No session to end in single-tenant (HTTP-basic) → no account/log-out.
        show_account: !s.single_tenant,
        on_home,
        on_repos,
        on_members,
        on_activity,
        on_console,
        // Single-tenant is all-access; otherwise admin if they manage any tenant.
        role: if s.single_tenant || user.is_superadmin || !user.admin_tenants.is_empty() {
            "Admin"
        } else {
            "Member"
        },
    };
    view.render().unwrap_or_default()
}

/// Static assets, embedded in the binary (no runtime asset dir — the server
/// stays a single self-contained executable). Stylesheet and page scripts live
/// in `assets/*.{css,js}`; fonts in `assets/fonts/`. All long-cached + immutable.
async fn asset(Path(path): Path<String>) -> Response {
    let (content_type, bytes): (&str, &'static [u8]) = match path.as_str() {
        "app.css" => (
            "text/css; charset=utf-8",
            include_bytes!("../assets/app.css"),
        ),
        "repo.js" => (
            "text/javascript; charset=utf-8",
            include_bytes!("../assets/repo.js"),
        ),
        "login.js" => (
            "text/javascript; charset=utf-8",
            include_bytes!("../assets/login.js"),
        ),
        "fonts/geist.woff2" => ("font/woff2", include_bytes!("../assets/fonts/geist.woff2")),
        "fonts/geist-mono.woff2" => (
            "font/woff2",
            include_bytes!("../assets/fonts/geist-mono.woff2"),
        ),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        bytes,
    )
        .into_response()
}

async fn lookup(
    s: &Ui,
    user: &CurrentUser,
    org: &str,
    repo: &str,
) -> Result<sconce_catalog::RepoSummary, StatusCode> {
    let summary = s
        .catalog
        .list_repositories()
        .await
        .map_err(e500)?
        .into_iter()
        .find(|r| r.org == org && r.repo == repo)
        .ok_or(StatusCode::NOT_FOUND)?;
    if user.can(summary.org_id) {
        Ok(summary)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

/// Like [`lookup`] but for mutations: requires the `admin` role (or superadmin).
/// A member who can *view* the repo gets 403 on a management action.
async fn lookup_admin(
    s: &Ui,
    user: &CurrentUser,
    org: &str,
    repo: &str,
) -> Result<sconce_catalog::RepoSummary, StatusCode> {
    let summary = lookup(s, user, org, repo).await?;
    if user.can_admin(summary.org_id) {
        Ok(summary)
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

/// Resolve an org slug to its summary, enforcing the user's tenant access
/// (404 if unknown or inaccessible — same non-leaking behavior as `lookup`).
async fn lookup_org(
    s: &Ui,
    user: &CurrentUser,
    org: &str,
) -> Result<sconce_catalog::OrgSummary, StatusCode> {
    let summary = s
        .catalog
        .list_organizations()
        .await
        .map_err(e500)?
        .into_iter()
        .find(|o| o.slug == org)
        .ok_or(StatusCode::NOT_FOUND)?;
    if user.can(summary.id) {
        Ok(summary)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

/// Like [`lookup_org`] but requires the `admin` role for mutations.
async fn lookup_org_admin(
    s: &Ui,
    user: &CurrentUser,
    org: &str,
) -> Result<sconce_catalog::OrgSummary, StatusCode> {
    let summary = lookup_org(s, user, org).await?;
    if user.can_admin(summary.id) {
        Ok(summary)
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

/// C1 — the org overview: its repositories with visibility, package count, and
/// last sync, plus create/settings entry points.
async fn org_overview_page(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path(org): Path<String>,
) -> Result<Html<String>, StatusCode> {
    let summary = lookup_org(&s, &user, &org).await?;
    let repos = s
        .catalog
        .org_repo_overview(summary.id)
        .await
        .map_err(e500)?;
    let usage = s.catalog.org_storage(summary.id).await.map_err(e500)?;
    let view = views::OrgOverview {
        org: org.clone(),
        can_admin: user.can_admin(summary.id),
        storage: format!(
            "{} across {} blob{}",
            human_bytes(usage.bytes),
            usage.blob_count,
            if usage.blob_count == 1 { "" } else { "s" }
        ),
        repos: repos
            .into_iter()
            .map(|r| views::RepoRow {
                slug: r.slug,
                private: r.allow_private_packages,
                broken: r.broken,
                packages: r.packages,
                last_sync: r.last_sync.unwrap_or_else(|| "never".to_owned()),
                update_mode: r.update_mode,
            })
            .collect(),
    };
    Ok(shell(&s, &user, &org, &view.render().map_err(e500)?))
}

async fn org_settings_page(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path(org): Path<String>,
) -> Result<Html<String>, StatusCode> {
    let summary = lookup_org(&s, &user, &org).await?;
    let cfg = s.catalog.org_settings(summary.id).await.map_err(e500)?;
    let conn = s
        .catalog
        .oidc_connection_for_org(summary.id)
        .await
        .map_err(e500)?;
    let former = s
        .catalog
        .former_slugs("org", summary.id)
        .await
        .unwrap_or_default();
    // The client secret is write-only and never rendered back.
    let oidc = match conn.as_ref() {
        Some(c) => views::OidcView {
            issuer: c.issuer_url.clone(),
            client_id: c.client_id.clone(),
            redirect: c.redirect_url.clone(),
            scopes: c.scopes.clone(),
            allowed: c
                .allowed_domains
                .as_ref()
                .map(|d| d.join(", "))
                .unwrap_or_default(),
            admin: c
                .admin_domains
                .as_ref()
                .map(|d| d.join(", "))
                .unwrap_or_default(),
        },
        None => views::OidcView {
            scopes: "openid email profile".to_owned(),
            ..Default::default()
        },
    };
    let view = views::OrgSettings {
        org: org.clone(),
        allow_raw_tokens: cfg.allow_raw_tokens,
        max_ttl: cfg
            .max_token_ttl_days
            .map(|d| d.to_string())
            .unwrap_or_default(),
        oidc_configured: conn.is_some(),
        oidc,
        former,
    };
    Ok(shell(
        &s,
        &user,
        &format!("{org} settings"),
        &view.render().map_err(e500)?,
    ))
}

#[derive(Deserialize)]
struct OidcForm {
    issuer: String,
    client_id: String,
    client_secret: Option<String>,
    redirect_url: String,
    scopes: String,
    allowed_domains: Option<String>,
    admin_domains: Option<String>,
}

/// Split a comma-separated domain list, trimming blanks. `None`/empty → `None`.
fn split_domains(x: Option<&str>) -> Option<Vec<String>> {
    let v: Vec<String> = x?
        .split(',')
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .map(ToOwned::to_owned)
        .collect();
    (!v.is_empty()).then_some(v)
}

async fn save_oidc(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path(org): Path<String>,
    Form(f): Form<OidcForm>,
) -> Result<Redirect, StatusCode> {
    let summary = lookup_org_admin(&s, &user, &org).await?;
    // Write-only secret: a blank field keeps the stored one (set_oidc_connection
    // replaces the row, so we must re-supply it).
    let client_secret = match f
        .client_secret
        .as_deref()
        .map(str::trim)
        .filter(|x| !x.is_empty())
    {
        Some(sec) => Some(sec.as_bytes().to_vec()),
        None => s
            .catalog
            .oidc_connection_for_org(summary.id)
            .await
            .map_err(e500)?
            .and_then(|c| c.client_secret),
    };
    let conn = sconce_catalog::OidcConnection {
        id: Uuid::nil(),
        org_slug: Some(org.clone()),
        issuer_url: f.issuer.trim().to_owned(),
        client_id: f.client_id.trim().to_owned(),
        client_secret,
        redirect_url: f.redirect_url.trim().to_owned(),
        scopes: f.scopes.trim().to_owned(),
        allowed_domains: split_domains(f.allowed_domains.as_deref()),
        admin_domains: split_domains(f.admin_domains.as_deref()),
    };
    s.catalog
        .set_oidc_connection(Some(&org), &conn)
        .await
        .map_err(|e| ent_status(&e))?;
    Ok(Redirect::to(&format!("/o/{org}/settings")))
}

/// Generate (or rotate) the org's SCIM bearer token and show it once.
async fn gen_scim_token(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path(org): Path<String>,
) -> Result<Html<String>, StatusCode> {
    lookup_org_admin(&s, &user, &org).await?;
    let token = s
        .catalog
        .create_scim_token(&org)
        .await
        .map_err(|e| ent_status(&e))?
        .ok_or(StatusCode::NOT_FOUND)?;
    let view = views::ScimToken {
        org: org.clone(),
        token,
    };
    Ok(shell(
        &s,
        &user,
        "SCIM token",
        &view.render().map_err(e500)?,
    ))
}

// ----- package sets (F6) -----

#[derive(Deserialize)]
struct NameForm {
    name: String,
}
#[derive(Deserialize)]
struct PackageNameForm {
    package: String,
}
#[derive(Deserialize)]
struct GlobForm {
    glob: String,
}
#[derive(Deserialize)]
struct IdForm {
    id: String,
}

/// Resolve a set within an org, 404/403-ing if it doesn't belong here.
async fn lookup_set(s: &Ui, org_id: Uuid, id: &str) -> Result<(Uuid, String), StatusCode> {
    let set_id = id.parse::<Uuid>().map_err(|_| StatusCode::BAD_REQUEST)?;
    let (name, set_org) = s
        .catalog
        .package_set(set_id)
        .await
        .map_err(e500)?
        .ok_or(StatusCode::NOT_FOUND)?;
    if set_org != org_id {
        return Err(StatusCode::NOT_FOUND);
    }
    Ok((set_id, name))
}

async fn sets_page(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path(org): Path<String>,
) -> Result<Html<String>, StatusCode> {
    let summary = lookup_org(&s, &user, &org).await?;
    let sets = s
        .catalog
        .list_package_sets(summary.id)
        .await
        .map_err(e500)?;
    let mut rows = Vec::with_capacity(sets.len());
    for st in &sets {
        let count = s.catalog.resolve_set(st.id).await.map_err(e500)?.len();
        rows.push(views::SetRow {
            id: st.id.to_string(),
            name: st.name.clone(),
            count,
        });
    }
    let view = views::SetsList {
        org: org.clone(),
        sets: rows,
    };
    Ok(shell(
        &s,
        &user,
        "Package sets",
        &view.render().map_err(e500)?,
    ))
}

async fn create_set(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path(org): Path<String>,
    Form(f): Form<NameForm>,
) -> Result<Response, StatusCode> {
    let summary = lookup_org_admin(&s, &user, &org).await?;
    match s.catalog.create_package_set(summary.id, &f.name).await {
        Ok(_) => Ok(Redirect::to(&format!("/o/{org}/sets")).into_response()),
        Err(_) => Ok(error_card(
            &s,
            &user,
            "Couldn't create set",
            "A set with that name already exists.",
            &format!("/o/{org}/sets"),
        )),
    }
}

#[allow(clippy::too_many_lines)]
async fn set_editor_page(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, id)): Path<(String, String)>,
) -> Result<Html<String>, StatusCode> {
    let summary = lookup_org(&s, &user, &org).await?;
    let (set_id, name) = lookup_set(&s, summary.id, &id).await?;
    let members = s.catalog.set_members(set_id).await.map_err(e500)?;
    let rules = s.catalog.set_rules(set_id).await.map_err(e500)?;
    let resolved = s.catalog.resolve_set(set_id).await.map_err(e500)?;
    let view = views::SetEditor {
        org: org.clone(),
        set_id: set_id.to_string(),
        name: name.clone(),
        members: members
            .into_iter()
            .map(|(pid, pname)| views::SetMember {
                id: pid.to_string(),
                name: pname,
            })
            .collect(),
        rules: rules
            .into_iter()
            .map(|(rid, glob)| views::SetRule {
                id: rid.to_string(),
                glob,
            })
            .collect(),
        resolved,
    };
    Ok(shell(&s, &user, &name, &view.render().map_err(e500)?))
}

async fn delete_set(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, id)): Path<(String, String)>,
) -> Result<Redirect, StatusCode> {
    let summary = lookup_org_admin(&s, &user, &org).await?;
    let (set_id, _) = lookup_set(&s, summary.id, &id).await?;
    s.catalog
        .delete_package_set(summary.id, set_id)
        .await
        .map_err(e500)?;
    Ok(Redirect::to(&format!("/o/{org}/sets")))
}

async fn add_set_member(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, id)): Path<(String, String)>,
    Form(f): Form<PackageNameForm>,
) -> Result<Response, StatusCode> {
    let summary = lookup_org_admin(&s, &user, &org).await?;
    let (set_id, _) = lookup_set(&s, summary.id, &id).await?;
    match s
        .catalog
        .find_package_in_org(summary.id, f.package.trim())
        .await
        .map_err(e500)?
    {
        Some(pid) => {
            s.catalog.add_set_member(set_id, pid).await.map_err(e500)?;
            Ok(Redirect::to(&format!("/o/{org}/sets/{id}")).into_response())
        }
        None => Ok(error_card(
            &s,
            &user,
            "Package not found",
            "No package with that name in this organization.",
            &format!("/o/{org}/sets/{id}"),
        )),
    }
}

async fn remove_set_member(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, id)): Path<(String, String)>,
    Form(f): Form<IdForm>,
) -> Result<Redirect, StatusCode> {
    let summary = lookup_org_admin(&s, &user, &org).await?;
    let (set_id, _) = lookup_set(&s, summary.id, &id).await?;
    let pid = f.id.parse::<Uuid>().map_err(|_| StatusCode::BAD_REQUEST)?;
    s.catalog
        .remove_set_member(set_id, pid)
        .await
        .map_err(e500)?;
    Ok(Redirect::to(&format!("/o/{org}/sets/{id}")))
}

async fn add_set_rule(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, id)): Path<(String, String)>,
    Form(f): Form<GlobForm>,
) -> Result<Redirect, StatusCode> {
    let summary = lookup_org_admin(&s, &user, &org).await?;
    let (set_id, _) = lookup_set(&s, summary.id, &id).await?;
    s.catalog
        .add_set_rule(set_id, f.glob.trim())
        .await
        .map_err(e500)?;
    Ok(Redirect::to(&format!("/o/{org}/sets/{id}")))
}

async fn remove_set_rule(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, id)): Path<(String, String)>,
    Form(f): Form<IdForm>,
) -> Result<Redirect, StatusCode> {
    let summary = lookup_org_admin(&s, &user, &org).await?;
    lookup_set(&s, summary.id, &id).await?;
    let rid = f.id.parse::<Uuid>().map_err(|_| StatusCode::BAD_REQUEST)?;
    s.catalog.remove_set_rule(rid).await.map_err(e500)?;
    Ok(Redirect::to(&format!("/o/{org}/sets/{id}")))
}

async fn rename_org_action(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path(org): Path<String>,
    Form(f): Form<RenameForm>,
) -> Result<Response, StatusCode> {
    let summary = lookup_org_admin(&s, &user, &org).await?;
    let new = f.slug.trim().to_owned();
    match s.catalog.rename_org(summary.id, &new).await {
        Ok(()) => Ok(Redirect::to(&format!("/o/{new}/settings")).into_response()),
        Err(e @ (sconce_catalog::RenameError::Taken | sconce_catalog::RenameError::Retired)) => Ok(
            rename_failed(&s, &user, &format!("/o/{org}/settings"), &e.to_string()),
        ),
        Err(_) => Err(StatusCode::BAD_REQUEST),
    }
}

#[derive(serde::Deserialize)]
struct OrgSettingsForm {
    /// Present (="1") only when the checkbox is ticked.
    allow_raw_tokens: Option<String>,
    /// Blank/absent = no cap.
    max_token_ttl_days: Option<String>,
}

async fn save_org_settings(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path(org): Path<String>,
    Form(f): Form<OrgSettingsForm>,
) -> Result<Redirect, StatusCode> {
    let summary = lookup_org_admin(&s, &user, &org).await?;
    let max_token_ttl_days = f
        .max_token_ttl_days
        .as_deref()
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .map(str::parse::<i64>)
        .transpose()
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .filter(|d| *d > 0);
    let settings = sconce_catalog::OrgSettings {
        allow_raw_tokens: f.allow_raw_tokens.is_some(),
        max_token_ttl_days,
    };
    s.catalog
        .set_org_settings(summary.id, settings)
        .await
        .map_err(e500)?;
    Ok(Redirect::to(&format!("/o/{org}/settings")))
}

async fn repo_settings_page(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, repo)): Path<(String, String)>,
) -> Result<Html<String>, StatusCode> {
    let summary = lookup(&s, &user, &org, &repo).await?;
    let repo_cfg = s.catalog.repo_settings(summary.id).await.map_err(e500)?;
    let org_cfg = s.catalog.org_settings(summary.org_id).await.map_err(e500)?;
    let effective = s
        .catalog
        .effective_token_policy(summary.id)
        .await
        .map_err(e500)?;
    let former = s
        .catalog
        .former_slugs("repo", summary.id)
        .await
        .unwrap_or_default();
    let ttl = |d: Option<i64>| d.map_or_else(|| "no limit".to_owned(), |d| format!("{d} day(s)"));
    let view = views::RepoSettings {
        org: org.clone(),
        repo: repo.clone(),
        // Three-way override: inherit / allow / deny.
        raw_mode: match repo_cfg.allow_raw_tokens {
            None => "inherit",
            Some(true) => "allow",
            Some(false) => "deny",
        },
        repo_ttl: repo_cfg
            .max_token_ttl_days
            .map(|d| d.to_string())
            .unwrap_or_default(),
        private: repo_cfg.allow_private_packages,
        org_raw: if org_cfg.allow_raw_tokens {
            "allowed"
        } else {
            "disabled"
        },
        org_ttl: ttl(org_cfg.max_token_ttl_days),
        eff_raw: if effective.allow_raw_tokens {
            "allowed"
        } else {
            "disabled"
        },
        eff_ttl: ttl(effective.max_token_ttl_days),
        former,
    };
    Ok(shell(
        &s,
        &user,
        &format!("{org}/{repo} settings"),
        &view.render().map_err(e500)?,
    ))
}

/// A muted "Formerly: a, b" line (still redirecting), or empty if never renamed.
#[derive(Deserialize)]
struct RenameForm {
    slug: String,
}

/// A simple error page: title + an amber banner message + a back link.
fn error_card(s: &Ui, user: &CurrentUser, title: &str, msg: &str, back: &str) -> Response {
    let body = views::ErrorCard {
        title: title.to_owned(),
        msg: msg.to_owned(),
        back: back.to_owned(),
    }
    .render()
    .unwrap_or_default();
    shell(s, user, title, &body).into_response()
}

fn rename_failed(s: &Ui, user: &CurrentUser, back: &str, msg: &str) -> Response {
    error_card(s, user, "Rename failed", msg, back)
}

#[derive(Deserialize)]
struct ConfirmForm {
    confirm: String,
}

async fn delete_repo_action(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, repo)): Path<(String, String)>,
    Form(f): Form<ConfirmForm>,
) -> Result<Response, StatusCode> {
    let summary = lookup_admin(&s, &user, &org, &repo).await?;
    if f.confirm.trim() != repo {
        return Ok(error_card(
            &s,
            &user,
            "Repository not deleted",
            "The confirmation name didn't match.",
            &format!("/r/{org}/{repo}/settings"),
        ));
    }
    s.catalog.delete_repo(summary.id).await.map_err(e500)?;
    Ok(Redirect::to(&format!("/o/{org}")).into_response())
}

async fn rename_repo_action(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, repo)): Path<(String, String)>,
    Form(f): Form<RenameForm>,
) -> Result<Response, StatusCode> {
    let summary = lookup_admin(&s, &user, &org, &repo).await?;
    let new = f.slug.trim().to_owned();
    match s.catalog.rename_repo(summary.id, &new).await {
        Ok(()) => Ok(Redirect::to(&format!("/r/{org}/{new}")).into_response()),
        Err(e @ (sconce_catalog::RenameError::Taken | sconce_catalog::RenameError::Retired)) => {
            Ok(rename_failed(
                &s,
                &user,
                &format!("/r/{org}/{repo}/settings"),
                &e.to_string(),
            ))
        }
        Err(_) => Err(StatusCode::BAD_REQUEST),
    }
}

#[derive(serde::Deserialize)]
struct RepoSettingsForm {
    /// `inherit` | `allow` | `deny`.
    allow_raw_tokens: String,
    /// Blank/absent = inherit.
    max_token_ttl_days: Option<String>,
    /// Present (="1") only when the checkbox is ticked.
    allow_private_packages: Option<String>,
}

async fn save_repo_settings(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, repo)): Path<(String, String)>,
    Form(f): Form<RepoSettingsForm>,
) -> Result<Redirect, StatusCode> {
    let summary = lookup_admin(&s, &user, &org, &repo).await?;
    let allow_raw_tokens = match f.allow_raw_tokens.as_str() {
        "allow" => Some(true),
        "deny" => Some(false),
        _ => None, // inherit
    };
    let max_token_ttl_days = f
        .max_token_ttl_days
        .as_deref()
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .map(str::parse::<i64>)
        .transpose()
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .filter(|d| *d > 0);
    let settings = sconce_catalog::RepoSettings {
        allow_raw_tokens,
        max_token_ttl_days,
        allow_private_packages: f.allow_private_packages.is_some(),
    };
    s.catalog
        .set_repo_settings(summary.id, settings)
        .await
        .map_err(e500)?;
    Ok(Redirect::to(&format!("/r/{org}/{repo}/settings")))
}

// ----- login -----

/// A standalone centered status page (404 etc.) — themed, needs no user.
fn status_page(title: &str, msg: &str) -> Html<String> {
    let body = views::StatusPage {
        title: title.to_owned(),
        msg: msg.to_owned(),
    }
    .render()
    .unwrap_or_default();
    doc(title, &body)
}

async fn not_found_page() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        status_page("Page not found", "That page doesn't exist."),
    )
}

/// Render the sign-in page (two-pane card). A non-empty `error` shows an inline
/// banner above the email field. Shared by the form and every auth error path.
async fn login_page(s: &Ui, error: &str) -> Html<String> {
    // Offer SSO if configured: a direct button for the instance default, plus an
    // email box that routes org domains to their own IdP.
    let sso_enabled = s.catalog.oidc_configured().await.unwrap_or(false);
    let has_default = sso_enabled && matches!(s.catalog.oidc_connection().await, Ok(Some(_)));
    let body = views::Login {
        sso_enabled,
        has_default,
        error: error.to_owned(),
    }
    .render()
    .unwrap_or_default();
    doc("Sign in", &body)
}

async fn login_form(State(s): State<Ui>) -> Html<String> {
    login_page(&s, "").await
}

#[derive(Deserialize)]
struct LoginForm {
    email: String,
    password: String,
}

async fn login(
    State(s): State<Ui>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(f): Form<LoginForm>,
) -> Result<Response, StatusCode> {
    let ip = client_ip(&headers, Some(peer));
    let email = f.email.trim().to_ascii_lowercase();
    if !s
        .limiter
        .allow(&format!("login:ip:{ip}"), LOGIN_MAX_PER_IP, LOGIN_WINDOW)
        || !s.limiter.allow(
            &format!("login:email:{email}"),
            LOGIN_MAX_PER_EMAIL,
            LOGIN_WINDOW,
        )
    {
        return Ok(too_many_attempts());
    }
    let Some(user_id) = s
        .catalog
        .verify_credentials(&f.email, &f.password)
        .await
        .map_err(e500)?
    else {
        return Ok(
            login_page(&s, "Invalid email or password. Try again, or use SSO.")
                .await
                .into_response(),
        );
    };
    let token = s.catalog.create_session(user_id, 7).await.map_err(e500)?;
    Ok(redirect_with_cookie(
        "/",
        &session_set_cookie(&token, s.cookie_secure),
    ))
}

// ----- password reset -----

/// How long a reset link stays valid.
const RESET_TTL_MINUTES: i64 = 60;
/// Minimum new-password length (mirrors the form's `minlength`).
const MIN_PASSWORD_LEN: usize = 8;

/// Render the forgot-password page; a non-empty `error` shows an inline banner.
fn forgot_page(error: &str) -> Html<String> {
    let body = views::Forgot {
        error: error.to_owned(),
    }
    .render()
    .unwrap_or_default();
    doc("Forgot password", &body)
}

/// Render the set-new-password page for a (validated) token.
fn reset_page(token: &str, error: &str) -> Html<String> {
    let body = views::Reset {
        token: token.to_owned(),
        error: error.to_owned(),
    }
    .render()
    .unwrap_or_default();
    doc("Reset password", &body)
}

/// The neutral confirmation shown after requesting a reset — identical whether or
/// not the email matched an account (so it never reveals which emails exist).
fn forgot_sent_page() -> Html<String> {
    status_page(
        "Check your email",
        "If an account exists for that address, we've sent a password-reset link. \
         It expires in 60 minutes.",
    )
}

/// Password reset has no meaning without user accounts.
fn reset_disabled(s: &Ui) -> Option<Response> {
    s.single_tenant.then(|| {
        status_page(
            "Not available",
            "Password reset is disabled in single-tenant mode.",
        )
        .into_response()
    })
}

async fn forgot_form(State(s): State<Ui>) -> Response {
    if let Some(r) = reset_disabled(&s) {
        return r;
    }
    forgot_page("").into_response()
}

#[derive(Deserialize)]
struct ForgotForm {
    email: String,
}

async fn forgot_submit(
    State(s): State<Ui>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(f): Form<ForgotForm>,
) -> Result<Response, StatusCode> {
    if let Some(r) = reset_disabled(&s) {
        return Ok(r);
    }
    let email = f.email.trim();
    let ip = client_ip(&headers, Some(peer));
    if !s
        .limiter
        .allow(&format!("forgot:ip:{ip}"), FORGOT_MAX_PER_IP, FORGOT_WINDOW)
        || !s.limiter.allow(
            &format!("forgot:email:{}", email.to_ascii_lowercase()),
            FORGOT_MAX_PER_EMAIL,
            FORGOT_WINDOW,
        )
    {
        return Ok(too_many_attempts());
    }
    // Mint a token only if the user exists; either way the response is identical.
    if let Some(reset) = s
        .catalog
        .create_password_reset(email, RESET_TTL_MINUTES)
        .await
        .map_err(e500)?
    {
        let link = format!(
            "{}/reset?token={}",
            s.dashboard_url.trim_end_matches('/'),
            reset.token
        );
        let body = format!(
            "Someone (hopefully you) asked to reset the password for your Bougie Repo \
             account.\n\nOpen this link to choose a new password — it expires in {RESET_TTL_MINUTES} \
             minutes and can be used once:\n\n{link}\n\nIf you didn't request this, you can ignore \
             this email; your password won't change."
        );
        // Best-effort: a mail failure must not reveal that the account exists, so
        // log it server-side and still show the neutral confirmation.
        if let Err(e) = s
            .mailer
            .send(email, "Reset your Bougie Repo password", &body)
            .await
        {
            tracing::error!(email, error = %e, "failed to send password-reset link");
        }
    }
    Ok(forgot_sent_page().into_response())
}

#[derive(Deserialize)]
struct ResetParams {
    token: Option<String>,
}

async fn reset_form(State(s): State<Ui>, Query(q): Query<ResetParams>) -> Response {
    if let Some(r) = reset_disabled(&s) {
        return r;
    }
    let token = q.token.unwrap_or_default();
    match s.catalog.password_reset_valid(&token).await {
        Ok(true) => reset_page(&token, "").into_response(),
        Ok(false) => status_page(
            "Link expired",
            "This password-reset link is invalid or has expired. Request a new one from the \
             sign-in page.",
        )
        .into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

#[derive(Deserialize)]
struct ResetForm {
    token: String,
    password: String,
    confirm: String,
}

async fn reset_submit(
    State(s): State<Ui>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(f): Form<ResetForm>,
) -> Result<Response, StatusCode> {
    if let Some(r) = reset_disabled(&s) {
        return Ok(r);
    }
    let ip = client_ip(&headers, Some(peer));
    if !s
        .limiter
        .allow(&format!("reset:ip:{ip}"), RESET_MAX_PER_IP, RESET_WINDOW)
    {
        return Ok(too_many_attempts());
    }
    // Re-validate on submit (the token could have expired since the form loaded).
    if !s
        .catalog
        .password_reset_valid(&f.token)
        .await
        .map_err(e500)?
    {
        return Ok(status_page(
            "Link expired",
            "This password-reset link is invalid or has expired. Request a new one from the \
             sign-in page.",
        )
        .into_response());
    }
    if f.password.chars().count() < MIN_PASSWORD_LEN {
        return Ok(reset_page(&f.token, "Password must be at least 8 characters.").into_response());
    }
    if f.password != f.confirm {
        return Ok(reset_page(&f.token, "The passwords didn't match.").into_response());
    }
    // Consume the token + set the password. None means it was used/expired in a
    // race since the check above.
    if s.catalog
        .reset_password(&f.token, &f.password)
        .await
        .map_err(e500)?
        .is_none()
    {
        return Ok(status_page(
            "Link expired",
            "This password-reset link is invalid or has expired. Request a new one from the \
             sign-in page.",
        )
        .into_response());
    }
    Ok(status_page(
        "Password updated",
        "Your password has been reset and your other sessions signed out. \
         You can now sign in with your new password.",
    )
    .into_response())
}

/// Decrypt an OIDC connection's stored client secret (if any).
fn oidc_secret(
    s: &Ui,
    conn: &sconce_catalog::OidcConnection,
) -> Result<Option<String>, StatusCode> {
    match (&conn.client_secret, &s.secret_key) {
        (None, _) => Ok(None),
        (Some(ct), Some(key)) => key
            .decrypt(ct)
            .map(|b| Some(String::from_utf8_lossy(&b).into_owned()))
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR),
        // A secret is stored but no key to decrypt it → misconfiguration.
        (Some(_), None) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

#[derive(Deserialize)]
struct StartParams {
    conn: Option<String>,
}

/// Begin SSO: build the identity-provider redirect, persist the flow, redirect.
/// `?conn=<id>` selects a connection (org BYO-OIDC); absent = instance default.
async fn auth_start(
    State(s): State<Ui>,
    Query(q): Query<StartParams>,
) -> Result<Response, StatusCode> {
    let conn = match q.conn.as_deref().and_then(|c| c.parse::<uuid::Uuid>().ok()) {
        Some(id) => s.catalog.oidc_connection_by_id(id).await.map_err(e500)?,
        None => s.catalog.oidc_connection().await.map_err(e500)?,
    };
    let Some(conn) = conn else {
        return Err(StatusCode::NOT_FOUND);
    };
    let secret = oidc_secret(&s, &conn)?;
    let begin = match crate::oidc::begin(&conn, secret.as_deref()).await {
        Ok(b) => b,
        Err(e) => {
            return Ok(login_page(&s, &format!("SSO unavailable: {e}"))
                .await
                .into_response());
        }
    };
    s.catalog
        .create_oidc_flow(
            &begin.state,
            Some(conn.id),
            &begin.nonce,
            &begin.pkce_verifier,
            "/",
            600,
        )
        .await
        .map_err(e500)?;
    Ok(Redirect::to(&begin.auth_url).into_response())
}

#[derive(Deserialize)]
struct RouteForm {
    email: String,
}

/// Route an organization email to its identity provider (by domain), else the
/// instance default.
async fn auth_route(State(s): State<Ui>, Form(f): Form<RouteForm>) -> Result<Response, StatusCode> {
    match s
        .catalog
        .oidc_connection_for_email(&f.email)
        .await
        .map_err(e500)?
    {
        Some(id) => Ok(Redirect::to(&format!("/auth/start?conn={id}")).into_response()),
        None => Ok(login_page(&s, "no SSO is configured for that email domain")
            .await
            .into_response()),
    }
}

#[derive(Deserialize)]
struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// Finish SSO: validate the code/ID-token, JIT-provision the user, mint a session.
async fn auth_callback(
    State(s): State<Ui>,
    Query(p): Query<CallbackParams>,
) -> Result<Response, StatusCode> {
    if let Some(err) = p.error {
        return Ok(login_page(&s, &format!("IdP returned an error: {err}"))
            .await
            .into_response());
    }
    let (Some(code), Some(state)) = (p.code, p.state) else {
        return Err(StatusCode::BAD_REQUEST);
    };
    // The flow must exist (unknown/expired/replayed state → reject).
    let Some((conn_id, nonce, verifier, redirect_to)) =
        s.catalog.consume_oidc_flow(&state).await.map_err(e500)?
    else {
        return Ok(
            login_page(&s, "login session expired or invalid — try again")
                .await
                .into_response(),
        );
    };
    // Use the same connection the flow began with.
    let conn = match conn_id {
        Some(id) => s.catalog.oidc_connection_by_id(id).await.map_err(e500)?,
        None => s.catalog.oidc_connection().await.map_err(e500)?,
    };
    let Some(conn) = conn else {
        return Err(StatusCode::NOT_FOUND);
    };
    let secret = oidc_secret(&s, &conn)?;

    let identity =
        match crate::oidc::finish(&conn, secret.as_deref(), &code, &nonce, &verifier).await {
            Ok(id) => id,
            Err(e) => {
                return Ok(login_page(&s, &format!("SSO failed: {e}"))
                    .await
                    .into_response());
            }
        };

    // Gate by allowed domains (if configured), and grant superadmin by domain.
    if conn.allowed_domains.as_ref().is_some_and(|d| !d.is_empty())
        && !crate::oidc::domain_matches(&identity.email, &conn.allowed_domains)
    {
        return Ok(
            login_page(&s, "your email domain is not allowed to sign in")
                .await
                .into_response(),
        );
    }
    let is_superadmin = crate::oidc::domain_matches(&identity.email, &conn.admin_domains);
    let user_id = s
        .catalog
        .find_or_create_sso_user(&identity.email, is_superadmin)
        .await
        .map_err(e500)?;
    // An org-scoped connection grants membership in that org.
    if let Some(org) = &conn.org_slug {
        s.catalog
            .add_user_to_tenant(&identity.email, org, "member")
            .await
            .map_err(e500)?;
    }
    let token = s.catalog.create_session(user_id, 7).await.map_err(e500)?;
    let dest = if redirect_to.starts_with('/') {
        redirect_to
    } else {
        "/".to_owned()
    };
    Ok(redirect_with_cookie(
        &dest,
        &session_set_cookie(&token, s.cookie_secure),
    ))
}

// ----- SCIM provisioning (offboarding) -----
//
// A minimal SCIM 2.0 Users API the org's IdP drives. The key action is
// deactivation (PATCH/PUT active=false, or DELETE): the membership goes inactive
// AND the user's sessions are revoked, so access stops immediately — closing the
// gap that OIDC login alone leaves open.

fn scim_resp(status: StatusCode, v: &Value) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/scim+json")],
        v.to_string(),
    )
        .into_response()
}

fn scim_error(status: StatusCode, detail: &str) -> Response {
    scim_resp(
        status,
        &json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "detail": detail,
            "status": status.as_u16().to_string(),
        }),
    )
}

fn scim_user(id: uuid::Uuid, email: &str, active: bool) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": id.to_string(),
        "userName": email,
        "active": active,
        "emails": [{ "value": email, "primary": true }],
        "meta": { "resourceType": "User" },
    })
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(|t| t.trim().to_owned())
}

/// Authenticate a SCIM request → the org it provisions into.
async fn scim_org(s: &Ui, headers: &HeaderMap) -> Result<uuid::Uuid, Response> {
    let token = bearer(headers)
        .ok_or_else(|| scim_error(StatusCode::UNAUTHORIZED, "missing bearer token"))?;
    match s.catalog.resolve_scim_token(&token).await {
        Ok(Some(org)) => Ok(org),
        Ok(None) => Err(scim_error(StatusCode::UNAUTHORIZED, "invalid SCIM token")),
        Err(_) => Err(scim_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server error",
        )),
    }
}

/// Coerce a SCIM `active` value (bool, or "true"/"false" string) to a bool.
fn scim_bool(v: &Value) -> Option<bool> {
    v.as_bool()
        .or_else(|| v.as_str().and_then(|s| s.parse::<bool>().ok()))
}

/// Pull the requested `active` value out of a PATCH (Operations) or PUT body.
fn extract_active(body: &Value) -> Option<bool> {
    if let Some(ops) = body.get("Operations").and_then(Value::as_array) {
        for op in ops {
            let path = op
                .get("path")
                .and_then(Value::as_str)
                .map(str::to_ascii_lowercase);
            if path.as_deref() == Some("active")
                && let Some(b) = op.get("value").and_then(scim_bool)
            {
                return Some(b);
            }
            if let Some(b) = op
                .get("value")
                .and_then(|v| v.get("active"))
                .and_then(scim_bool)
            {
                return Some(b);
            }
        }
        return None;
    }
    body.get("active").and_then(scim_bool)
}

async fn scim_create_user(State(s): State<Ui>, headers: HeaderMap, body: String) -> Response {
    let org = match scim_org(&s, &headers).await {
        Ok(o) => o,
        Err(r) => return r,
    };
    let Ok(v) = serde_json::from_str::<Value>(&body) else {
        return scim_error(StatusCode::BAD_REQUEST, "invalid JSON");
    };
    let Some(email) = v.get("userName").and_then(Value::as_str) else {
        return scim_error(StatusCode::BAD_REQUEST, "userName is required");
    };
    // SCIM convention: a duplicate is 409 (the IdP GETs by filter first).
    match s.catalog.scim_member_by_email(org, email).await {
        Ok(Some(_)) => return scim_error(StatusCode::CONFLICT, "user already provisioned"),
        Ok(None) => {}
        Err(_) => return scim_error(StatusCode::INTERNAL_SERVER_ERROR, "server error"),
    }
    let Ok(id) = s.catalog.scim_provision(org, email).await else {
        return scim_error(StatusCode::INTERNAL_SERVER_ERROR, "provisioning failed");
    };
    scim_resp(StatusCode::CREATED, &scim_user(id, email, true))
}

#[derive(Deserialize)]
struct ScimQuery {
    filter: Option<String>,
}

async fn scim_list_users(
    State(s): State<Ui>,
    headers: HeaderMap,
    Query(q): Query<ScimQuery>,
) -> Response {
    let org = match scim_org(&s, &headers).await {
        Ok(o) => o,
        Err(r) => return r,
    };
    // Support `userName eq "email"` (what Okta/Azure send to find a user).
    let resources: Vec<Value> = match q.filter.as_deref().and_then(parse_username_filter) {
        Some(email) => match s.catalog.scim_member_by_email(org, &email).await {
            Ok(Some((id, active))) => vec![scim_user(id, &email, active)],
            Ok(None) => vec![],
            Err(_) => return scim_error(StatusCode::INTERNAL_SERVER_ERROR, "server error"),
        },
        None => vec![],
    };
    scim_resp(
        StatusCode::OK,
        &json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": resources.len(),
            "startIndex": 1,
            "itemsPerPage": resources.len(),
            "Resources": resources,
        }),
    )
}

/// Extract the email from a `userName eq "..."` SCIM filter.
fn parse_username_filter(filter: &str) -> Option<String> {
    let lower = filter.to_ascii_lowercase();
    if !lower.contains("username") || !lower.contains(" eq ") {
        return None;
    }
    let start = filter.find('"')?;
    let rest = &filter[start + 1..];
    let end = rest.find('"')?;
    Some(rest[..end].to_owned())
}

async fn scim_get_user(
    State(s): State<Ui>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let org = match scim_org(&s, &headers).await {
        Ok(o) => o,
        Err(r) => return r,
    };
    let Ok(uid) = id.parse::<uuid::Uuid>() else {
        return scim_error(StatusCode::NOT_FOUND, "no such user");
    };
    match s.catalog.scim_member(org, uid).await {
        Ok(Some((email, active))) => scim_resp(StatusCode::OK, &scim_user(uid, &email, active)),
        Ok(None) => scim_error(StatusCode::NOT_FOUND, "no such user"),
        Err(_) => scim_error(StatusCode::INTERNAL_SERVER_ERROR, "server error"),
    }
}

/// Apply an `active` change (the offboarding action) and return the resource.
async fn scim_apply_active(s: &Ui, org: uuid::Uuid, uid: uuid::Uuid, active: bool) -> Response {
    match s.catalog.scim_set_active(org, uid, active).await {
        Ok(true) => {}
        Ok(false) => return scim_error(StatusCode::NOT_FOUND, "no such user"),
        Err(_) => return scim_error(StatusCode::INTERNAL_SERVER_ERROR, "server error"),
    }
    if !active {
        // Deactivation: revoke sessions so access stops now, not at token expiry.
        let _ = s.catalog.delete_user_sessions(uid).await;
    }
    match s.catalog.scim_member(org, uid).await {
        Ok(Some((email, a))) => scim_resp(StatusCode::OK, &scim_user(uid, &email, a)),
        _ => scim_error(StatusCode::INTERNAL_SERVER_ERROR, "server error"),
    }
}

async fn scim_patch_user(
    State(s): State<Ui>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: String,
) -> Response {
    let org = match scim_org(&s, &headers).await {
        Ok(o) => o,
        Err(r) => return r,
    };
    let (Ok(uid), Ok(v)) = (
        id.parse::<uuid::Uuid>(),
        serde_json::from_str::<Value>(&body),
    ) else {
        return scim_error(StatusCode::BAD_REQUEST, "invalid request");
    };
    match extract_active(&v) {
        Some(active) => scim_apply_active(&s, org, uid, active).await,
        // No active change we understand → just echo the current resource.
        None => scim_get_user(State(s), headers, Path(id)).await,
    }
}

async fn scim_put_user(
    State(s): State<Ui>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: String,
) -> Response {
    scim_patch_user(State(s), headers, Path(id), body).await
}

async fn scim_delete_user(
    State(s): State<Ui>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let org = match scim_org(&s, &headers).await {
        Ok(o) => o,
        Err(r) => return r,
    };
    let Ok(uid) = id.parse::<uuid::Uuid>() else {
        return scim_error(StatusCode::NOT_FOUND, "no such user");
    };
    // Treat DELETE as deactivation (don't destroy the account globally).
    match s.catalog.scim_set_active(org, uid, false).await {
        Ok(true) => {
            let _ = s.catalog.delete_user_sessions(uid).await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => scim_error(StatusCode::NOT_FOUND, "no such user"),
        Err(_) => scim_error(StatusCode::INTERNAL_SERVER_ERROR, "server error"),
    }
}

async fn logout(State(s): State<Ui>, headers: HeaderMap) -> Response {
    if let Some(token) = session_cookie(&headers) {
        let _ = s.catalog.delete_session(&token).await;
    }
    redirect_with_cookie("/login", &session_clear_cookie(s.cookie_secure))
}

/// A4 — the signed-in user's account: email + active sessions (revocable).
async fn account_page(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    headers: HeaderMap,
) -> Result<Html<String>, StatusCode> {
    let Some(uid) = user.id else {
        return Ok(shell(
            &s,
            &user,
            "Account",
            "<h1>Account</h1><p class=muted>Single-tenant mode uses HTTP-basic admin auth — \
             there's no per-user account here.</p>",
        ));
    };
    let email = s
        .catalog
        .user_email(uid)
        .await
        .map_err(e500)?
        .unwrap_or_default();
    let current = session_cookie(&headers);
    let sessions = s
        .catalog
        .list_sessions(uid, current.as_deref())
        .await
        .map_err(e500)?;
    let view = views::Account {
        email,
        is_superadmin: user.is_superadmin,
        sessions: sessions
            .into_iter()
            .map(|sn| views::SessionRow {
                created: sn.created,
                expires: sn.expires,
                id: sn.hash_hex,
                current: sn.current,
            })
            .collect(),
    };
    Ok(shell(&s, &user, "Account", &view.render().map_err(e500)?))
}

#[derive(Deserialize)]
struct RevokeSessionForm {
    id: String,
}

async fn revoke_my_session(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Form(f): Form<RevokeSessionForm>,
) -> Result<Redirect, StatusCode> {
    let uid = user.id.ok_or(StatusCode::FORBIDDEN)?;
    s.catalog
        .revoke_session_for_user(uid, &f.id)
        .await
        .map_err(e500)?;
    Ok(Redirect::to("/account"))
}

// ----- superadmin: users -----

async fn users_page(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
) -> Result<Html<String>, StatusCode> {
    if !user.is_superadmin {
        return Err(StatusCode::FORBIDDEN);
    }
    let users = s.catalog.list_users().await.map_err(e500)?;
    let view = views::UsersPage {
        users: users
            .into_iter()
            .map(|u| views::UserRow {
                email: u.email,
                is_superadmin: u.is_superadmin,
                // Each membership: slug + role badge, inline role select + Remove.
                // Deactivated (SCIM-offboarded) memberships read red.
                tenants: u
                    .tenants
                    .into_iter()
                    .map(|t| views::TenantChip {
                        tone: if !t.active {
                            "held"
                        } else if t.role == "admin" {
                            "violet"
                        } else {
                            "slate"
                        },
                        slug: t.slug,
                        active: t.active,
                        role: t.role,
                    })
                    .collect(),
            })
            .collect(),
    };
    Ok(shell(&s, &user, "Users", &view.render().map_err(e500)?))
}

/// G2 — superadmin instance console: totals, instance SSO, and all orgs.
async fn console_page(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
) -> Result<Html<String>, StatusCode> {
    if !user.is_superadmin {
        return Err(StatusCode::FORBIDDEN);
    }
    let orgs = s.catalog.list_organizations().await.map_err(e500)?;
    let repos = s.catalog.list_repositories().await.map_err(e500)?;
    let users = s.catalog.list_users().await.map_err(e500)?;
    let oidc = s.catalog.oidc_connection().await.map_err(e500)?;
    let view = views::Console {
        orgs: orgs.len(),
        repos: repos.len(),
        users: users.len(),
        oidc_configured: oidc.is_some(),
        org_rows: orgs
            .iter()
            .map(|o| views::ConsoleOrg {
                slug: o.slug.clone(),
                repos: repos.iter().filter(|r| r.org_id == o.id).count(),
            })
            .collect(),
    };
    Ok(shell(
        &s,
        &user,
        "Instance console",
        &view.render().map_err(e500)?,
    ))
}

/// G1 — the "is it done yet?" surface: recent mirror jobs and their state.
async fn activity_page(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
) -> Result<Html<String>, StatusCode> {
    // Single-tenant / superadmin see everything; a tenant member sees their orgs.
    let scoped: Vec<Uuid> = user.tenants.iter().copied().collect();
    let org_ids = if s.single_tenant || user.is_superadmin {
        None
    } else {
        Some(scoped.as_slice())
    };
    let jobs = s.catalog.recent_jobs(100, org_ids).await.map_err(e500)?;
    let view = views::Activity {
        jobs: jobs
            .into_iter()
            .map(|j| {
                // Status as a tone badge; a backing-off pending job reads as
                // "retrying", a terminal failure as red (with its error).
                let (tone, status) = match j.status.as_str() {
                    "ready" => ("ok", "ready".to_owned()),
                    "running" => ("blue", "running".to_owned()),
                    "failed" => ("held", "failed".to_owned()),
                    _ if j.attempts > 1 => ("amber", format!("retrying · attempt {}", j.attempts)),
                    _ => ("slate", "queued".to_owned()),
                };
                let kind = match j.kind.as_str() {
                    "mirror_upstream" => "upstream sync",
                    "mirror_package" => "package mirror",
                    "resolve_closure" => "dependency resolve",
                    other => other,
                }
                .to_owned();
                let err = match (j.last_error, j.status.as_str()) {
                    (Some(e), "failed") => e,
                    _ => String::new(),
                };
                views::JobRow {
                    tone,
                    status,
                    kind,
                    target: j.target,
                    repo: j.repo.unwrap_or_else(|| "—".to_owned()),
                    err,
                    updated: j.updated,
                }
            })
            .collect(),
    };
    Ok(shell(&s, &user, "Activity", &view.render().map_err(e500)?))
}

#[derive(Deserialize)]
struct CreateUserForm {
    email: String,
    password: String,
    superadmin: Option<String>,
}

async fn create_user(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Form(f): Form<CreateUserForm>,
) -> Result<Redirect, StatusCode> {
    if !user.is_superadmin {
        return Err(StatusCode::FORBIDDEN);
    }
    s.catalog
        .create_user(&f.email, &f.password, f.superadmin.is_some())
        .await
        .map_err(e500)?;
    Ok(Redirect::to("/users"))
}

#[derive(Deserialize)]
struct GrantTenantForm {
    email: String,
    tenant: String,
    role: Option<String>,
}

async fn grant_tenant(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Form(f): Form<GrantTenantForm>,
) -> Result<Redirect, StatusCode> {
    if !user.is_superadmin {
        return Err(StatusCode::FORBIDDEN);
    }
    let role = match f.role.as_deref() {
        Some("admin") => "admin",
        _ => "member",
    };
    s.catalog
        .add_user_to_tenant(&f.email, &f.tenant, role)
        .await
        .map_err(e500)?;
    Ok(Redirect::to("/users"))
}

#[derive(Deserialize)]
struct RemoveMemberForm {
    email: String,
    tenant: String,
}

async fn remove_member(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Form(f): Form<RemoveMemberForm>,
) -> Result<Redirect, StatusCode> {
    if !user.is_superadmin {
        return Err(StatusCode::FORBIDDEN);
    }
    s.catalog
        .remove_from_tenant(&f.email, &f.tenant)
        .await
        .map_err(e500)?;
    Ok(Redirect::to("/users"))
}

// ----- index + org/repo creation -----

#[allow(clippy::too_many_lines)] // page builder; clearer kept together
async fn index(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
) -> Result<Html<String>, StatusCode> {
    let orgs = s.catalog.list_organizations().await.map_err(e500)?;
    let visible: Vec<_> = orgs.iter().filter(|o| user.can(o.id)).collect();

    // Scope repo + activity queries to the user's orgs (None = all, for a
    // superadmin or single-tenant), in one query each.
    let scoped: Vec<Uuid> = user.tenants.iter().copied().collect();
    let org_ids = if s.single_tenant || user.is_superadmin {
        None
    } else {
        Some(scoped.as_slice())
    };
    let repos = s.catalog.home_repo_overview(org_ids).await.map_err(e500)?;

    // Greeting: capitalize the first name-ish token of the email local part.
    let greeting = match user.id {
        Some(uid) => {
            let email = s
                .catalog
                .user_email(uid)
                .await
                .map_err(e500)?
                .unwrap_or_default();
            let local = email.split('@').next().unwrap_or("");
            let first = local
                .split(['.', '+', '_'])
                .next()
                .filter(|s| !s.is_empty());
            match first {
                Some(f) => format!("Welcome back, {}", capitalize(f)),
                None => "Welcome back".to_owned(),
            }
        }
        None => "Welcome back".to_owned(),
    };

    // Org cards, each with its repo rows (or an empty state).
    let org_cards: Vec<views::OrgCard> = visible
        .iter()
        .map(|o| views::OrgCard {
            slug: o.slug.clone(),
            name: o
                .name
                .as_deref()
                .filter(|n| !n.is_empty())
                .unwrap_or(&o.slug)
                .to_owned(),
            can_admin: user.can_admin(o.id),
            repos: repos
                .iter()
                .filter(|r| r.org_id == o.id)
                .map(|r| {
                    let (sync_tone, sync_label, when) = match &r.last_sync {
                        Some(ls) if r.broken > 0 => ("held", "failed", ls.clone()),
                        Some(ls) => ("ok", "ready", ls.clone()),
                        None => ("", "never synced", String::new()),
                    };
                    views::OrgCardRepo {
                        slug: r.slug.clone(),
                        private: r.allow_private_packages,
                        packages: r.packages,
                        sync_tone,
                        sync_label,
                        when,
                    }
                })
                .collect(),
        })
        .collect();

    // Recent activity (right column).
    let jobs = s.catalog.recent_jobs(6, org_ids).await.map_err(e500)?;
    let activity: Vec<views::ActItem> = jobs
        .into_iter()
        .map(|j| {
            let (ic_bg, icon) = match j.status.as_str() {
                "running" => ("#e9f0fc", "spinner"),
                "ready" => ("#e8f5ec", "check"),
                "failed" => ("#fceae7", "x"),
                _ => ("#eef1f6", "dot"),
            };
            let failed = j.status == "failed";
            views::ActItem {
                ic_bg,
                icon,
                kind: j.kind,
                target: (j.target != "dependency closure").then_some(j.target),
                failed,
                repo: j.repo,
                err: if failed {
                    j.last_error.unwrap_or_else(|| "failed".to_owned())
                } else {
                    String::new()
                },
                status: j.status,
                when: j.updated,
            }
        })
        .collect();

    let view = views::Home {
        greeting,
        attention: repos.iter().map(|r| r.broken).sum(),
        can_new_org: user.is_superadmin,
        can_new_repo: orgs.iter().any(|o| user.can_admin(o.id)),
        orgs: org_cards,
        activity,
    };
    Ok(shell(&s, &user, "Home", &view.render().map_err(e500)?))
}

#[derive(Deserialize)]
struct RepoFilter {
    /// Substring filter on the repository name.
    q: Option<String>,
    /// Visibility filter: `private` | `public` (absent / other = all).
    vis: Option<String>,
}

/// The Repositories page (design C1): a single table of every repository you can
/// reach — visibility, update mode, package / pending counts, last sync — with a
/// name + visibility filter.
async fn repositories_page(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Query(f): Query<RepoFilter>,
) -> Result<Html<String>, StatusCode> {
    let orgs = s.catalog.list_organizations().await.map_err(e500)?;
    // org_id → slug, for building `/r/{org}/{repo}` links on a flat table.
    let org_slug: HashMap<Uuid, &str> = orgs
        .iter()
        .filter(|o| user.can(o.id))
        .map(|o| (o.id, o.slug.as_str()))
        .collect();
    let scoped: Vec<Uuid> = user.tenants.iter().copied().collect();
    let org_ids = if s.single_tenant || user.is_superadmin {
        None
    } else {
        Some(scoped.as_slice())
    };
    let all = s.catalog.home_repo_overview(org_ids).await.map_err(e500)?;

    // Apply the name / visibility filters (and only show repos in orgs we can see).
    let needle = f.q.as_deref().unwrap_or("").trim().to_lowercase();
    let vis_filter = f.vis.as_deref().unwrap_or("");
    let repos: Vec<_> = all
        .iter()
        .filter(|r| org_slug.contains_key(&r.org_id))
        .filter(|r| needle.is_empty() || r.slug.to_lowercase().contains(&needle))
        .filter(|r| match vis_filter {
            "private" => r.allow_private_packages,
            "public" => !r.allow_private_packages,
            _ => true,
        })
        .collect();

    let rows: Vec<views::RepoTableRow> = repos
        .iter()
        .filter_map(|r| {
            let org = (*org_slug.get(&r.org_id)?).to_owned();
            let (never, sync_tone, sync_label, when) = match &r.last_sync {
                Some(ls) if r.broken > 0 => (false, "held", "failed", ls.clone()),
                Some(ls) => (false, "ok", "ready", ls.clone()),
                None => (true, "", "", String::new()),
            };
            Some(views::RepoTableRow {
                org,
                slug: r.slug.clone(),
                private: r.allow_private_packages,
                mode: match r.update_mode.as_str() {
                    "delayed" => format!("delayed · {}d", r.cooldown_days),
                    other => other.to_owned(),
                },
                packages: r.packages,
                pending: r.pending,
                never,
                sync_tone,
                sync_label,
                when,
            })
        })
        .collect();

    let view = views::Repositories {
        count: rows.len(),
        can_new_repo: orgs.iter().any(|o| user.can_admin(o.id)),
        q: f.q.as_deref().unwrap_or("").to_owned(),
        vis: vis_filter.to_owned(),
        repos: rows,
    };
    Ok(shell(
        &s,
        &user,
        "Repositories",
        &view.render().map_err(e500)?,
    ))
}

/// Uppercase the first character of `s` (ASCII/Unicode-aware), leaving the rest.
fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

#[derive(Deserialize)]
struct NewRepoQuery {
    /// Pre-select this org in the dropdown (e.g. from an org's "create one" link).
    org: Option<String>,
}

/// The "New repository" screen: pick an org you administer + a name.
async fn new_repo_page(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Query(q): Query<NewRepoQuery>,
) -> Result<Html<String>, StatusCode> {
    let orgs = s.catalog.list_organizations().await.map_err(e500)?;
    let admin_orgs: Vec<String> = orgs
        .iter()
        .filter(|o| user.can_admin(o.id))
        .map(|o| o.slug.clone())
        .collect();
    let view = views::NewRepo {
        is_superadmin: user.is_superadmin,
        selected: q.org.unwrap_or_default(),
        orgs: admin_orgs,
    };
    Ok(shell(
        &s,
        &user,
        "New repository",
        &view.render().map_err(e500)?,
    ))
}

/// The "New organization" screen (superadmin).
async fn new_org_page(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
) -> Result<Html<String>, StatusCode> {
    if !user.is_superadmin {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(shell(
        &s,
        &user,
        "New organization",
        &views::NewOrg.render().map_err(e500)?,
    ))
}

#[derive(Deserialize)]
struct OrgForm {
    slug: String,
    name: Option<String>,
}

async fn create_org(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Form(f): Form<OrgForm>,
) -> Result<Response, StatusCode> {
    if !user.is_superadmin {
        return Err(StatusCode::FORBIDDEN);
    }
    // A retired slug can never be re-registered (it still redirects elsewhere).
    if s.catalog
        .org_slug_retired(f.slug.trim())
        .await
        .map_err(e500)?
    {
        return Ok(error_card(
            &s,
            &user,
            "Couldn't create organization",
            "That name was previously used and is permanently retired.",
            "/orgs/new",
        ));
    }
    let name = f.name.as_deref().filter(|n| !n.is_empty());
    s.catalog.create_org(&f.slug, name).await.map_err(e500)?;
    Ok(Redirect::to("/").into_response())
}

#[derive(Deserialize)]
struct RepoForm {
    org: String,
    repo: String,
}

async fn create_repo(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Form(f): Form<RepoForm>,
) -> Result<Response, StatusCode> {
    // Must have access to the target org.
    let org = s
        .catalog
        .list_organizations()
        .await
        .map_err(e500)?
        .into_iter()
        .find(|o| o.slug == f.org)
        .ok_or(StatusCode::BAD_REQUEST)?;
    if !user.can_admin(org.id) {
        return Err(StatusCode::FORBIDDEN);
    }
    // A retired repo slug can't be reused (it still redirects).
    if s.catalog
        .repo_slug_retired(org.id, f.repo.trim())
        .await
        .map_err(e500)?
    {
        return Ok(error_card(
            &s,
            &user,
            "Couldn't create repository",
            "That name was previously used in this organization and is retired.",
            "/repos/new",
        ));
    }
    s.catalog
        .create_repo(&f.org, &f.repo)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(Redirect::to(&format!("/r/{}/{}", f.org, f.repo)).into_response())
}

// ----- repository detail -----

#[allow(clippy::too_many_lines)]
#[derive(Deserialize)]
struct PageQuery {
    page: Option<i64>,
    /// Package-name search (substring).
    q: Option<String>,
    /// State filter: `held` | `yanked` | `approved`.
    state: Option<String>,
}

/// Percent-encode a query-string value (RFC 3986 unreserved set kept as-is).
fn urlencode(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for b in v.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

#[allow(clippy::too_many_lines)] // one big page builder; clearer kept together
async fn repo_page(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, repo)): Path<(String, String)>,
    Query(q): Query<PageQuery>,
) -> Result<Html<String>, StatusCode> {
    // Paginate the (potentially long) packages & versions list, with optional
    // name search + state filter.
    const PER_PAGE: i64 = 50;
    // Approval-queue display caps (Approvals tab).
    const AP_CAP: i64 = 300; // versions fetched per state for the queue
    const AP_ROWS: usize = 4; // pending rows shown per package group
    const AP_CARDS: usize = 8; // cooldown / held cards before "+ N more"
    let summary = lookup(&s, &user, &org, &repo).await?;
    let name_q = q.q.as_deref().map(str::trim).filter(|x| !x.is_empty());
    let state_q = q
        .state
        .as_deref()
        .filter(|x| matches!(*x, "held" | "yanked" | "approved" | "pending"));
    // When the user is searching/filtering packages, open on the Packages tab.
    let filtering = name_q.is_some() || state_q.is_some() || q.page.is_some();
    let total_versions = s
        .catalog
        .count_package_versions(summary.id, name_q, state_q)
        .await
        .map_err(e500)?;
    let last_page = ((total_versions + PER_PAGE - 1) / PER_PAGE).max(1);
    let page = q.page.unwrap_or(1).clamp(1, last_page);
    let versions = s
        .catalog
        .admin_package_versions(summary.id, PER_PAGE, (page - 1) * PER_PAGE, name_q, state_q)
        .await
        .map_err(e500)?;
    let tokens = s.catalog.list_tokens(summary.id).await.map_err(e500)?;
    let licenses = s.catalog.list_licenses(summary.id).await.map_err(e500)?;
    let editions = s.catalog.list_editions(summary.id).await.map_err(e500)?;
    let grants = s.catalog.list_grants(summary.id).await.map_err(e500)?;
    let grant_rules = s.catalog.list_grant_rules(summary.id).await.map_err(e500)?;
    let org_sets = s
        .catalog
        .list_package_sets(summary.org_id)
        .await
        .map_err(e500)?;
    let upstreams = s.catalog.list_upstreams(summary.id).await.map_err(e500)?;
    let ci_policies = s.catalog.ci_policies(summary.id).await.map_err(e500)?;
    let packages = s.catalog.list_packages(summary.id).await.map_err(e500)?;
    let dep_plan = s
        .catalog
        .list_dependency_plan(summary.id)
        .await
        .map_err(e500)?;
    let title = format!("{org}/{repo}");

    // ---- Packages tab: version rows ----
    let version_rows: Vec<views::RepoVerRow> = versions
        .iter()
        .map(|v| {
            let (tone, label) = if v.yanked {
                ("held", "yanked".to_owned())
            } else if v.held {
                ("held", "held".to_owned())
            } else if v.approved {
                ("ok", "approved".to_owned())
            } else {
                match summary.update_mode.as_str() {
                    "manual" => ("amber", "pending approval".to_owned()),
                    "delayed" => match v.cooldown_days_left {
                        None => ("amber", "pending".to_owned()),
                        Some(0) => ("ok", "live".to_owned()),
                        Some(n) => ("blue", format!("cooldown · {n}d left")),
                    },
                    _ => ("ok", "live".to_owned()),
                }
            };
            views::RepoVerRow {
                package: v.package.clone(),
                version: v.version.clone(),
                normalized: v.normalized_version.clone(),
                stability: v.stability.clone(),
                badge_tone: tone,
                badge_label: label,
                released: v.released_at.clone().unwrap_or_default(),
                held: v.held,
                yanked: v.yanked,
            }
        })
        .collect();

    // ---- Overview: recent versions (top 4) ----
    let recent: Vec<views::RecentVer> = versions
        .iter()
        .take(4)
        .map(|v| {
            let (tone, label) = if v.yanked {
                ("held", "yanked".to_owned())
            } else if v.held {
                ("held", "held".to_owned())
            } else if v.approved {
                ("ok", "approved".to_owned())
            } else {
                match summary.update_mode.as_str() {
                    "manual" => ("amber", "pending".to_owned()),
                    "delayed" => match v.cooldown_days_left {
                        None => ("amber", "pending".to_owned()),
                        Some(0) => ("ok", "live".to_owned()),
                        Some(n) => ("blue", format!("cooldown · {n}d")),
                    },
                    _ => ("ok", "live".to_owned()),
                }
            };
            views::RecentVer {
                package: v.package.clone(),
                version: v.version.clone(),
                badge_tone: tone,
                badge_label: label,
            }
        })
        .collect();

    // ---- Approvals: package-health rows (broken / archived / stale) ----
    let broken_count = packages
        .iter()
        .filter(|p| p.sync_health == "broken" && !p.archived)
        .count();
    let is_stale = |p: &sconce_catalog::PackageStatus| {
        p.sync_health == "ok" && !p.archived && p.upstream_error.is_some()
    };
    let health: Vec<views::HealthRow> = packages
        .iter()
        .filter(|p| p.archived || p.sync_health == "broken" || is_stale(p))
        .map(|p| {
            let (tone, label, reason, action_value, action_label): (
                &'static str,
                &'static str,
                Option<String>,
                Option<&'static str>,
                &'static str,
            ) = if p.archived {
                (
                    "slate",
                    "archived · frozen",
                    None,
                    Some("unarchive"),
                    "Un-archive",
                )
            } else if p.sync_health == "broken" {
                (
                    "amber",
                    "broken",
                    Some(p.broken_reason.as_deref().unwrap_or("?").to_owned()),
                    Some("archive"),
                    "Archive",
                )
            } else {
                let err: String = p
                    .upstream_error
                    .as_deref()
                    .unwrap_or("")
                    .chars()
                    .take(60)
                    .collect();
                (
                    "blue",
                    "sync stale",
                    Some(format!("retrying — {}", err.trim())),
                    None,
                    "",
                )
            };
            views::HealthRow {
                pkg: p.name.clone(),
                badge_tone: tone,
                badge_label: label,
                reason,
                last: p
                    .last_success_at
                    .clone()
                    .unwrap_or_else(|| "never".to_owned()),
                action_value,
                action_label,
            }
        })
        .collect();

    // ---- Approvals: the approval queue (pending groups, cooldown, held) ----
    let pending_versions = s
        .catalog
        .admin_package_versions(summary.id, AP_CAP + 1, 0, None, Some("pending"))
        .await
        .map_err(e500)?;
    let held_versions = s
        .catalog
        .admin_package_versions(summary.id, AP_CAP + 1, 0, None, Some("held"))
        .await
        .map_err(e500)?;
    let cap = usize::try_from(AP_CAP).unwrap_or(usize::MAX);
    let ap_capped = pending_versions.len() > cap || held_versions.len() > cap;

    // Short dist sha → "a3f9c1b…e7d2"; release timestamp → its date.
    let short_sha = |h: &Option<String>| match h {
        Some(x) if x.len() > 12 => format!("{}…{}", &x[..7], &x[x.len() - 4..]),
        Some(x) => x.clone(),
        None => "—".to_owned(),
    };
    let rel_date = |r: &Option<String>| {
        r.as_deref()
            .map_or_else(|| "—".to_owned(), |t| t.get(..10).unwrap_or(t).to_owned())
    };

    // In a delayed repo an un-decided version with days left is "cooling"
    // (auto-exposes later); everywhere else an un-decided version is "pending".
    let delayed = summary.update_mode == "delayed";
    let is_cooling = |v: &sconce_catalog::AdminVersion| {
        delayed && matches!(v.cooldown_days_left, Some(n) if n > 0)
    };

    // Cooldown cards: a countdown + progress bar per still-cooling version.
    let ap_cooldown = pending_versions.iter().filter(|v| is_cooling(v)).count();
    let ap_cooldowns: Vec<views::CooldownCard> = pending_versions
        .iter()
        .filter(|v| is_cooling(v))
        .take(AP_CARDS)
        .map(|v| {
            let left = v.cooldown_days_left.unwrap_or(0);
            let total = i64::from(summary.cooldown_days.max(1));
            views::CooldownCard {
                package: v.package.clone(),
                version: v.version.clone(),
                normalized: v.normalized_version.clone(),
                days_left: left,
                days_ago: (total - left).max(0),
                days_total: total,
                pct: (((total - left).max(0) * 100) / total).clamp(0, 100),
            }
        })
        .collect();

    // "via {upstream} · {visibility}" provenance for a group header.
    let upstream_name = |id: Uuid| {
        upstreams.iter().find(|u| u.id == id).map(|u| {
            u.label.clone().unwrap_or_else(|| {
                u.base
                    .trim_start_matches("https://")
                    .trim_start_matches("http://")
                    .to_owned()
            })
        })
    };
    let group_via = |pkg: &str| {
        packages
            .iter()
            .find(|p| p.name == pkg)
            .map_or_else(String::new, |p| {
                p.upstream_id.and_then(upstream_name).map_or_else(
                    || p.visibility.clone(),
                    |up| format!("via {up} · {}", p.visibility),
                )
            })
    };

    // Pending versions (awaiting approval) grouped by package. They arrive
    // ordered by (package, version), so consecutive runs share a package. Every
    // row is rendered; the template collapses rows past the first few behind an
    // inline "Show all N".
    let mut ap_groups: Vec<views::ApprovalGroup> = Vec::new();
    for v in pending_versions.iter().filter(|v| !is_cooling(v)) {
        let row = views::ApprovalVer {
            package: v.package.clone(),
            normalized: v.normalized_version.clone(),
            version: v.version.clone(),
            stability: v.stability.clone(),
            stab_tone: if v.stability == "stable" {
                "ok"
            } else {
                "slate"
            },
            age: rel_date(&v.released_at),
            sha: short_sha(&v.dist_shasum),
        };
        match ap_groups.last_mut() {
            Some(g) if g.package == v.package => {
                g.count += 1;
                if g.rows.len() >= AP_ROWS {
                    g.more += 1;
                }
                g.rows.push(row);
            }
            _ => ap_groups.push(views::ApprovalGroup {
                package: v.package.clone(),
                count: 1,
                rows: vec![row],
                more: 0,
                expanded: false,
                via: group_via(&v.package),
            }),
        }
    }
    // Largest batch first and expanded by default (the design's open group).
    ap_groups.sort_by(|a, b| b.count.cmp(&a.count).then(a.package.cmp(&b.package)));
    if let Some(g) = ap_groups.first_mut() {
        g.expanded = true;
    }
    let ap_pending: usize = ap_groups.iter().map(|g| g.count).sum();

    // Held cards.
    let ap_helds: Vec<views::HeldCard> = held_versions
        .iter()
        .take(AP_CARDS)
        .map(|v| views::HeldCard {
            package: v.package.clone(),
            version: v.version.clone(),
            normalized: v.normalized_version.clone(),
            released: rel_date(&v.released_at),
        })
        .collect();
    let ap_held = held_versions.len();
    let ap_total = ap_pending + ap_cooldown + ap_held;

    // "synced 2m ago" pill — the freshest upstream sync, if any.
    let ap_synced = upstreams
        .iter()
        .filter_map(|u| u.last_sync_age)
        .min()
        .map_or_else(String::new, ago);
    // "N upstreams synced" banner: upstreams whose last sync completed within
    // the past hour (only worth announcing while there's something to review).
    let ap_fresh_ups = upstreams
        .iter()
        .filter(|u| matches!(u.last_sync_age, Some(a) if a < 3600))
        .count();

    // ---- Policy: grants + autogrant rules ----
    let grant_rows: Vec<views::GrantRow> = grants
        .iter()
        .map(|g| views::GrantRow {
            package: g.package.clone(),
            source_org: g.source_org.clone(),
            source_repo: g.source_repo.clone(),
            mode: g.policy.update_mode.clone().unwrap_or_default(),
            cooldown: g
                .policy
                .cooldown_days
                .map_or_else(String::new, |d| d.to_string()),
        })
        .collect();
    let mut autogrant_rules = Vec::with_capacity(grant_rules.len());
    for (rid, set_id, set_name) in &grant_rules {
        let count = s.catalog.resolve_set(*set_id).await.map_err(e500)?.len();
        autogrant_rules.push(views::AutograntRow {
            rid: rid.to_string(),
            set_name: set_name.clone(),
            count,
        });
    }
    let set_opt = |st: &sconce_catalog::PackageSet| views::SetOpt {
        id: st.id.to_string(),
        name: st.name.clone(),
    };
    let set_opts: Vec<views::SetOpt> = org_sets.iter().map(set_opt).collect();
    let org_set_opts: Vec<views::SetOpt> = org_sets.iter().map(set_opt).collect();

    // ---- Upstreams ----
    let git_count = upstreams.iter().filter(|u| u.kind == "git").count();
    let composer_count = upstreams.iter().filter(|u| u.kind == "composer").count();
    let failing_count = upstreams
        .iter()
        .filter(|u| u.job_status.as_deref() == Some("failed"))
        .count();
    let up_total = upstreams.len();
    let upstream_rows: Vec<views::UpstreamRow> = upstreams
        .iter()
        .map(|u| {
            let failed = u.job_status.as_deref() == Some("failed");
            let running = matches!(u.job_status.as_deref(), Some("running" | "pending"));
            // Only ready / other states show the relative age (matches serving).
            let (last_tone, last_label, show_when): (&'static str, String, bool) =
                match u.job_status.as_deref() {
                    None => ("slate", "never synced".to_owned(), false),
                    Some("failed") => ("held", "failed".to_owned(), false),
                    Some("running" | "pending") => ("blue", "running".to_owned(), false),
                    Some("ready") => ("ok", "ready".to_owned(), true),
                    Some(other) => ("slate", other.to_owned(), true),
                };
            let when = if show_when {
                u.last_sync_age.map_or(String::new(), ago)
            } else {
                String::new()
            };
            views::UpstreamRow {
                kind: u.kind.clone(),
                is_composer: u.kind == "composer",
                base: u.base.clone(),
                requires: u
                    .requires
                    .iter()
                    .map(sconce_catalog::UpstreamRequire::to_spec)
                    .collect(),
                source_paths: u.source_paths.clone(),
                error: failed.then(|| {
                    u.job_error
                        .clone()
                        .unwrap_or_else(|| "sync failed".to_owned())
                }),
                public: u.visibility == "public",
                has_credential: u.has_credential,
                credential_type: u.credential_type.clone(),
                last_tone,
                last_label,
                when,
                running,
                failed,
                id: u.id.to_string(),
                text: u.base.to_lowercase(),
            }
        })
        .collect();

    // ---- Dependencies ----
    let deps: Vec<views::DepRow> = dep_plan
        .iter()
        .map(|d| {
            let (status_kind, status_other) = match d.status.as_str() {
                "missing" => ("missing", String::new()),
                "present" => ("present", String::new()),
                other => ("other", other.to_owned()),
            };
            views::DepRow {
                status_kind,
                status_other,
                name: d.name.clone(),
                required_by: d.required_by.clone().unwrap_or_default(),
                resolvable: d.status.starts_with("resolvable"),
            }
        })
        .collect();

    // ---- Tokens + licenses ----
    let license_rows: Vec<views::LicenseRow> = licenses
        .iter()
        .map(|l| views::LicenseRow {
            buyer: l.buyer.clone().unwrap_or_else(|| "—".to_owned()),
            status: l.status.clone(),
            packages: l.packages.join(", "),
            id: l.id.to_string(),
            sets: l
                .sets
                .iter()
                .map(|(sid, sname)| views::LicSet {
                    set_id: sid.to_string(),
                    name: sname.clone(),
                })
                .collect(),
            mode: l.policy.update_mode.clone().unwrap_or_default(),
            cooldown: l
                .policy
                .cooldown_days
                .map_or_else(String::new, |d| d.to_string()),
            until: l.bound.until.clone().unwrap_or_default(),
            major: l.bound.major.map_or_else(String::new, |m| m.to_string()),
        })
        .collect();
    let edition_rows: Vec<views::EditionRow> = editions
        .iter()
        .map(|e| views::EditionRow {
            id: e.id.to_string(),
            name: e.name.clone(),
            slug: e.slug.clone().unwrap_or_default(),
            set_name: e.set_name.clone(),
            bound: e.bound.label(),
            snapshot: e.snapshot,
            active: e.active,
        })
        .collect();
    // Only active editions are offered in the issue picker.
    let edition_opts: Vec<views::EditionOpt> = editions
        .iter()
        .filter(|e| e.active)
        .map(|e| views::EditionOpt {
            id: e.id.to_string(),
            label: format!("{} — {}", e.name, e.bound.label()),
        })
        .collect();
    let token_rows: Vec<views::TokenRow> = tokens
        .iter()
        .map(|t| views::TokenRow {
            label: t.label.clone(),
            origin: t.origin.clone(),
            origin_tone: match t.origin.as_str() {
                "ci" => "violet",
                "session" => "blue",
                _ => "slate",
            },
            created: t.created.clone(),
            last: t.last_used.clone().unwrap_or_else(|| "never".to_owned()),
            expired: t.expired,
            expires: t.expires.clone(),
            mode: t.policy.update_mode.clone().unwrap_or_default(),
            cooldown: t
                .policy
                .cooldown_days
                .map_or_else(String::new, |d| d.to_string()),
            id: t.id.to_string(),
        })
        .collect();

    // ---- CI ----
    let ci: Vec<views::CiRow> = ci_policies
        .iter()
        .map(|p| {
            let claims = p.claims.as_object().map_or_else(String::new, |m| {
                m.iter()
                    .map(|(k, v)| format!("{k}={}", v.as_str().unwrap_or("")))
                    .collect::<Vec<_>>()
                    .join(", ")
            });
            views::CiRow {
                provider: p.provider.clone(),
                issuer: p.issuer.clone(),
                audience: p.audience.clone(),
                claims,
                ttl: p.token_ttl_secs,
                id: p.id.to_string(),
            }
        })
        .collect();

    // ---- header / overview scalars ----
    let repo_cfg = s.catalog.repo_settings(summary.id).await.map_err(e500)?;
    let pending_count = s
        .catalog
        .count_package_versions(summary.id, None, Some("pending"))
        .await
        .map_err(e500)?;
    let held_count = s
        .catalog
        .count_package_versions(summary.id, None, Some("held"))
        .await
        .map_err(e500)?;
    let has_status = |st: &str| {
        upstreams
            .iter()
            .any(|u| u.job_status.as_deref() == Some(st))
    };
    let (sync_tone, sync_label) = if upstreams.is_empty() {
        ("slate", "no upstreams")
    } else if has_status("failed") {
        ("held", "sync failing")
    } else if has_status("running") || has_status("pending") {
        ("blue", "syncing")
    } else {
        ("ok", "synced")
    };
    let policy_phrase = match summary.update_mode.as_str() {
        "delayed" => format!(
            "delayed updates with a {}-day cooldown",
            summary.cooldown_days
        ),
        "manual" => "manual approval required".to_owned(),
        _ => "automatic updates".to_owned(),
    };
    let base = s.public_base_url.trim_end_matches('/').to_owned();
    let host = base
        .split_once("://")
        .map_or(base.as_str(), |(_, r)| r)
        .split('/')
        .next()
        .unwrap_or(&base)
        .to_owned();
    let example_pkg = packages
        .first()
        .map_or_else(|| "<package>".to_owned(), |p| p.name.clone());
    let q_enc = name_q.map_or(String::new(), urlencode);
    let pager = if total_versions == 0 {
        None
    } else {
        let mut extra = String::new();
        if let Some(n) = name_q {
            let _ = write!(extra, "q={}", urlencode(n));
        }
        if let Some(st) = state_q {
            if !extra.is_empty() {
                extra.push('&');
            }
            let _ = write!(extra, "state={st}");
        }
        Some(views::Pager {
            from: (page - 1) * PER_PAGE + 1,
            to: (page * PER_PAGE).min(total_versions),
            total: total_versions,
            page,
            last_page,
            base: format!("/r/{org}/{repo}"),
            extra,
        })
    };

    let view = views::RepoPage {
        org: org.clone(),
        repo: repo.clone(),
        private_packages: repo_cfg.allow_private_packages,
        sync_tone,
        sync_label,
        pkg_count: packages.len(),
        total_versions,
        policy_phrase,
        broken_count,
        read_only: !user.can_admin(summary.org_id),
        filtering,
        approvals_count: pending_count + held_count,
        base,
        host,
        example_pkg,
        pending_count,
        held_count,
        recent,
        search_q: name_q.unwrap_or("").to_owned(),
        q_enc,
        state: state_q.unwrap_or("").to_owned(),
        filtered: name_q.is_some() || state_q.is_some(),
        versions: version_rows,
        pager,
        ap_total,
        ap_pending,
        ap_fresh_ups,
        ap_cooldown,
        ap_held,
        ap_synced,
        ap_capped,
        ap_groups,
        ap_cooldowns,
        ap_helds,
        health,
        update_mode: summary.update_mode.clone(),
        cooldown_days: summary.cooldown_days,
        grants: grant_rows,
        org_sets_empty: org_sets.is_empty(),
        autogrant_rules,
        set_opts,
        upstreams: upstream_rows,
        up_total,
        git_count,
        composer_count,
        failing_count,
        has_secret_key: s.secret_key.is_some(),
        deps,
        licenses: license_rows,
        org_set_opts,
        editions: edition_rows,
        edition_opts,
        tokens: token_rows,
        ci,
    };
    Ok(shell_js(
        &s,
        &user,
        &title,
        &view.render().map_err(e500)?,
        "/assets/repo.js",
    ))
}

// ----- repo actions (access already enforced by `lookup`) -----

#[derive(Deserialize)]
struct PolicyForm {
    mode: String,
    cooldown_days: i32,
}

async fn set_policy(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, repo)): Path<(String, String)>,
    Form(f): Form<PolicyForm>,
) -> Result<Redirect, StatusCode> {
    let id = lookup(&s, &user, &org, &repo).await?.id;
    s.catalog
        .set_update_policy(id, &f.mode, f.cooldown_days)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(Redirect::to(&format!("/r/{org}/{repo}")))
}

#[derive(Deserialize)]
struct VersionForm {
    package: String,
    normalized: String,
    action: String,
}

async fn version_action(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, repo)): Path<(String, String)>,
    Form(f): Form<VersionForm>,
) -> Result<Redirect, StatusCode> {
    let id = lookup(&s, &user, &org, &repo).await?.id;
    match f.action.as_str() {
        "hold" => s.catalog.hold_version(id, &f.package, &f.normalized).await,
        "unhold" => {
            s.catalog
                .unhold_version(id, &f.package, &f.normalized)
                .await
        }
        "approve" => {
            s.catalog
                .approve_version(id, &f.package, &f.normalized)
                .await
        }
        "yank" => s.catalog.yank_version(id, &f.package, &f.normalized).await,
        "unyank" => {
            s.catalog
                .unyank_version(id, &f.package, &f.normalized)
                .await
        }
        _ => return Err(StatusCode::BAD_REQUEST),
    }
    .map_err(e500)?;
    Ok(Redirect::to(&format!("/r/{org}/{repo}")))
}

#[derive(Deserialize)]
struct ApproveBulkForm {
    /// Whole-package "Approve all N" (the group header / footer forms).
    package: Option<String>,
    /// Newline-separated `package|normalized` pairs from the selection bar.
    /// Present-but-empty means "selection bar, nothing ticked" → a no-op, which
    /// is why it's distinguished from the absent ("approve everything") case.
    versions: Option<String>,
}

/// Approvals tab bulk action: approve a hand-picked selection, a whole package,
/// or every still-pending version in the repo.
async fn approve_bulk(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, repo)): Path<(String, String)>,
    Form(f): Form<ApproveBulkForm>,
) -> Result<Redirect, StatusCode> {
    let id = lookup(&s, &user, &org, &repo).await?.id;
    if let Some(list) = f.versions.as_deref() {
        // Selection bar: approve exactly the ticked versions (skip empties).
        for line in list.lines() {
            if let Some((pkg, norm)) = line.split_once('|') {
                let (pkg, norm) = (pkg.trim(), norm.trim());
                if !pkg.is_empty() && !norm.is_empty() {
                    s.catalog
                        .approve_version(id, pkg, norm)
                        .await
                        .map_err(e500)?;
                }
            }
        }
    } else {
        // No `versions` field → a whole-package or repo-wide "Approve all".
        let pkg = f.package.as_deref().filter(|x| !x.is_empty());
        s.catalog.approve_all_pending(id, pkg).await.map_err(e500)?;
    }
    Ok(Redirect::to(&format!("/r/{org}/{repo}")))
}

/// Bulk-hold the ticked versions from the Approvals selection bar. Only an
/// explicit selection is accepted — there is deliberately no repo-wide
/// "hold everything".
async fn hold_bulk(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, repo)): Path<(String, String)>,
    Form(f): Form<ApproveBulkForm>,
) -> Result<Redirect, StatusCode> {
    let id = lookup(&s, &user, &org, &repo).await?.id;
    if let Some(list) = f.versions.as_deref() {
        for line in list.lines() {
            if let Some((pkg, norm)) = line.split_once('|') {
                let (pkg, norm) = (pkg.trim(), norm.trim());
                if !pkg.is_empty() && !norm.is_empty() {
                    s.catalog.hold_version(id, pkg, norm).await.map_err(e500)?;
                }
            }
        }
    }
    Ok(Redirect::to(&format!("/r/{org}/{repo}")))
}

#[derive(Deserialize)]
struct PackageActionForm {
    package: String,
    action: String,
}

/// D11 — per-package detail: lifecycle header + version provenance + actions.
#[allow(clippy::too_many_lines)] // page builder; clearer kept together
async fn package_detail_page(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, repo, pkg)): Path<(String, String, String)>,
) -> Result<Html<String>, StatusCode> {
    let summary = lookup(&s, &user, &org, &repo).await?;
    let packages = s.catalog.list_packages(summary.id).await.map_err(e500)?;
    let Some(ps) = packages.iter().find(|p| p.name == pkg) else {
        return Ok(status_page(
            "Package not found",
            "No such package in this repository.",
        ));
    };
    let versions = s
        .catalog
        .admin_package_versions(summary.id, 500, 0, Some(&pkg), None)
        .await
        .map_err(e500)?;

    // Lifecycle header badge + optional archive action.
    let stale = ps.sync_health == "ok" && !ps.archived && ps.upstream_error.is_some();
    let (life_tone, life_label, life_reason, action_value, action_label) = if ps.archived {
        (
            "slate",
            "archived · frozen",
            None,
            Some("unarchive"),
            "Un-archive",
        )
    } else if ps.sync_health == "broken" {
        (
            "amber",
            "broken",
            Some(ps.broken_reason.as_deref().unwrap_or("?").to_owned()),
            Some("archive"),
            "Archive",
        )
    } else if stale {
        (
            "blue",
            "sync stale · retrying",
            None,
            Some("archive"),
            "Archive",
        )
    } else {
        ("ok", "healthy", None, None, "")
    };

    let rows: Vec<views::VersionRow> = versions
        .iter()
        .map(|v| {
            let (tone, label) = if v.yanked {
                ("held", "yanked".to_owned())
            } else if v.held {
                ("held", "held".to_owned())
            } else if v.approved {
                ("ok", "approved".to_owned())
            } else {
                match summary.update_mode.as_str() {
                    "manual" => ("amber", "pending".to_owned()),
                    "delayed" => match v.cooldown_days_left {
                        None | Some(0) => ("ok", "live".to_owned()),
                        Some(n) => ("blue", format!("cooldown · {n}d")),
                    },
                    _ => ("ok", "live".to_owned()),
                }
            };
            views::VersionRow {
                version: v.version.clone(),
                badge_tone: tone,
                badge_label: label,
                released: v.released_at.clone().unwrap_or_default(),
                sha: v.dist_shasum.clone().unwrap_or_else(|| "—".to_owned()),
                src: v.source_reference.clone().unwrap_or_else(|| "—".to_owned()),
                normalized: v.normalized_version.clone(),
                held: v.held,
                yanked: v.yanked,
            }
        })
        .collect();

    let view = views::PackageDetail {
        org: org.clone(),
        repo: repo.clone(),
        pkg: pkg.clone(),
        life_tone,
        life_label,
        life_reason,
        action_value,
        action_label,
        visibility: ps.visibility.clone(),
        nver: versions.len(),
        last: ps
            .last_success_at
            .clone()
            .unwrap_or_else(|| "never".to_owned()),
        sync_error: ps.upstream_error.clone().filter(|_| stale),
        versions: rows,
    };
    Ok(shell(&s, &user, &pkg, &view.render().map_err(e500)?))
}

async fn package_archive(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, repo)): Path<(String, String)>,
    Form(f): Form<PackageActionForm>,
) -> Result<Redirect, StatusCode> {
    let id = lookup_admin(&s, &user, &org, &repo).await?.id;
    match f.action.as_str() {
        "archive" => s.catalog.archive_package(id, &f.package).await,
        "unarchive" => s.catalog.unarchive_package(id, &f.package).await,
        _ => return Err(StatusCode::BAD_REQUEST),
    }
    .map_err(e500)?;
    Ok(Redirect::to(&format!("/r/{org}/{repo}")))
}

/// Parse `k=v, k2=v2` into a JSON object of claim matchers.
fn parse_claims(raw: &str) -> Value {
    let mut m = serde_json::Map::new();
    for pair in raw.split(',') {
        if let Some((k, v)) = pair.split_once('=') {
            let k = k.trim();
            if !k.is_empty() {
                m.insert(k.to_owned(), Value::String(v.trim().to_owned()));
            }
        }
    }
    Value::Object(m)
}

#[derive(Deserialize)]
struct CiForm {
    provider: String,
    issuer: String,
    audience: String,
    claims: Option<String>,
    ttl: Option<String>,
}

async fn add_ci(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, repo)): Path<(String, String)>,
    Form(f): Form<CiForm>,
) -> Result<Redirect, StatusCode> {
    let id = lookup_admin(&s, &user, &org, &repo).await?.id;
    if !matches!(f.provider.as_str(), "github" | "gitlab") {
        return Err(StatusCode::BAD_REQUEST);
    }
    let ttl = match f.ttl.as_deref().map(str::trim).filter(|x| !x.is_empty()) {
        Some(t) => t
            .parse::<i64>()
            .map_err(|_| StatusCode::BAD_REQUEST)?
            .max(60),
        None => 900,
    };
    let claims = parse_claims(f.claims.as_deref().unwrap_or(""));
    s.catalog
        .add_ci_policy(
            id,
            &f.provider,
            f.issuer.trim(),
            f.audience.trim(),
            &claims,
            ttl,
        )
        .await
        .map_err(e500)?;
    Ok(Redirect::to(&format!("/r/{org}/{repo}#tab-ci")))
}

#[derive(Deserialize)]
struct CiRemoveForm {
    id: String,
}

async fn remove_ci(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, repo)): Path<(String, String)>,
    Form(f): Form<CiRemoveForm>,
) -> Result<Redirect, StatusCode> {
    let repo_id = lookup_admin(&s, &user, &org, &repo).await?.id;
    let id =
        f.id.parse::<uuid::Uuid>()
            .map_err(|_| StatusCode::BAD_REQUEST)?;
    s.catalog
        .delete_ci_policy(repo_id, id)
        .await
        .map_err(e500)?;
    Ok(Redirect::to(&format!("/r/{org}/{repo}#tab-ci")))
}

#[derive(Deserialize)]
struct GrantForm {
    package: String,
    from: String,
}

#[derive(Deserialize)]
struct GrantPolicyForm {
    package: String,
    mode: String,
    cooldown_days: Option<String>,
}

#[derive(Deserialize)]
struct AutograntForm {
    set_id: String,
}

async fn add_autogrant(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, repo)): Path<(String, String)>,
    Form(f): Form<AutograntForm>,
) -> Result<Redirect, StatusCode> {
    let summary = lookup_admin(&s, &user, &org, &repo).await?;
    let set_id = f
        .set_id
        .parse::<uuid::Uuid>()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    // The set must belong to this repo's org.
    match s.catalog.package_set(set_id).await.map_err(e500)? {
        Some((_, set_org)) if set_org == summary.org_id => {
            s.catalog
                .add_grant_rule(summary.id, set_id)
                .await
                .map_err(|e| ent_status(&e))?;
            Ok(Redirect::to(&format!("/r/{org}/{repo}")))
        }
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

async fn remove_autogrant(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, repo)): Path<(String, String)>,
    Form(f): Form<IdForm>,
) -> Result<Redirect, StatusCode> {
    let summary = lookup_admin(&s, &user, &org, &repo).await?;
    let rule_id =
        f.id.parse::<uuid::Uuid>()
            .map_err(|_| StatusCode::BAD_REQUEST)?;
    s.catalog
        .remove_grant_rule(summary.id, rule_id)
        .await
        .map_err(e500)?;
    Ok(Redirect::to(&format!("/r/{org}/{repo}")))
}

async fn set_grant_policy_action(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, repo)): Path<(String, String)>,
    Form(f): Form<GrantPolicyForm>,
) -> Result<Redirect, StatusCode> {
    let repo_id = lookup_admin(&s, &user, &org, &repo).await?.id;
    let update_mode = match f.mode.as_str() {
        "auto" | "manual" | "delayed" => Some(f.mode.clone()),
        "" => None,
        _ => return Err(StatusCode::BAD_REQUEST),
    };
    let cooldown_days = match f.cooldown_days.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(d) => Some(d.parse::<i32>().map_err(|_| StatusCode::BAD_REQUEST)?),
    };
    let policy = sconce_catalog::PolicyOverride {
        update_mode,
        cooldown_days,
    };
    s.catalog
        .set_grant_policy(repo_id, f.package.trim(), &policy)
        .await
        .map_err(e500)?;
    Ok(Redirect::to(&format!("/r/{org}/{repo}")))
}

async fn create_grant(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, repo)): Path<(String, String)>,
    Form(f): Form<GrantForm>,
) -> Result<Redirect, StatusCode> {
    let target = lookup_admin(&s, &user, &org, &repo).await?.id;
    let (src_org, src_repo) = f.from.split_once('/').ok_or(StatusCode::BAD_REQUEST)?;
    let source = lookup(&s, &user, src_org, src_repo).await?.id;
    s.catalog
        .grant_package(target, source, &f.package)
        .await
        .map_err(e500)?;
    Ok(Redirect::to(&format!("/r/{org}/{repo}")))
}

#[derive(Deserialize)]
struct UpstreamForm {
    kind: String,
    visibility: String,
    base: String,
    label: Option<String>,
    credential: Option<String>,
    /// For `basic` auth the username is entered separately (two boxes) and folded
    /// into the stored `user:token` credential here.
    cred_user: Option<String>,
    credential_type: Option<String>,
    /// Mirror subscription: one entry per line (`vendor/*@2.4`, `re:^x/`, `*`, …).
    /// Required for a composer upstream.
    requires: Option<String>,
    /// git-only: monorepo subpaths to mirror, one per line (empty = repo root).
    source_paths: Option<String>,
}

#[allow(clippy::too_many_lines)]
async fn create_upstream(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, repo)): Path<(String, String)>,
    Form(f): Form<UpstreamForm>,
) -> Result<Response, StatusCode> {
    let repo_id = lookup_admin(&s, &user, &org, &repo).await?.id;
    let visibility =
        sconce_catalog::Visibility::parse(&f.visibility).ok_or(StatusCode::BAD_REQUEST)?;
    if f.kind != "git" && f.kind != "composer" {
        return Err(StatusCode::BAD_REQUEST);
    }
    let credential_type = f.credential_type.as_deref().unwrap_or("basic");
    if !matches!(credential_type, "basic" | "github" | "gitlab" | "bearer") {
        return Err(StatusCode::BAD_REQUEST);
    }
    // Parse the mirror subscription (one entry per line). A malformed entry or an
    // empty list for a composer upstream is refused.
    let mut requires = Vec::new();
    for line in f.requires.as_deref().unwrap_or("").lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match sconce_catalog::UpstreamRequire::parse(line) {
            Ok(r) => requires.push(r),
            Err(_) => return Err(StatusCode::BAD_REQUEST),
        }
    }
    // A composer upstream must be scoped — refuse to register one that would
    // mirror the whole registry on sync (an explicit `*` entry opts into all).
    if f.kind == "composer" && requires.is_empty() {
        let body = views::UpstreamNotice {
            reason: "filter",
            org: org.clone(),
            repo: repo.clone(),
        }
        .render()
        .map_err(e500)?;
        return Ok(shell(&s, &user, "Upstream not added", &body).into_response());
    }
    let label = f.label.as_deref().map(str::trim).filter(|l| !l.is_empty());
    // For basic auth the username comes from a separate box; fold it into the
    // stored `user:token` form (unless the token already contains a `user:`).
    let token = f
        .credential
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty());
    let cred_user = f
        .cred_user
        .as_deref()
        .map(str::trim)
        .filter(|u| !u.is_empty());
    let combined = match (credential_type, cred_user, token) {
        ("basic", Some(user), Some(tok)) if !tok.contains(':') => Some(format!("{user}:{tok}")),
        _ => token.map(str::to_owned),
    };
    // Public upstreams carry no credential — ignore any submitted one (so no key
    // is needed for a public upstream even if the field leaked a value).
    let credential = if matches!(visibility, sconce_catalog::Visibility::Public) {
        None
    } else {
        combined.as_deref()
    };

    // Encrypt the credential if one was given; needs the key.
    let ciphertext = if let Some(c) = credential {
        let Some(key) = &s.secret_key else {
            // No key configured — tell the user instead of silently dropping it.
            let body = views::UpstreamNotice {
                reason: "nokey",
                org: org.clone(),
                repo: repo.clone(),
            }
            .render()
            .map_err(e500)?;
            return Ok(shell(&s, &user, "Upstream not added", &body).into_response());
        };
        Some(key.encrypt(c.as_bytes()))
    } else {
        None
    };
    let id = s
        .catalog
        .create_upstream(
            repo_id,
            &f.kind,
            &f.base,
            visibility,
            label,
            ciphertext.as_deref(),
            credential_type,
        )
        .await
        .map_err(e500)?;
    // Store the mirror subscription (required above for a composer upstream).
    if !requires.is_empty() {
        s.catalog
            .set_upstream_requires(repo_id, id, &requires)
            .await
            .map_err(e500)?;
    }
    // Store any monorepo source-paths (git upstreams only).
    if f.kind == "git" {
        let paths: Vec<String> = f
            .source_paths
            .as_deref()
            .unwrap_or("")
            .lines()
            .map(|l| l.trim().to_owned())
            .filter(|l| !l.is_empty())
            .collect();
        if !paths.is_empty() {
            s.catalog
                .set_upstream_source_paths(repo_id, id, &paths)
                .await
                .map_err(e500)?;
        }
    }
    Ok(Redirect::to(&format!("/r/{org}/{repo}")).into_response())
}

async fn remove_upstream(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, repo)): Path<(String, String)>,
    Form(f): Form<RevokeTokenForm>,
) -> Result<Redirect, StatusCode> {
    let repo_id = lookup_admin(&s, &user, &org, &repo).await?.id;
    let id =
        f.id.parse::<uuid::Uuid>()
            .map_err(|_| StatusCode::BAD_REQUEST)?;
    s.catalog.delete_upstream(repo_id, id).await.map_err(e500)?;
    Ok(Redirect::to(&format!("/r/{org}/{repo}")))
}

/// Enqueue a mirror job for an upstream (the worker does the actual clone). This
/// is just an INSERT + NOTIFY — no CAS or secret key needed in the UI process.
async fn sync_upstream(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, repo)): Path<(String, String)>,
    Form(f): Form<RevokeTokenForm>,
) -> Result<Redirect, StatusCode> {
    // The upstream must belong to a repo the user can access.
    let repo_id = lookup_admin(&s, &user, &org, &repo).await?.id;
    let id =
        f.id.parse::<uuid::Uuid>()
            .map_err(|_| StatusCode::BAD_REQUEST)?;
    if !s
        .catalog
        .list_upstreams(repo_id)
        .await
        .map_err(e500)?
        .iter()
        .any(|u| u.id == id)
    {
        return Err(StatusCode::NOT_FOUND);
    }
    s.catalog.enqueue_mirror_job(id).await.map_err(e500)?;
    Ok(Redirect::to(&format!("/r/{org}/{repo}")))
}

/// Enqueue a mirror job for every upstream in the repo (the toolbar "Sync all").
async fn sync_all_upstreams(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, repo)): Path<(String, String)>,
) -> Result<Redirect, StatusCode> {
    let repo_id = lookup_admin(&s, &user, &org, &repo).await?.id;
    for u in s.catalog.list_upstreams(repo_id).await.map_err(e500)? {
        s.catalog.enqueue_mirror_job(u.id).await.map_err(e500)?;
    }
    Ok(Redirect::to(&format!("/r/{org}/{repo}")))
}

/// Enqueue a closure-resolution job (the worker computes the plan).
async fn resolve_deps(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, repo)): Path<(String, String)>,
) -> Result<Redirect, StatusCode> {
    let repo_id = lookup_admin(&s, &user, &org, &repo).await?.id;
    s.catalog
        .enqueue_resolve_closure_job(repo_id)
        .await
        .map_err(e500)?;
    Ok(Redirect::to(&format!("/r/{org}/{repo}")))
}

#[derive(Deserialize)]
struct AddDepForm {
    package: String,
}

/// Operator approves a planned dependency → enqueue mirroring it from its
/// resolver. Only resolvable plan entries can be added.
async fn add_dep(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, repo)): Path<(String, String)>,
    Form(f): Form<AddDepForm>,
) -> Result<Redirect, StatusCode> {
    let repo_id = lookup_admin(&s, &user, &org, &repo).await?.id;
    let entry = s
        .catalog
        .dependency_plan_entry(repo_id, &f.package)
        .await
        .map_err(e500)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let upstream = entry.resolver_upstream_id.ok_or(StatusCode::BAD_REQUEST)?;
    s.catalog
        .enqueue_mirror_package_job(upstream, &f.package)
        .await
        .map_err(e500)?;
    Ok(Redirect::to(&format!("/r/{org}/{repo}")))
}

#[derive(Deserialize)]
struct LicenseForm {
    buyer: Option<String>,
    packages: String,
}

async fn create_license(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, repo)): Path<(String, String)>,
    Form(f): Form<LicenseForm>,
) -> Result<Html<String>, StatusCode> {
    let repo_id = lookup_admin(&s, &user, &org, &repo).await?.id;
    let buyer = f.buyer.as_deref().filter(|b| !b.is_empty());
    let packages: Vec<&str> = f
        .packages
        .split([',', ' ', '\n', '\t'])
        .filter(|p| !p.is_empty())
        .collect();
    let key = s
        .catalog
        .issue_license(repo_id, buyer, &packages)
        .await
        .map_err(e500)?
        .ok_or(StatusCode::BAD_REQUEST)?;
    let view = views::LicenseCreated {
        packages: packages.join(", "),
        key,
        org: org.clone(),
        repo: repo.clone(),
    };
    Ok(shell(
        &s,
        &user,
        "License created",
        &view.render().map_err(e500)?,
    ))
}

/// Parse a required, non-empty integer form field with a minimum → `400` on
/// missing/blank/unparseable/too-small input.
fn form_int(v: Option<&str>, min: i32) -> Result<i32, StatusCode> {
    let raw = v
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let n: i32 = raw.parse().map_err(|_| StatusCode::BAD_REQUEST)?;
    if n < min {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(n)
}

#[derive(Deserialize)]
struct IssueEditionForm {
    edition_id: String,
    buyer: Option<String>,
}

/// Issue a license key against an edition — resolves the edition's bound,
/// entitlements, and policy onto the new key, then shows it once.
async fn issue_license_edition(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, repo)): Path<(String, String)>,
    Form(f): Form<IssueEditionForm>,
) -> Result<Html<String>, StatusCode> {
    let repo_id = lookup_admin(&s, &user, &org, &repo).await?.id;
    let edition_id = f
        .edition_id
        .parse::<Uuid>()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let buyer = f.buyer.as_deref().map(str::trim).filter(|b| !b.is_empty());
    let ed = s
        .catalog
        .edition(repo_id, edition_id)
        .await
        .map_err(e500)?
        .ok_or(StatusCode::BAD_REQUEST)?;
    let key = s
        .catalog
        .issue_from_edition(repo_id, edition_id, buyer, None)
        .await
        .map_err(e500)?
        .ok_or(StatusCode::BAD_REQUEST)?
        .key
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let view = views::LicenseCreated {
        packages: format!("edition “{}”", ed.name),
        key,
        org: org.clone(),
        repo: repo.clone(),
    };
    Ok(shell(
        &s,
        &user,
        "License created",
        &view.render().map_err(e500)?,
    ))
}

#[derive(Deserialize)]
struct EditionForm {
    name: String,
    slug: Option<String>,
    /// An existing org package set (by id), used when `package` is blank.
    set_id: Option<String>,
    /// A single package name — creates/reuses a singleton set (takes precedence).
    package: Option<String>,
    /// `perpetual` | `time` | `version`.
    bound_kind: String,
    period_months: Option<String>,
    major: Option<String>,
    /// Checkbox: present (`on`) = snapshot at issue.
    snapshot: Option<String>,
    /// Optional policy override stamped on issued keys (absent = inherit repo).
    mode: Option<String>,
    cooldown_days: Option<String>,
}

/// Create an edition. The target is a single package (singleton set) if given,
/// else an existing org set. Gated on `max_skus`.
#[allow(clippy::too_many_lines)]
async fn create_edition_action(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, repo)): Path<(String, String)>,
    Form(f): Form<EditionForm>,
) -> Result<Response, StatusCode> {
    let summary = lookup_admin(&s, &user, &org, &repo).await?;
    let name = f.name.trim();
    if name.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let slug = f.slug.as_deref().map(str::trim).filter(|x| !x.is_empty());
    let back = format!("/r/{org}/{repo}");

    // Resolve the target set: a single package (singleton set) takes precedence
    // over a chosen set. Exactly one path must produce a set.
    let set_id = if let Some(pkg) = f
        .package
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        match s
            .catalog
            .singleton_set(summary.org_id, pkg)
            .await
            .map_err(e500)?
        {
            sconce_catalog::SingletonSet::Set(id) => id,
            sconce_catalog::SingletonSet::UnknownPackage => {
                return Ok(error_card(
                    &s,
                    &user,
                    "Package not found",
                    "No package with that name in this organization.",
                    &back,
                ));
            }
            sconce_catalog::SingletonSet::NameCollision => {
                return Ok(error_card(
                    &s,
                    &user,
                    "Name already in use",
                    "A package set already has that exact name and holds more than this \
                     one package. Select it under \u{201c}Package set\u{201d} instead, or \
                     rename it.",
                    &back,
                ));
            }
        }
    } else if let Some(sid) = f.set_id.as_deref().map(str::trim).filter(|x| !x.is_empty()) {
        let sid = sid.parse::<Uuid>().map_err(|_| StatusCode::BAD_REQUEST)?;
        // The set must belong to this repo's org.
        match s.catalog.package_set(sid).await.map_err(e500)? {
            Some((_, set_org)) if set_org == summary.org_id => sid,
            _ => return Err(StatusCode::BAD_REQUEST),
        }
    } else {
        return Ok(error_card(
            &s,
            &user,
            "No target",
            "Pick a package set or enter a single package for the edition.",
            &back,
        ));
    };

    // Build the bound template from the chosen kind + its one relevant field
    // (months ≥ 1 for time; major ≥ 0 for version — v0.x is a valid cap).
    let bound = match f.bound_kind.as_str() {
        "time" => sconce_catalog::EditionBound::Time {
            period_months: form_int(f.period_months.as_deref(), 1)?,
        },
        "version" => sconce_catalog::EditionBound::Version {
            major: form_int(f.major.as_deref(), 0)?,
        },
        _ => sconce_catalog::EditionBound::Perpetual,
    };
    let snapshot = f.snapshot.is_some();
    let update_mode = match f.mode.as_deref() {
        Some(m @ ("auto" | "manual" | "delayed")) => Some(m.to_owned()),
        _ => None,
    };
    let cooldown_days = match f.cooldown_days.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(d) => {
            let n = d.parse::<i32>().map_err(|_| StatusCode::BAD_REQUEST)?;
            if n < 0 {
                return Err(StatusCode::BAD_REQUEST);
            }
            Some(n)
        }
    };
    let policy = sconce_catalog::PolicyOverride {
        update_mode,
        cooldown_days,
    };
    match s
        .catalog
        .create_edition(summary.id, name, slug, set_id, &bound, snapshot, &policy)
        .await
    {
        Ok(Some(_)) => Ok(Redirect::to(&back).into_response()),
        Ok(None) => Err(StatusCode::BAD_REQUEST),
        Err(sconce_catalog::EntitlementError::SkuCapReached(cap)) => Ok(error_card(
            &s,
            &user,
            "SKU limit reached",
            &format!(
                "This organization's plan allows at most {cap} editions. Deactivate one or upgrade the plan."
            ),
            &back,
        )),
        Err(_) => Ok(error_card(
            &s,
            &user,
            "Couldn't create edition",
            "An edition with that name may already exist (names are unique per repo).",
            &back,
        )),
    }
}

async fn deactivate_edition(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, repo)): Path<(String, String)>,
    Form(f): Form<IdForm>,
) -> Result<Redirect, StatusCode> {
    let repo_id = lookup_admin(&s, &user, &org, &repo).await?.id;
    let id = f.id.parse::<Uuid>().map_err(|_| StatusCode::BAD_REQUEST)?;
    s.catalog
        .set_edition_active(repo_id, id, false)
        .await
        .map_err(e500)?;
    Ok(Redirect::to(&format!("/r/{org}/{repo}")))
}

#[derive(serde::Deserialize)]
struct CreateTokenForm {
    label: Option<String>,
    /// Days until expiry; empty/absent means never.
    expires_days: Option<String>,
}

async fn create_token(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, repo)): Path<(String, String)>,
    Form(f): Form<CreateTokenForm>,
) -> Result<Html<String>, StatusCode> {
    let repo_id = lookup_admin(&s, &user, &org, &repo).await?.id;
    // Treat a blank name as "unnamed"; a blank/garbage expiry as "never".
    let label = f.label.as_deref().map(str::trim).filter(|l| !l.is_empty());
    let expires_days = f
        .expires_days
        .as_deref()
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .map(str::parse::<i64>)
        .transpose()
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .filter(|d| *d > 0);
    let token = match s.catalog.create_token(repo_id, label, expires_days).await {
        Ok(t) => t,
        // An org-policy rejection is the user's problem to fix, not a 500 — show
        // the reason and a link back.
        Err(sconce_catalog::CreateTokenError::Policy(reason)) => {
            let body = views::RepoNotice {
                title: "Token not created".to_owned(),
                message: reason,
                org: org.clone(),
                repo: repo.clone(),
            }
            .render()
            .map_err(e500)?;
            return Ok(shell(&s, &user, "Token not created", &body));
        }
        Err(sconce_catalog::CreateTokenError::Db(e)) => return Err(e500(e)),
    };
    let base = s.public_base_url.trim_end_matches('/');
    // Composer matches http-basic auth by hostname, so the auth line keys off the
    // host (not the full URL). The token is the *password*; the username is
    // ignored by the server, so "token" is just a readable placeholder.
    let host = base
        .split_once("://")
        .map_or(base, |(_, rest)| rest)
        .split('/')
        .next()
        .unwrap_or(base);
    let view = views::TokenCreated {
        tok: token,
        base: base.to_owned(),
        host: host.to_owned(),
        org: org.clone(),
        repo: repo.clone(),
    };
    Ok(shell(
        &s,
        &user,
        "Token created",
        &view.render().map_err(e500)?,
    ))
}

#[derive(serde::Deserialize)]
struct RevokeTokenForm {
    id: String,
}

async fn revoke_token(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, repo)): Path<(String, String)>,
    Form(f): Form<RevokeTokenForm>,
) -> Result<Redirect, StatusCode> {
    let repo_id = lookup_admin(&s, &user, &org, &repo).await?.id;
    let token_id =
        f.id.parse::<uuid::Uuid>()
            .map_err(|_| StatusCode::BAD_REQUEST)?;
    s.catalog
        .revoke_token(repo_id, token_id)
        .await
        .map_err(e500)?;
    Ok(Redirect::to(&format!("/r/{org}/{repo}")))
}

#[derive(Deserialize)]
struct TokenPolicyForm {
    label: String,
    mode: String,
    cooldown_days: Option<String>,
}

async fn set_token_policy(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, repo)): Path<(String, String)>,
    Form(f): Form<TokenPolicyForm>,
) -> Result<Redirect, StatusCode> {
    let repo_id = lookup_admin(&s, &user, &org, &repo).await?.id;
    // Empty mode = inherit (clear). Cooldown parses to None when blank.
    let update_mode = match f.mode.as_str() {
        "auto" | "manual" | "delayed" => Some(f.mode.clone()),
        "" => None,
        _ => return Err(StatusCode::BAD_REQUEST),
    };
    let cooldown_days = match f.cooldown_days.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(d) => Some(d.parse::<i32>().map_err(|_| StatusCode::BAD_REQUEST)?),
    };
    let policy = sconce_catalog::PolicyOverride {
        update_mode,
        cooldown_days,
    };
    s.catalog
        .set_token_policy(repo_id, &f.label, &policy)
        .await
        .map_err(e500)?;
    Ok(Redirect::to(&format!("/r/{org}/{repo}")))
}

#[derive(Deserialize)]
struct LicenseBoundForm {
    id: String,
    until: Option<String>,
    major: Option<String>,
}

async fn set_license_bound_action(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, repo)): Path<(String, String)>,
    Form(f): Form<LicenseBoundForm>,
) -> Result<Redirect, StatusCode> {
    let repo_id = lookup_admin(&s, &user, &org, &repo).await?.id;
    let license_id =
        f.id.parse::<uuid::Uuid>()
            .map_err(|_| StatusCode::BAD_REQUEST)?;
    let until = f.until.as_deref().map(str::trim).filter(|x| !x.is_empty());
    let major = match f.major.as_deref().map(str::trim).filter(|x| !x.is_empty()) {
        None => None,
        Some(m) => Some(m.parse::<i32>().map_err(|_| StatusCode::BAD_REQUEST)?),
    };
    s.catalog
        .set_license_bound(repo_id, license_id, until, major)
        .await
        .map_err(e500)?;
    Ok(Redirect::to(&format!("/r/{org}/{repo}")))
}

#[derive(Deserialize)]
struct LicensePolicyForm {
    id: String,
    mode: String,
    cooldown_days: Option<String>,
}

async fn set_license_policy(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, repo)): Path<(String, String)>,
    Form(f): Form<LicensePolicyForm>,
) -> Result<Redirect, StatusCode> {
    let repo_id = lookup_admin(&s, &user, &org, &repo).await?.id;
    let license_id =
        f.id.parse::<uuid::Uuid>()
            .map_err(|_| StatusCode::BAD_REQUEST)?;
    let update_mode = match f.mode.as_str() {
        "auto" | "manual" | "delayed" => Some(f.mode.clone()),
        "" => None,
        _ => return Err(StatusCode::BAD_REQUEST),
    };
    let cooldown_days = match f.cooldown_days.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(d) => Some(d.parse::<i32>().map_err(|_| StatusCode::BAD_REQUEST)?),
    };
    let policy = sconce_catalog::PolicyOverride {
        update_mode,
        cooldown_days,
    };
    s.catalog
        .set_license_policy(repo_id, license_id, &policy)
        .await
        .map_err(e500)?;
    Ok(Redirect::to(&format!("/r/{org}/{repo}")))
}

#[derive(Deserialize)]
struct LicenseSetForm {
    id: String,
    set_id: String,
}

async fn entitle_license_set(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, repo)): Path<(String, String)>,
    Form(f): Form<LicenseSetForm>,
) -> Result<Redirect, StatusCode> {
    let summary = lookup_admin(&s, &user, &org, &repo).await?;
    let license_id =
        f.id.parse::<uuid::Uuid>()
            .map_err(|_| StatusCode::BAD_REQUEST)?;
    let set_id = f
        .set_id
        .parse::<uuid::Uuid>()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    // The set must belong to the repo's org (no cross-tenant entitlement).
    match s.catalog.package_set(set_id).await.map_err(e500)? {
        Some((_, org_id)) if org_id == summary.org_id => {}
        _ => return Err(StatusCode::BAD_REQUEST),
    }
    s.catalog
        .entitle_set(license_id, set_id)
        .await
        .map_err(e500)?;
    Ok(Redirect::to(&format!("/r/{org}/{repo}")))
}

async fn remove_license_set(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, repo)): Path<(String, String)>,
    Form(f): Form<LicenseSetForm>,
) -> Result<Redirect, StatusCode> {
    lookup_admin(&s, &user, &org, &repo).await?;
    let license_id =
        f.id.parse::<uuid::Uuid>()
            .map_err(|_| StatusCode::BAD_REQUEST)?;
    let set_id = f
        .set_id
        .parse::<uuid::Uuid>()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    s.catalog
        .remove_set_entitlement(license_id, set_id)
        .await
        .map_err(e500)?;
    Ok(Redirect::to(&format!("/r/{org}/{repo}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_cookie_secure_only_on_https_dashboards() {
        let https = session_set_cookie("tok", true);
        assert!(https.ends_with("; Secure"));
        assert!(https.contains("HttpOnly") && https.contains("SameSite=Lax"));
        let http = session_set_cookie("tok", false);
        assert!(!http.contains("Secure"));
        assert!(session_clear_cookie(true).ends_with("; Secure"));
        assert!(session_clear_cookie(false).contains("Max-Age=0"));
    }

    #[test]
    fn client_ip_prefers_the_proxy_appended_forwarded_entry() {
        let peer: SocketAddr = "10.0.0.9:443".parse().unwrap();
        let mut h = HeaderMap::new();
        // The client-supplied (spoofable) entry comes first; the nearest proxy
        // appends the real peer last — that one must win.
        h.insert("x-forwarded-for", "1.2.3.4, 198.51.100.7".parse().unwrap());
        assert_eq!(client_ip(&h, Some(peer)), "198.51.100.7");
    }

    #[test]
    fn client_ip_falls_back_to_the_socket_peer() {
        let peer: SocketAddr = "192.0.2.1:5000".parse().unwrap();
        assert_eq!(client_ip(&HeaderMap::new(), Some(peer)), "192.0.2.1");
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "".parse().unwrap());
        assert_eq!(client_ip(&h, Some(peer)), "192.0.2.1");
        assert_eq!(client_ip(&HeaderMap::new(), None), "unknown");
    }
}
