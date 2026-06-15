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

use std::collections::HashSet;
use std::fmt::Write as _;

use axum::Router;
use axum::extract::{Extension, Form, Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use base64::Engine as _;
use sconce_catalog::Catalog;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

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
pub fn router(
    catalog: Catalog,
    public_base_url: String,
    single_tenant: bool,
    admin_password: Option<String>,
) -> Router {
    let state = Ui {
        catalog,
        public_base_url,
        single_tenant,
        admin_password,
        secret_key: sconce_catalog::secret::SecretKey::from_env().ok(),
    };
    Router::new()
        .route("/", get(index))
        .route("/assets/fonts/{file}", get(font_asset))
        .route("/login", get(login_form).post(login))
        .route("/auth/start", get(auth_start))
        .route("/auth/route", post(auth_route))
        .route("/auth/callback", get(auth_callback))
        .route("/scim/v2/Users", get(scim_list_users).post(scim_create_user))
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
        .route("/users/grant", post(grant_tenant))
        .route("/orgs", post(create_org))
        .route("/orgs/new", get(new_org_page))
        .route("/repos/new", get(new_repo_page))
        .route("/o/{org}", get(org_overview_page))
        .route("/o/{org}/settings", get(org_settings_page).post(save_org_settings))
        .route("/o/{org}/rename", post(rename_org_action))
        .route("/o/{org}/oidc", post(save_oidc))
        .route("/o/{org}/scim-token", post(gen_scim_token))
        .route("/repos", post(create_repo))
        .route("/r/{org}/{repo}", get(repo_page))
        .route("/r/{org}/{repo}/settings", get(repo_settings_page).post(save_repo_settings))
        .route("/r/{org}/{repo}/rename", post(rename_repo_action))
        .route("/r/{org}/{repo}/policy", post(set_policy))
        .route("/r/{org}/{repo}/version", post(version_action))
        .route("/r/{org}/{repo}/token", post(create_token))
        .route("/r/{org}/{repo}/token/revoke", post(revoke_token))
        .route("/r/{org}/{repo}/token/policy", post(set_token_policy))
        .route("/r/{org}/{repo}/license/policy", post(set_license_policy))
        .route("/r/{org}/{repo}/license", post(create_license))
        .route("/r/{org}/{repo}/grant", post(create_grant))
        .route("/r/{org}/{repo}/upstream", post(create_upstream))
        .route("/r/{org}/{repo}/upstream/remove", post(remove_upstream))
        .route("/r/{org}/{repo}/upstream/sync", post(sync_upstream))
        .route("/r/{org}/{repo}/deps/resolve", post(resolve_deps))
        .route("/r/{org}/{repo}/deps/add", post(add_dep))
        .route("/r/{org}/{repo}/package/archive", post(package_archive))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth))
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
    axum::serve(listener, app).await
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
    if s.single_tenant {
        if let Some(expected) = &s.admin_password
            && basic_password(req.headers()).as_deref() != Some(expected.as_str())
        {
            return basic_challenge();
        }
        req.extensions_mut().insert(CurrentUser::all_access());
        return next.run(req).await;
    }

    let path = req.uri().path();
    if path == "/login" || path.starts_with("/auth/") {
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

fn e500<E>(_: E) -> StatusCode {
    StatusCode::INTERNAL_SERVER_ERROR
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The design-system stylesheet (Bougie Repo · Stripe/Linear-style). Grounded in
/// the Claude Design handoff: Geist + Geist Mono, neutral light palette, indigo
/// accent (#5a4ff0), first-class status-badge tones. Shared by every page.
const STYLE: &str = "\
@font-face{font-family:'Geist Variable';src:url('/assets/fonts/geist.woff2') format('woff2');\
font-weight:100 900;font-style:normal;font-display:swap}\
@font-face{font-family:'Geist Mono Variable';src:url('/assets/fonts/geist-mono.woff2') format('woff2');\
font-weight:100 900;font-style:normal;font-display:swap}\
:root{--bg:#f7f8fa;--surface:#fff;--border:#e7e9ee;--soft:#eef0f3;\
--text:#15171c;--text2:#545b68;--muted:#9098a4;\
--accent:#5a4ff0;--accent-press:#4f44e6;--accent-fg:#4b3fc4;\
--sans:'Geist Variable','Geist',system-ui,-apple-system,sans-serif;\
--mono:'Geist Mono Variable','Geist Mono',ui-monospace,SFMono-Regular,Menlo,monospace}\
*{box-sizing:border-box}\
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 var(--sans);-webkit-font-smoothing:antialiased}\
a{color:var(--accent-fg);text-decoration:none}a:hover{text-decoration:underline}\
code,pre,.mono{font-family:var(--mono)}\
.appbar{display:flex;align-items:center;justify-content:space-between;height:56px;padding:0 28px;\
background:var(--surface);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:5}\
.brand{display:flex;align-items:center;gap:10px;color:var(--text);font-weight:700;font-size:15px}\
.brand:hover{text-decoration:none}\
.brandmark{display:flex;width:28px;height:28px;align-items:center;justify-content:center;border-radius:8px;\
background:linear-gradient(150deg,#7b6cf6,#5a4ff0);box-shadow:0 1px 2px rgba(74,63,196,.35)}\
.appnav{display:flex;align-items:center;gap:14px;color:var(--muted);font-size:13px}\
.appnav a{color:var(--text2)}\
.wrap{max-width:74rem;margin:26px auto 4rem;padding:0 28px}\
h1{font-size:22px;font-weight:650;letter-spacing:-.01em;margin:.2rem 0 1rem}\
h2{font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin:2.2rem 0 .7rem}\
table{width:100%;border-collapse:separate;border-spacing:0;margin:.5rem 0 1rem;background:var(--surface);\
border:1px solid var(--border);border-radius:11px;overflow:hidden;box-shadow:0 1px 2px rgba(20,23,28,.04)}\
th,td{text-align:left;padding:.6rem .8rem;border-bottom:1px solid var(--soft);vertical-align:middle}\
th{background:#fbfbfc;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.045em;color:var(--muted)}\
tr:last-child td{border-bottom:none}\
.muted{color:var(--muted)}\
.badge{display:inline-flex;align-items:center;gap:5px;height:21px;padding:0 8px;border-radius:6px;\
font-size:11.5px;font-weight:600;line-height:1;white-space:nowrap;background:#f3f4f6;color:#4b5260;border:1px solid #e5e7ec}\
.badge.ok{background:#e8f5ec;color:#127544;border-color:#cfe9d8}\
.badge.held{background:#fceae7;color:#a82c20;border-color:#f4cfc8}\
.badge.amber{background:#fbf1d9;color:#8a5a00;border-color:#f0e0ac}\
.badge.slate{background:#eef1f6;color:#3f4756;border-color:#dfe4ec}\
.badge.blue{background:#e9f0fc;color:#1f54ad;border-color:#d3e1f7}\
.badge.violet{background:#f0edfd;color:#4b3fc4;border-color:#e1dbf8}\
button{font:inherit;font-size:12.5px;font-weight:600;cursor:pointer;color:var(--text2);background:var(--surface);\
border:1px solid var(--border);border-radius:7px;padding:.32rem .62rem;transition:background .12s,border-color .12s}\
button:hover{background:#f6f7f9;border-color:#dcdfe6}\
form.row button,button.primary{color:#fff;background:var(--accent);border-color:var(--accent-press);\
box-shadow:0 1px 2px rgba(74,63,196,.28)}\
form.row button:hover,button.primary:hover{background:var(--accent-press);border-color:var(--accent-press)}\
input,select{font:inherit;font-size:13px;color:var(--text);background:var(--surface);border:1px solid var(--border);\
border-radius:7px;padding:.32rem .5rem}\
input:focus,select:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(90,79,240,.15)}\
form.inline{display:inline-flex;gap:.3rem;align-items:center;flex-wrap:wrap}\
form.row{display:flex;flex-wrap:wrap;gap:.5rem;align-items:center;margin:.7rem 0}\
code{background:#f1f3f6;border:1px solid var(--soft);border-radius:5px;padding:.05rem .3rem;font-size:12.5px}\
pre{background:#0f1115;color:#e6e8ee;border:1px solid #1f232b;border-radius:10px;padding:.9rem 1rem;\
overflow:auto;font-size:12.5px;line-height:1.55}\
pre code{background:none;border:none;color:inherit;padding:0}\
.banner{display:flex;align-items:center;gap:8px;padding:.6rem .85rem;border-radius:9px;font-size:13px;\
font-weight:500;background:#fbf1d9;color:#8a5a00;border:1px solid #f0e0ac;margin:1rem 0}\
.layout{display:flex;min-height:100vh}\
.sidebar{width:240px;flex:none;background:var(--surface);border-right:1px solid var(--border);\
display:flex;flex-direction:column;padding:14px 12px;position:sticky;top:0;height:100vh}\
.org{display:flex;align-items:center;gap:10px;padding:8px 9px;border:1px solid var(--border);border-radius:9px;background:#fbfbfc;text-decoration:none}\
.org:hover{text-decoration:none}\
.org .mk{width:30px;height:30px;flex:none;border-radius:8px;display:flex;align-items:center;justify-content:center;\
background:linear-gradient(150deg,#7b6cf6,#5a4ff0);box-shadow:0 1px 2px rgba(74,63,196,.35)}\
.org .name{display:block;font-size:13.5px;font-weight:600;color:var(--text);line-height:1.2}\
.org .sub{display:block;font-size:11px;color:var(--muted)}\
.side-nav{display:flex;flex-direction:column;gap:1px;margin-top:16px;flex:1}\
.side-nav .grp{font-size:10.5px;font-weight:600;letter-spacing:.07em;color:#a2a9b4;padding:14px 10px 5px}\
.side-nav a{display:flex;align-items:center;gap:10px;height:34px;padding:0 10px;border-radius:7px;\
font-size:13.5px;font-weight:500;color:var(--text2);text-decoration:none}\
.side-nav a:hover{background:#f6f7f9;text-decoration:none}\
.side-nav a.active{background:#f1effc;color:var(--accent-fg);font-weight:600}\
.side-nav a.active svg{color:var(--accent)}\
.side-nav svg{color:#8b94a3;flex:none}\
.userbox{display:flex;align-items:center;gap:9px;padding:10px 8px 4px;border-top:1px solid var(--soft);margin-top:8px}\
.userbox .avatar{width:30px;height:30px;flex:none;border-radius:50%;background:#ece9fb;color:#5a4ff0;\
display:flex;align-items:center;justify-content:center}\
.userbox form{margin:0}.userbox button{padding:.2rem .5rem;font-size:11.5px}\
.rolepill{display:inline-flex;align-items:center;height:17px;padding:0 7px;border-radius:5px;font-size:10.5px;font-weight:600;background:#f0edfd;color:#4b3fc4}\
.col{flex:1;display:flex;flex-direction:column;min-width:0}\
.topbar{height:56px;flex:none;display:flex;align-items:center;gap:9px;padding:0 30px;\
background:var(--surface);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:5;font-size:13.5px}\
.topbar .sep{color:#cdd2da}.topbar .here{font-weight:600;color:var(--text)}\
.content{flex:1;padding:24px 30px;min-width:0;max-width:1120px}\
.content h1:first-child{margin-top:0}\
.pager{display:flex;align-items:center;gap:12px;font-size:12px;margin:-.4rem 0 1.2rem}\
.pager a{font-weight:600}\
.authwrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;background:var(--bg)}\
.authcard{width:100%;max-width:380px;background:var(--surface);border:1px solid var(--border);\
border-radius:14px;box-shadow:0 4px 24px rgba(20,23,28,.06);padding:30px 28px}\
.authcard .brand{justify-content:center;margin-bottom:6px}\
.authcard h1{font-size:18px;font-weight:650;text-align:center;margin:.4rem 0 1.3rem}\
.authform{display:flex;flex-direction:column;gap:11px}\
.authform label{display:block;font-size:12px;font-weight:600;color:var(--text2);margin-bottom:4px}\
.authform input{width:100%;height:34px}\
.authcard button{width:100%;justify-content:center;height:36px;font-size:13px}\
.authsep{display:flex;align-items:center;gap:10px;color:var(--muted);font-size:11px;\
text-transform:uppercase;letter-spacing:.06em;margin:18px 0}\
.authsep::before,.authsep::after{content:'';flex:1;height:1px;background:var(--border)}\
.errbanner{padding:.55rem .75rem;border-radius:8px;font-size:12.5px;background:#fceae7;color:#a82c20;\
border:1px solid #f4cfc8;margin-bottom:13px;text-align:center}\
.toolbar{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:8px}\
.toolbar h1{margin:0}\
.toolbar a{text-decoration:none}\
.repohead{display:flex;align-items:center;flex-wrap:wrap;gap:9px;margin-bottom:2px}\
.repohead h1{margin:0}.repohead a{text-decoration:none;margin-left:auto}\
.summary{color:var(--muted);font-size:13px;margin:.1rem 0 1.1rem}\
.hero{background:var(--surface);border:1px solid var(--border);border-radius:11px;padding:14px 16px;\
margin:0 0 1.4rem;box-shadow:0 1px 2px rgba(20,23,28,.04)}\
.hero h2{margin:0 0 .5rem}.hero pre{margin:0}\
";

/// The hexagon-package brand glyph (from the design's `AppShell`), white-stroked
/// for the gradient mark chip.
const MARK_SVG: &str = "<svg width=16 height=16 viewBox=\"0 0 24 24\" fill=none stroke=#fff stroke-width=2 \
stroke-linecap=round stroke-linejoin=round><path d=\"M12 3l8 4.5v9L12 21l-8-4.5v-9L12 3z\"></path>\
<path d=\"M4 7.5l8 4.5 8-4.5\"></path><path d=\"M12 12v9\"></path></svg>";

/// Full HTML scaffold shared by every page. Fonts + stylesheet live in `STYLE`;
/// the Geist woff2 are vendored and served from `/assets/fonts` (no CDN).
fn doc(title: &str, inner: &str) -> Html<String> {
    Html(format!(
        "<!doctype html><html lang=en><head><meta charset=utf-8>\
         <meta name=viewport content=\"width=device-width,initial-scale=1\">\
         <title>{title} · Bougie Repo</title>\
         <style>{STYLE}</style></head><body>{inner}</body></html>"
    ))
}

/// An authenticated app page, wrapped in the sidebar `AppShell` (left nav + top
/// breadcrumb bar + content).
fn shell(s: &Ui, user: &CurrentUser, title: &str, body: &str) -> Html<String> {
    doc(
        title,
        &format!(
            "<div class=layout>{sidebar}<div class=col>\
               <header class=topbar><span class=muted>Bougie Repo</span>\
               <span class=sep>&rsaquo;</span><span class=here>{here}</span></header>\
               <main class=content>{body}</main></div></div>",
            sidebar = sidebar(s, user, title),
            here = esc(title),
        ),
    )
}

/// "Showing X–Y of N {noun}" with prev/next links (hidden when it fits on one
/// page, per the design). `base` is the page URL; pagination uses `?page=`.
fn paginator(noun: &str, total: i64, page: i64, per_page: i64, base: &str) -> String {
    let last_page = ((total + per_page - 1) / per_page).max(1);
    let page = page.clamp(1, last_page);
    let from = if total == 0 { 0 } else { (page - 1) * per_page + 1 };
    let to = (page * per_page).min(total);
    let mut controls = String::new();
    if last_page > 1 {
        if page > 1 {
            let _ = write!(controls, "<a href=\"{base}?page={}\">&lsaquo; Prev</a>", page - 1);
        }
        let _ = write!(controls, "<span class=muted>Page {page} of {last_page}</span>");
        if page < last_page {
            let _ = write!(controls, "<a href=\"{base}?page={}\">Next &rsaquo;</a>", page + 1);
        }
    }
    format!("<div class=pager><span class=muted>Showing {from}&ndash;{to} of {total} {noun}</span>{controls}</div>")
}

/// A 24×24 stroke nav icon.
fn nav_icon(paths: &str) -> String {
    format!(
        "<svg width=17 height=17 viewBox=\"0 0 24 24\" fill=none stroke=currentColor stroke-width=1.7 \
         stroke-linecap=round stroke-linejoin=round>{paths}</svg>"
    )
}

/// The left sidebar: brand/org block, route-grounded nav (active state derived
/// from `title`), and the user/role + log-out footer.
fn sidebar(s: &Ui, user: &CurrentUser, title: &str) -> String {
    const REPOS: &str = "<path d=\"M12 3l8 4.5v9L12 21l-8-4.5v-9L12 3z\"></path>\
<path d=\"M4 7.5l8 4.5 8-4.5\"></path><path d=\"M12 12v9\"></path>";
    const MEMBERS: &str = "<circle cx=9 cy=8 r=3.2></circle><path d=\"M3 20a6 6 0 0 1 12 0\"></path>\
<path d=\"M16 5.5a3 3 0 0 1 0 5.5\"></path><path d=\"M21 20a6 6 0 0 0-4-5.6\"></path>";
    const ACTIVITY: &str = "<path d=\"M3 12h4l2.5 7 4-14 2.5 7h5\"></path>";
    let on_members = title == "Users";
    let on_activity = title == "Activity";
    let cls = |on: bool| if on { " class=active" } else { "" };

    let mut nav = format!(
        "<a href=/{c}>{ic}<span>Repositories</span></a>",
        c = cls(!on_members && !on_activity),
        ic = nav_icon(REPOS),
    );
    // Members lives in multi-tenant and is superadmin-managed.
    if !s.single_tenant && user.is_superadmin {
        let _ = write!(
            nav,
            "<div class=grp>ORGANIZATION</div><a href=/users{c}>{ic}<span>Members</span></a>",
            c = cls(on_members),
            ic = nav_icon(MEMBERS),
        );
    }
    let _ = write!(
        nav,
        "<div class=grp>SYSTEM</div><a href=/activity{c}>{ic}<span>Activity</span></a>",
        c = cls(on_activity),
        ic = nav_icon(ACTIVITY),
    );

    let sub = if s.single_tenant { "Single-tenant" } else { "Hosted" };
    // Single-tenant is all-access; otherwise admin if they manage any tenant.
    let role = if s.single_tenant || user.is_superadmin || !user.admin_tenants.is_empty() {
        "Admin"
    } else {
        "Member"
    };
    // No session to end in single-tenant (HTTP-basic), so no log-out / account.
    let logout = if s.single_tenant {
        String::new()
    } else {
        "<form method=post action=/logout><button>Log out</button></form>".to_owned()
    };
    let (user_open, user_close) = if s.single_tenant {
        ("", "")
    } else {
        ("<a href=/account title=Account style=\"display:flex;align-items:center;gap:9px;flex:1;min-width:0;text-decoration:none\">", "</a>")
    };

    format!(
        "<aside class=sidebar>\
           <a class=org href=/><span class=mk>{MARK_SVG}</span>\
             <span><span class=name>Bougie Repo</span><span class=sub>{sub}</span></span></a>\
           <nav class=side-nav>{nav}</nav>\
           <div class=userbox>\
             {user_open}<span class=avatar><svg width=16 height=16 viewBox=\"0 0 24 24\" fill=none stroke=currentColor \
               stroke-width=2 stroke-linecap=round stroke-linejoin=round><circle cx=12 cy=8 r=4></circle>\
               <path d=\"M4 21a8 8 0 0 1 16 0\"></path></svg></span>\
             <span style=\"flex:1;min-width:0\"><span class=rolepill>{role}</span></span>{user_close}{logout}\
           </div></aside>"
    )
}

/// Serve a vendored Geist woff2, embedded in the binary (no runtime file or CDN
/// dependency — keeps the single-binary deploy self-contained). Public + immutable.
async fn font_asset(Path(file): Path<String>) -> Response {
    let bytes: &'static [u8] = match file.as_str() {
        "geist.woff2" => include_bytes!("../assets/fonts/geist.woff2"),
        "geist-mono.woff2" => include_bytes!("../assets/fonts/geist-mono.woff2"),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    (
        [
            (header::CONTENT_TYPE, "font/woff2"),
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
    let repos = s.catalog.org_repo_overview(summary.id).await.map_err(e500)?;
    let slug = esc(&org);
    let can_admin = user.can_admin(summary.id);

    let mut rows = String::new();
    for r in &repos {
        let vis = if r.allow_private_packages {
            "<span class='badge slate'>private</span>"
        } else {
            "<span class='badge blue'>public-only</span>"
        };
        let broken = if r.broken > 0 {
            format!(" <span class='badge amber'>⚠ {}</span>", r.broken)
        } else {
            String::new()
        };
        let _ = write!(
            rows,
            "<tr><td><a href=\"/r/{slug}/{rp}\">{rp}</a>{broken}</td><td>{vis}</td>\
             <td>{pk}</td><td class=muted>{last}</td><td>{mode}</td></tr>",
            rp = esc(&r.slug),
            pk = r.packages,
            last = esc(r.last_sync.as_deref().unwrap_or("never")),
            mode = esc(&r.update_mode),
        );
    }
    if repos.is_empty() {
        let cta = if can_admin {
            format!(" — <a href=\"/repos/new?org={slug}\">create one</a>")
        } else {
            String::new()
        };
        rows = format!("<tr><td colspan=5 class=muted>No repositories yet{cta}.</td></tr>");
    }

    let actions = if can_admin {
        format!(
            "<a href=\"/o/{slug}/settings\"><button>Settings</button></a> \
             <a href=\"/repos/new?org={slug}\"><button class=primary>+ New repository</button></a>"
        )
    } else {
        String::new()
    };
    let body = format!(
        "<div class=toolbar><h1>{slug}</h1><div>{actions}</div></div>\
         <table><tr><th>Repository</th><th>Visibility</th><th>Packages</th><th>Last sync</th><th>Update mode</th></tr>{rows}</table>"
    );
    Ok(shell(&s, &user, &org, &body))
}

async fn org_settings_page(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path(org): Path<String>,
) -> Result<Html<String>, StatusCode> {
    let summary = lookup_org(&s, &user, &org).await?;
    let cfg = s.catalog.org_settings(summary.id).await.map_err(e500)?;
    let oidc = s.catalog.oidc_connection_for_org(summary.id).await.map_err(e500)?;
    let slug = esc(&org);
    let raw_checked = if cfg.allow_raw_tokens { " checked" } else { "" };
    let max_ttl = cfg
        .max_token_ttl_days
        .map(|d| d.to_string())
        .unwrap_or_default();
    let body = format!(
        "<h1>{slug} — settings</h1>\
         <form class=row method=post action=\"/o/{slug}/settings\">\
         <p><label><input type=checkbox name=allow_raw_tokens value=1{raw_checked}> \
         Allow raw repo tokens</label><br>\
         <span class=muted>When off, tokens can't be created here — the org relies on \
         SSO/CI-derived credentials that can be deprovisioned.</span></p>\
         <p>Max token expiry (days), blank = no limit: \
         <input name=max_token_ttl_days type=number min=1 value=\"{max_ttl}\" style=\"width:7em\"></p>\
         <button>Save settings</button></form>\
         {oidc_section}{scim_section}\
         <h2>Rename organization</h2>{former}\
         <p class=muted>Old URLs keep working via redirect, so existing \
         <code>composer.lock</code> files don't break. The old slug is \
         <strong>permanently retired</strong> and can't be reused.</p>\
         <form class=row method=post action=\"/o/{slug}/rename\">\
         new slug <input name=slug placeholder=\"{slug}\" required> <button>Rename</button></form>\
         <p><a href=\"/\">← back</a></p>",
        former = former_line(&s, "org", summary.id).await,
        oidc_section = oidc_section(&slug, oidc.as_ref()),
        scim_section = scim_section(&slug),
    );
    Ok(shell(&s, &user, &format!("{org} settings"), &body))
}

/// C4 — the SSO/OIDC connection form (per-org). The client secret is write-only:
/// it's never rendered back; leaving it blank on save keeps the stored one.
fn oidc_section(slug: &str, c: Option<&sconce_catalog::OidcConnection>) -> String {
    let v = |x: &str| esc(x);
    let issuer = c.map_or(String::new(), |c| v(&c.issuer_url));
    let client_id = c.map_or(String::new(), |c| v(&c.client_id));
    let redirect = c.map_or(String::new(), |c| v(&c.redirect_url));
    let scopes = c.map_or_else(|| "openid email profile".to_owned(), |c| v(&c.scopes));
    let allowed = c
        .and_then(|c| c.allowed_domains.as_ref())
        .map_or(String::new(), |d| esc(&d.join(", ")));
    let admin = c
        .and_then(|c| c.admin_domains.as_ref())
        .map_or(String::new(), |d| esc(&d.join(", ")));
    let status = if c.is_some() {
        "<span class='badge ok'>configured</span>"
    } else {
        "<span class='badge slate'>not set</span>"
    };
    format!(
        "<h2>SSO — OIDC {status}</h2>\
         <p class=muted>Users who sign in via this connection are provisioned into <code>{slug}</code>. \
         The client secret is write-only — leave it blank to keep the current one.</p>\
         <form class=row method=post action=\"/o/{slug}/oidc\">\
         <p>Issuer URL <input name=issuer type=url value=\"{issuer}\" placeholder=\"https://idp.example.com\" required style=\"width:24em\"></p>\
         <p>Client ID <input name=client_id value=\"{client_id}\" required style=\"width:18em\"></p>\
         <p>Client secret <input name=client_secret type=password placeholder=\"(unchanged)\" style=\"width:18em\"></p>\
         <p>Redirect URL <input name=redirect_url type=url value=\"{redirect}\" placeholder=\"https://dashboard/auth/callback\" required style=\"width:24em\"></p>\
         <p>Scopes <input name=scopes value=\"{scopes}\" style=\"width:18em\"></p>\
         <p>Allowed email domains (comma-sep, blank = any) <input name=allowed_domains value=\"{allowed}\" style=\"width:18em\"></p>\
         <p>Admin email domains (comma-sep) <input name=admin_domains value=\"{admin}\" style=\"width:18em\"></p>\
         <button>Save SSO connection</button></form>"
    )
}

/// C5 — SCIM provisioning: the endpoint + a generate/rotate-token action.
fn scim_section(slug: &str) -> String {
    format!(
        "<h2>SCIM provisioning</h2>\
         <p class=muted>Point your IdP's SCIM connector here so offboarded users are deactivated \
         (their sessions revoked) automatically. Endpoint: \
         <code>&lt;dashboard-url&gt;/scim/v2/Users</code> — bearer auth with the token below.</p>\
         <form class=row method=post action=\"/o/{slug}/scim-token\">\
         <button>Generate / rotate SCIM token</button></form>"
    )
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
    let client_secret = match f.client_secret.as_deref().map(str::trim).filter(|x| !x.is_empty()) {
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
    s.catalog.set_oidc_connection(Some(&org), &conn).await.map_err(e500)?;
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
        .map_err(e500)?
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(shell(
        &s,
        &user,
        "SCIM token",
        &format!(
            "<h1>SCIM token</h1>\
             <p class=banner>Store it now — it won't be shown again.</p>\
             <pre>{}</pre>\
             <p class=muted>Use it as the bearer token in your IdP's SCIM connector. Endpoint: \
             <code>&lt;dashboard-url&gt;/scim/v2/Users</code></p>\
             <p><a href=\"/o/{org}/settings\">← back to settings</a></p>",
            esc(&token)
        ),
    ))
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
        Err(e @ (sconce_catalog::RenameError::Taken | sconce_catalog::RenameError::Retired)) => {
            Ok(rename_failed(&s, &user, &format!("/o/{org}/settings"), &e.to_string()))
        }
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
    let slug = format!("{}/{}", esc(&org), esc(&repo));

    // Three-way <select> for the boolean override: inherit / allow / deny.
    let opt = |val: &str, label: &str, current: Option<bool>| {
        let sel = match (val, current) {
            ("inherit", None) | ("allow", Some(true)) | ("deny", Some(false)) => " selected",
            _ => "",
        };
        format!("<option value={val}{sel}>{label}</option>")
    };
    let raw_select = format!(
        "{}{}{}",
        opt("inherit", "Inherit from org", repo_cfg.allow_raw_tokens),
        opt("allow", "Allow", repo_cfg.allow_raw_tokens),
        opt("deny", "Disable", repo_cfg.allow_raw_tokens),
    );
    let repo_ttl = repo_cfg
        .max_token_ttl_days
        .map(|d| d.to_string())
        .unwrap_or_default();
    let org_raw = if org_cfg.allow_raw_tokens { "allowed" } else { "disabled" };
    let org_ttl = org_cfg
        .max_token_ttl_days
        .map_or_else(|| "no limit".to_owned(), |d| format!("{d} day(s)"));
    let eff_raw = if effective.allow_raw_tokens { "allowed" } else { "disabled" };
    let eff_ttl = effective
        .max_token_ttl_days
        .map_or_else(|| "no limit".to_owned(), |d| format!("{d} day(s)"));
    let private_checked = if repo_cfg.allow_private_packages {
        " checked"
    } else {
        ""
    };

    let body = format!(
        "<h1>{slug} — settings</h1>\
         <p class=muted>Org baseline: raw tokens {org_raw}, max TTL {org_ttl}. \
         A repo can only <em>tighten</em> the org policy, never loosen it.</p>\
         <form class=row method=post action=\"/r/{slug}/settings\">\
         <p>Raw tokens: <select name=allow_raw_tokens>{raw_select}</select></p>\
         <p>Max token expiry (days), blank = inherit: \
         <input name=max_token_ttl_days type=number min=1 value=\"{repo_ttl}\" style=\"width:7em\"></p>\
         <p><label><input type=checkbox name=allow_private_packages value=1{private_checked}> \
         Allow private packages</label><br>\
         <span class=muted>When off, this repo is public-only — private packages can't be \
         added and any already present aren't served.</span></p>\
         <button>Save settings</button></form>\
         <p><strong>Effective now:</strong> raw tokens {eff_raw}, max TTL {eff_ttl}.</p>\
         <h2>Rename repository</h2>{former}\
         <p class=muted>Old URLs keep working via redirect, so existing \
         <code>composer.lock</code> files don't break. The old name is \
         <strong>permanently retired</strong> and can't be reused. Update your \
         <code>composer config</code> when convenient.</p>\
         <form class=row method=post action=\"/r/{slug}/rename\">\
         new name <input name=slug placeholder=\"{repo}\" required> <button>Rename</button></form>\
         <p><a href=\"/r/{slug}\">← back to {slug}</a></p>",
        former = former_line(&s, "repo", summary.id).await,
    );
    Ok(shell(&s, &user, &format!("{org}/{repo} settings"), &body))
}

/// A muted "Formerly: a, b" line (still redirecting), or empty if never renamed.
async fn former_line(s: &Ui, entity_type: &str, entity_id: Uuid) -> String {
    match s.catalog.former_slugs(entity_type, entity_id).await {
        Ok(v) if !v.is_empty() => format!(
            "<p class=muted>Formerly (still redirecting): {}</p>",
            v.iter().map(|x| format!("<code>{}</code>", esc(x))).collect::<Vec<_>>().join(", ")
        ),
        _ => String::new(),
    }
}

#[derive(Deserialize)]
struct RenameForm {
    slug: String,
}

/// Render a rename failure (taken/retired) with the reason and a back link.
/// A simple error page: title + an amber banner message + a back link.
fn error_card(s: &Ui, user: &CurrentUser, title: &str, msg: &str, back: &str) -> Response {
    let body = format!(
        "<h1>{title}</h1><p class=banner>{}</p><p><a href=\"{back}\">← back</a></p>",
        esc(msg)
    );
    shell(s, user, title, &body).into_response()
}

fn rename_failed(s: &Ui, user: &CurrentUser, back: &str, msg: &str) -> Response {
    error_card(s, user, "Rename failed", msg, back)
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
            Ok(rename_failed(&s, &user, &format!("/r/{org}/{repo}/settings"), &e.to_string()))
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

/// A centered sign-in card (brand + `inner`), full-viewport, no app chrome.
fn auth_page(title: &str, inner: &str) -> Html<String> {
    doc(
        title,
        &format!(
            "<div class=authwrap><div class=authcard>\
               <a class=brand href=/><span class=brandmark>{MARK_SVG}</span> <span>Bougie Repo</span></a>\
               {inner}</div></div>"
        ),
    )
}

async fn login_form(State(s): State<Ui>) -> Html<String> {
    // Offer SSO if any connection exists: a direct button for the instance
    // default, and an email box that routes org domains to their own IdP.
    let mut sso = String::new();
    if s.catalog.oidc_configured().await.unwrap_or(false) {
        sso.push_str("<div class=authsep>or</div>");
        if matches!(s.catalog.oidc_connection().await, Ok(Some(_))) {
            sso.push_str(
                "<a href=\"/auth/start\"><button type=button>Sign in with SSO</button></a>",
            );
        }
        sso.push_str(
            "<form class=authform method=post action=/auth/route style=\"margin-top:11px\">\
             <div><label>Organization email</label>\
             <input name=email type=email placeholder=\"you@company.com\"></div>\
             <button type=submit>Continue with SSO</button></form>",
        );
    }
    auth_page(
        "Sign in",
        &format!(
            "<h1>Sign in</h1>\
             <form class=authform method=post action=/login>\
             <div><label>Email</label><input name=email type=email required autofocus></div>\
             <div><label>Password</label><input name=password type=password required></div>\
             <button class=primary type=submit>Sign in</button></form>{sso}"
        ),
    )
}

#[derive(Deserialize)]
struct LoginForm {
    email: String,
    password: String,
}

async fn login(State(s): State<Ui>, Form(f): Form<LoginForm>) -> Result<Response, StatusCode> {
    let Some(user_id) = s
        .catalog
        .verify_credentials(&f.email, &f.password)
        .await
        .map_err(e500)?
    else {
        return Ok(login_error("Invalid email or password."));
    };
    let token = s.catalog.create_session(user_id, 7).await.map_err(e500)?;
    let cookie = format!("sconce_session={token}; HttpOnly; Path=/; SameSite=Lax; Max-Age=604800");
    Ok(redirect_with_cookie("/", &cookie))
}

/// Decrypt an OIDC connection's stored client secret (if any).
fn oidc_secret(s: &Ui, conn: &sconce_catalog::OidcConnection) -> Result<Option<String>, StatusCode> {
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
        Err(e) => return Ok(login_error(&format!("SSO unavailable: {}", esc(&e.to_string())))),
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
async fn auth_route(
    State(s): State<Ui>,
    Form(f): Form<RouteForm>,
) -> Result<Response, StatusCode> {
    match s.catalog.oidc_connection_for_email(&f.email).await.map_err(e500)? {
        Some(id) => Ok(Redirect::to(&format!("/auth/start?conn={id}")).into_response()),
        None => Ok(login_error("no SSO is configured for that email domain")),
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
        return Ok(login_error(&format!("IdP returned an error: {}", esc(&err))));
    }
    let (Some(code), Some(state)) = (p.code, p.state) else {
        return Err(StatusCode::BAD_REQUEST);
    };
    // The flow must exist (unknown/expired/replayed state → reject).
    let Some((conn_id, nonce, verifier, redirect_to)) =
        s.catalog.consume_oidc_flow(&state).await.map_err(e500)?
    else {
        return Ok(login_error("login session expired or invalid — try again"));
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
            Err(e) => return Ok(login_error(&format!("SSO failed: {}", esc(&e.to_string())))),
        };

    // Gate by allowed domains (if configured), and grant superadmin by domain.
    if conn.allowed_domains.as_ref().is_some_and(|d| !d.is_empty())
        && !crate::oidc::domain_matches(&identity.email, &conn.allowed_domains)
    {
        return Ok(login_error("your email domain is not allowed to sign in"));
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
    let cookie = format!("sconce_session={token}; HttpOnly; Path=/; SameSite=Lax; Max-Age=604800");
    let dest = if redirect_to.starts_with('/') { redirect_to } else { "/".to_owned() };
    Ok(redirect_with_cookie(&dest, &cookie))
}

/// A login-page error response (centered card with a red banner).
fn login_error(msg: &str) -> Response {
    auth_page(
        "Sign in",
        &format!(
            "<h1>Sign in</h1><p class=errbanner>{}</p>\
             <p style=\"text-align:center\"><a href=/login>← try again</a></p>",
            esc(msg)
        ),
    )
    .into_response()
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
    let token =
        bearer(headers).ok_or_else(|| scim_error(StatusCode::UNAUTHORIZED, "missing bearer token"))?;
    match s.catalog.resolve_scim_token(&token).await {
        Ok(Some(org)) => Ok(org),
        Ok(None) => Err(scim_error(StatusCode::UNAUTHORIZED, "invalid SCIM token")),
        Err(_) => Err(scim_error(StatusCode::INTERNAL_SERVER_ERROR, "server error")),
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
            let path = op.get("path").and_then(Value::as_str).map(str::to_ascii_lowercase);
            if path.as_deref() == Some("active")
                && let Some(b) = op.get("value").and_then(scim_bool)
            {
                return Some(b);
            }
            if let Some(b) = op.get("value").and_then(|v| v.get("active")).and_then(scim_bool) {
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

async fn scim_get_user(State(s): State<Ui>, headers: HeaderMap, Path(id): Path<String>) -> Response {
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
    let (Ok(uid), Ok(v)) = (id.parse::<uuid::Uuid>(), serde_json::from_str::<Value>(&body)) else {
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
    redirect_with_cookie(
        "/login",
        "sconce_session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0",
    )
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
    let email = s.catalog.user_email(uid).await.map_err(e500)?.unwrap_or_default();
    let current = session_cookie(&headers);
    let sessions = s
        .catalog
        .list_sessions(uid, current.as_deref())
        .await
        .map_err(e500)?;
    let mut rows = String::new();
    for sn in &sessions {
        let this = if sn.current {
            " <span class='badge ok'>this device</span>"
        } else {
            ""
        };
        let _ = write!(
            rows,
            "<tr><td>{created}{this}</td><td class=muted>{expires}</td><td>\
             <form class=inline method=post action=/account/revoke>\
             <input type=hidden name=id value=\"{id}\"><button>Revoke</button></form></td></tr>",
            created = esc(&sn.created),
            expires = esc(&sn.expires),
            id = esc(&sn.hash_hex),
        );
    }
    Ok(shell(
        &s,
        &user,
        "Account",
        &format!(
            "<h1>Account</h1>\
             <p>Signed in as <strong>{email}</strong>{admin}.</p>\
             <h2>Active sessions</h2>\
             <p class=muted>Revoke any session to sign that device out. Revoking <em>this device</em> \
             signs you out here.</p>\
             <table><tr><th>Signed in</th><th>Expires</th><th></th></tr>{rows}</table>\
             <form class=row method=post action=/logout><button>Sign out</button></form>",
            email = esc(&email),
            admin = if user.is_superadmin { " (superadmin)" } else { "" },
        ),
    ))
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
    let mut rows = String::new();
    for u in &users {
        // Each membership as a chip: slug + role, greyed + "deactivated" if inactive.
        let mut chips = String::new();
        for t in &u.tenants {
            let (tone, suffix) = if t.active {
                (if t.role == "admin" { "violet" } else { "slate" }, String::new())
            } else {
                ("held", " · deactivated".to_owned())
            };
            let _ = write!(
                chips,
                "<span class='badge {tone}'>{slug} · {role}{suffix}</span> ",
                slug = esc(&t.slug),
                role = esc(&t.role),
            );
        }
        if u.tenants.is_empty() {
            chips.push_str("<span class=muted>—</span>");
        }
        let _ = write!(
            rows,
            "<tr><td>{email}</td><td>{sa}</td><td>{chips}</td></tr>",
            email = esc(&u.email),
            sa = if u.is_superadmin {
                "<span class='badge amber'>superadmin</span>"
            } else {
                ""
            },
        );
    }
    Ok(shell(
        &s,
        &user,
        "Users",
        &format!(
            "<h1>Members</h1><table><tr><th>Email</th><th>Role</th><th>Tenants</th></tr>{rows}</table>\
             <h2>Create user</h2>\
             <form class=row method=post action=/users>email <input name=email type=email required> \
             password <input name=password type=password required> \
             <label><input type=checkbox name=superadmin value=1> superadmin</label> <button>Create</button></form>\
             <h2>Grant tenant access</h2>\
             <form class=row method=post action=/users/grant>email <input name=email type=email required> \
             tenant <input name=tenant placeholder=org-slug required> \
             <select name=role><option value=member>member</option><option value=admin>admin</option></select> \
             <button>Grant</button></form>"
        ),
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

    let mut rows = String::new();
    for j in &jobs {
        // Status as a tone badge; a backing-off pending job reads as "retrying",
        // a terminal failure as red (with its error) — matching the lifecycle ladder.
        let badge = match j.status.as_str() {
            "ready" => "<span class='badge ok'>ready</span>".to_owned(),
            "running" => "<span class='badge blue'>running</span>".to_owned(),
            "failed" => "<span class='badge held'>failed</span>".to_owned(),
            _ if j.attempts > 1 => {
                format!("<span class='badge amber'>retrying · attempt {}</span>", j.attempts)
            }
            _ => "<span class='badge slate'>queued</span>".to_owned(),
        };
        let kind = match j.kind.as_str() {
            "mirror_upstream" => "upstream sync",
            "mirror_package" => "package mirror",
            "resolve_closure" => "dependency resolve",
            other => other,
        };
        let repo = j.repo.as_deref().unwrap_or("—");
        let err = match (&j.last_error, j.status.as_str()) {
            (Some(e), "failed") => format!("<div class=muted style=\"font-size:11.5px\">{}</div>", esc(e)),
            _ => String::new(),
        };
        let _ = write!(
            rows,
            "<tr><td>{badge}</td><td>{kind}</td><td class=mono>{target}{err}</td><td class=mono>{repo}</td>\
             <td class=muted>{updated}</td></tr>",
            target = esc(&j.target),
            repo = esc(repo),
            updated = esc(&j.updated),
        );
    }
    if jobs.is_empty() {
        rows = "<tr><td colspan=5 class=muted>No background jobs yet. Sync an upstream to see activity here.</td></tr>".into();
    }
    Ok(shell(
        &s,
        &user,
        "Activity",
        &format!(
            "<h1>Activity</h1>\
             <p class=muted>Background mirror jobs — newest first. Pending jobs that keep failing back off and retry; \
             a terminal failure stops and (for a package) flags it broken.</p>\
             <table><tr><th>Status</th><th>Job</th><th>Target</th><th>Repo</th><th>Updated</th></tr>{rows}</table>"
        ),
    ))
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

// ----- index + org/repo creation -----

async fn index(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
) -> Result<Html<String>, StatusCode> {
    let orgs = s.catalog.list_organizations().await.map_err(e500)?;
    let repos = s.catalog.list_repositories().await.map_err(e500)?;
    let attention: HashSet<(Uuid, i64)> = s
        .catalog
        .attention_counts()
        .await
        .map_err(e500)?
        .into_iter()
        .collect();
    let broken_for = |repo_id: Uuid| attention.iter().find(|(id, _)| *id == repo_id).map(|(_, n)| *n);

    let can_create_repo = orgs.iter().any(|o| user.can_admin(o.id));
    let new_org_btn = if user.is_superadmin {
        "<a href=/orgs/new><button>New organization</button></a> "
    } else {
        ""
    };
    let new_repo_btn = if can_create_repo {
        "<a href=/repos/new><button class=primary>+ New repository</button></a>"
    } else {
        ""
    };
    let mut body = format!(
        "<div class=toolbar><h1>Repositories</h1><div>{new_org_btn}{new_repo_btn}</div></div>"
    );
    let visible: Vec<_> = orgs.iter().filter(|o| user.can(o.id)).collect();
    if visible.is_empty() {
        body.push_str(
            "<p class=muted>No organizations you can access yet.</p>",
        );
    }
    for o in &visible {
        let label = o
            .name
            .as_deref()
            .filter(|n| !n.is_empty())
            .map(|n| format!(" <span class=muted>({})</span>", esc(n)))
            .unwrap_or_default();
        let _ = write!(
            body,
            "<h2><a href=\"/o/{sl}\">{sl}</a>{label} \
             <a class=muted style=\"font-size:.8rem\" href=\"/o/{sl}/settings\">settings</a></h2>",
            sl = esc(&o.slug),
        );
        let org_repos: Vec<_> = repos.iter().filter(|r| r.org_id == o.id).collect();
        if org_repos.is_empty() {
            let cta = if user.can_admin(o.id) {
                format!(" — <a href=\"/repos/new?org={}\">create one</a>", esc(&o.slug))
            } else {
                String::new()
            };
            let _ = write!(body, "<p class=muted>No repositories yet{cta}.</p>");
            continue;
        }
        body.push_str(
            "<table><tr><th>Repository</th><th>Update mode</th><th>Cooldown (days)</th></tr>",
        );
        for r in org_repos {
            let att = match broken_for(r.id) {
                Some(n) => format!(" <span class='badge amber'>⚠ {n} can't sync</span>"),
                None => String::new(),
            };
            let _ = write!(
                body,
                "<tr><td><a href=\"/r/{o}/{rp}\">{rp}</a>{att}</td><td>{mode}</td><td>{cd}</td></tr>",
                o = esc(&r.org),
                rp = esc(&r.repo),
                mode = esc(&r.update_mode),
                cd = r.cooldown_days,
            );
        }
        body.push_str("</table>");
    }
    Ok(shell(&s, &user, "Repositories", &body))
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
    let admin_orgs: Vec<_> = orgs.iter().filter(|o| user.can_admin(o.id)).collect();
    if admin_orgs.is_empty() {
        let hint = if user.is_superadmin {
            "<p><a href=/orgs/new>Create an organization</a> first.</p>"
        } else {
            "<p class=muted>You don't administer any organization yet — ask an org admin.</p>"
        };
        return Ok(shell(
            &s,
            &user,
            "New repository",
            &format!("<h1>New repository</h1>{hint}<p><a href=/>← back</a></p>"),
        ));
    }
    let mut options = String::new();
    for o in &admin_orgs {
        let sel = if q.org.as_deref() == Some(o.slug.as_str()) {
            " selected"
        } else {
            ""
        };
        let _ = write!(options, "<option value=\"{sl}\"{sel}>{sl}</option>", sl = esc(&o.slug));
    }
    Ok(shell(
        &s,
        &user,
        "New repository",
        &format!(
            "<h1>New repository</h1>\
             <p class=muted>A repository serves a Composer registry — mirror packages into it, gate \
             versions by policy, and hand out install tokens.</p>\
             <form class=row method=post action=/repos>\
             <p>Organization <select name=org required>{options}</select></p>\
             <p>Repository name <input name=repo placeholder=\"e.g. web\" required></p>\
             <button class=primary>Create repository</button></form>\
             <p><a href=/>← cancel</a></p>"
        ),
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
        "<h1>New organization</h1>\
         <p class=muted>An organization (tenant) owns repositories, members, and its own SSO.</p>\
         <form class=row method=post action=/orgs>\
         <p>Slug <input name=slug placeholder=\"acme\" required> <span class=muted>(used in URLs)</span></p>\
         <p>Display name <input name=name placeholder=\"Acme Inc\"></p>\
         <button class=primary>Create organization</button></form>\
         <p><a href=/>← cancel</a></p>",
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
    if s.catalog.org_slug_retired(f.slug.trim()).await.map_err(e500)? {
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
    if s.catalog.repo_slug_retired(org.id, f.repo.trim()).await.map_err(e500)? {
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
}

#[allow(clippy::too_many_lines)] // one big page builder; clearer kept together
async fn repo_page(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, repo)): Path<(String, String)>,
    Query(q): Query<PageQuery>,
) -> Result<Html<String>, StatusCode> {
    // Paginate the (potentially long) packages & versions list.
    const PER_PAGE: i64 = 50;
    let summary = lookup(&s, &user, &org, &repo).await?;
    let total_versions = s.catalog.count_package_versions(summary.id).await.map_err(e500)?;
    let last_page = ((total_versions + PER_PAGE - 1) / PER_PAGE).max(1);
    let page = q.page.unwrap_or(1).clamp(1, last_page);
    let versions = s
        .catalog
        .admin_package_versions(summary.id, PER_PAGE, (page - 1) * PER_PAGE)
        .await
        .map_err(e500)?;
    let tokens = s.catalog.list_tokens(summary.id).await.map_err(e500)?;
    let licenses = s.catalog.list_licenses(summary.id).await.map_err(e500)?;
    let grants = s.catalog.list_grants(summary.id).await.map_err(e500)?;
    let upstreams = s.catalog.list_upstreams(summary.id).await.map_err(e500)?;
    let packages = s.catalog.list_packages(summary.id).await.map_err(e500)?;
    let dep_plan = s.catalog.list_dependency_plan(summary.id).await.map_err(e500)?;
    let slug = format!("{}/{}", esc(&org), esc(&repo));

    let opt = |v: &str| {
        let sel = if v == summary.update_mode {
            " selected"
        } else {
            ""
        };
        format!("<option{sel}>{v}</option>")
    };
    let policy = format!(
        "<h2>Update policy</h2><form class=inline method=post action=\"/r/{slug}/policy\">\
         mode <select name=mode>{auto}{manual}{delayed}</select> \
         cooldown days <input name=cooldown_days type=number value={cd} min=0 style=width:5rem> \
         <button>Save</button></form>",
        auto = opt("auto"),
        manual = opt("manual"),
        delayed = opt("delayed"),
        cd = summary.cooldown_days,
    );

    let mut rows = String::new();
    for v in &versions {
        // The effective gated state, matching what serving hides (visible_versions):
        // yanked/held hide unconditionally; approved overrides mode/cooldown;
        // otherwise auto=live, manual=pending, delayed=cooldown-countdown.
        let badge = if v.yanked {
            "<span class='badge held'>yanked</span>".to_owned()
        } else if v.held {
            "<span class='badge held'>held</span>".to_owned()
        } else if v.approved {
            "<span class='badge ok'>approved</span>".to_owned()
        } else {
            match summary.update_mode.as_str() {
                "manual" => "<span class='badge amber'>pending approval</span>".to_owned(),
                "delayed" => match v.cooldown_days_left {
                    None => "<span class='badge amber'>pending</span>".to_owned(),
                    Some(0) => "<span class='badge ok'>live</span>".to_owned(),
                    Some(n) => format!("<span class='badge blue'>cooldown · {n}d left</span>"),
                },
                _ => "<span class='badge ok'>live</span>".to_owned(),
            }
        };
        let (hold_label, hold_action) = if v.held {
            ("Unhold", "unhold")
        } else {
            ("Hold", "hold")
        };
        let (yank_label, yank_action) = if v.yanked {
            ("Unyank", "unyank")
        } else {
            ("Yank", "yank")
        };
        let _ = write!(
            rows,
            "<tr><td>{pkg}</td><td>{ver} <span class=muted>{norm}</span></td><td>{stab}</td>\
             <td>{badge} <span class=muted>{rel}</span></td><td>\
             <form class=inline method=post action=\"/r/{slug}/version\">\
             <input type=hidden name=package value=\"{pkg}\"><input type=hidden name=normalized value=\"{norm}\">\
             <button name=action value={hold_action}>{hold_label}</button> \
             <button name=action value=approve>Approve</button> \
             <button name=action value={yank_action}>{yank_label}</button></form></td></tr>",
            pkg = esc(&v.package),
            ver = esc(&v.version),
            norm = esc(&v.normalized_version),
            stab = esc(&v.stability),
            rel = esc(v.released_at.as_deref().unwrap_or("")),
        );
    }
    if versions.is_empty() && total_versions == 0 {
        rows = "<tr><td colspan=5 class=muted>No packages yet. Mirror one with <code>sconce mirror</code>.</td></tr>".into();
    }
    let pager = if total_versions == 0 {
        String::new()
    } else {
        paginator("versions", total_versions, page, PER_PAGE, &format!("/r/{slug}"))
    };

    // Package health: only the actionable ones (broken or archived). Already-
    // mirrored versions keep serving regardless — this is about new versions.
    let mut health_rows = String::new();
    let broken_count = packages
        .iter()
        .filter(|p| p.sync_health == "broken" && !p.archived)
        .count();
    for p in packages.iter().filter(|p| p.archived || p.sync_health == "broken") {
        let (badge, action, label) = if p.archived {
            (
                "<span class='badge slate'>archived · frozen</span>".to_owned(),
                "unarchive",
                "Un-archive",
            )
        } else {
            (
                format!(
                    "<span class='badge amber'>broken</span> <span class=muted>{}</span>",
                    esc(p.broken_reason.as_deref().unwrap_or("?"))
                ),
                "archive",
                "Archive",
            )
        };
        let last = p.last_success_at.as_deref().unwrap_or("never");
        let _ = write!(
            health_rows,
            "<tr><td>{pkg}</td><td>{badge}</td><td class=muted>last sync {last}</td><td>\
             <form class=inline method=post action=\"/r/{slug}/package/archive\">\
             <input type=hidden name=package value=\"{pkg}\">\
             <button name=action value={action}>{label}</button></form></td></tr>",
            pkg = esc(&p.name),
            last = esc(last),
        );
    }
    // Repo-level needs-attention roll-up, shown up top (links to Package health).
    let attention_banner = if broken_count > 0 {
        format!(
            "<p class=banner>⚠ {broken_count} package(s) can't sync — they keep serving their existing \
             versions, but won't get new ones until fixed. See <a href=\"#health\">Package health</a>.</p>"
        )
    } else {
        String::new()
    };
    let health_section = if health_rows.is_empty() {
        String::new()
    } else {
        let note = if broken_count > 0 {
            format!("<p class=muted>{broken_count} package(s) can't sync (still serving their existing versions). Archive to acknowledge and silence.</p>")
        } else {
            String::new()
        };
        format!(
            "<h2 id=health>Package health</h2>{note}<table>\
             <tr><th>Package</th><th>State</th><th>Last sync</th><th>Actions</th></tr>{health_rows}</table>"
        )
    };

    let mut grant_rows = String::new();
    for g in &grants {
        let _ = write!(
            grant_rows,
            "<li>{pkg} <span class=muted>from {o}/{r}</span></li>",
            pkg = esc(&g.package),
            o = esc(&g.source_org),
            r = esc(&g.source_repo),
        );
    }
    let grants_section = format!(
        "<h2>Granted packages</h2><ul>{rows}</ul>\
         <form class=row method=post action=\"/r/{slug}/grant\">grant <input name=package placeholder=\"vendor/name\" required> \
         from <input name=from placeholder=\"org/repo\" required> <button>Grant</button></form>",
        rows = if grant_rows.is_empty() {
            "<li class=muted>none</li>".into()
        } else {
            grant_rows
        },
    );

    let up_rows = upstreams.iter().fold(String::new(), |mut acc, u| {
        use std::fmt::Write as _;
        let label = u.label.as_deref().map_or(String::new(), esc);
        let cred = if u.has_credential { "auth" } else { "—" };
        // Show the latest job status; on failure, surface the error on hover.
        let status = match (u.job_status.as_deref(), u.job_error.as_deref()) {
            (None, _) => "<span class=muted>never synced</span>".to_owned(),
            (Some("failed"), err) => format!(
                "<span style=\"color:#a12\" title=\"{}\">failed</span>",
                esc(err.unwrap_or(""))
            ),
            (Some(s), _) => esc(s),
        };
        let base_cell = match u.package_filter.as_deref() {
            Some(p) => format!("{}<br><span class=muted>match {}</span>", esc(&u.base), esc(p)),
            None => esc(&u.base),
        };
        let _ = write!(
            acc,
            "<tr><td>{kind}</td><td>{vis}</td><td>{base_cell}</td><td>{label}</td><td>{cred}</td>\
             <td>{status}</td>\
             <td><form class=inline method=post action=\"/r/{slug}/upstream/sync\">\
             <input type=hidden name=id value=\"{id}\"><button>Sync</button></form> \
             <form class=inline method=post action=\"/r/{slug}/upstream/remove\" \
             onsubmit=\"return confirm('Remove this upstream?')\">\
             <input type=hidden name=id value=\"{id}\"><button>Remove</button></form></td></tr>",
            kind = esc(&u.kind),
            vis = esc(&u.visibility),
            id = u.id,
        );
        acc
    });
    let up_rows = if up_rows.is_empty() {
        "<tr><td colspan=7 class=muted>none</td></tr>".to_owned()
    } else {
        up_rows
    };
    let cred_note = if s.secret_key.is_some() {
        "Credential is stored encrypted."
    } else {
        "Set SCONCE_SECRET_KEY to store a credential; without it only public/unauthed upstreams work."
    };
    let upstreams_section = format!(
        "<h2>Upstreams</h2>\
         <table><tr><th>Kind</th><th>Visibility</th><th>URL</th><th>Label</th><th>Cred</th><th>Status</th><th></th></tr>{up_rows}</table>\
         <form class=row method=post action=\"/r/{slug}/upstream\">\
         <select name=kind><option value=git>git</option><option value=composer>composer</option></select> \
         <select name=visibility id=upvis \
           onchange=\"document.getElementById('credfields').style.display=this.value=='private'?'':'none'\">\
           <option value=public>public</option><option value=private>private</option></select> \
         url <input name=base placeholder=\"https://host/org/repo.git\" required> \
         label <input name=label> \
         match <input name=package_filter placeholder=\"^vendor/ (composer)\"> \
         <span id=credfields style=\"display:none\">\
           <select name=credential_type>\
             <option value=basic>basic (user:token)</option>\
             <option value=github>github token</option>\
             <option value=gitlab>gitlab token</option>\
             <option value=bearer>bearer header</option></select> \
           credential <input name=credential placeholder=\"token or user:pass\">\
         </span> \
         <button>Add upstream</button></form>\
         <p class=muted>{cred_note} Credentials apply to private upstreams only.</p>"
    );

    let dep_rows = dep_plan.iter().fold(String::new(), |mut acc, d| {
        use std::fmt::Write as _;
        let by = d.required_by.as_deref().map_or(String::new(), esc);
        let status = match d.status.as_str() {
            "missing" => "<span style=\"color:#a12\">missing</span>".to_owned(),
            "present" => "<span class=muted>present</span>".to_owned(),
            other => esc(other),
        };
        // Only resolvable deps can be added (they have a resolver upstream).
        let action = if d.status.starts_with("resolvable") {
            format!(
                "<form class=inline method=post action=\"/r/{slug}/deps/add\">\
                 <input type=hidden name=package value=\"{}\"><button>Add</button></form>",
                esc(&d.name)
            )
        } else {
            String::new()
        };
        let _ = write!(
            acc,
            "<tr><td>{status}</td><td>{}</td><td class=muted>{by}</td><td>{action}</td></tr>",
            esc(&d.name)
        );
        acc
    });
    let dep_rows = if dep_rows.is_empty() {
        "<tr><td colspan=4 class=muted>no plan yet — resolve to compute it</td></tr>".to_owned()
    } else {
        dep_rows
    };
    let deps_section = format!(
        "<h2>Dependency plan</h2>\
         <form class=inline method=post action=\"/r/{slug}/deps/resolve\"><button>Resolve dependencies</button></form>\
         <span class=muted> — computes the full closure (background); add the ones you want.</span>\
         <table><tr><th>Status</th><th>Package</th><th>Required by</th><th></th></tr>{dep_rows}</table>"
    );

    let mut lic_rows = String::new();
    for l in &licenses {
        // Per-license supply-chain policy, keyed by id (a conservative buyer can
        // be served "delayed + cooldown" while others see the repo default).
        let m = l.policy.update_mode.as_deref().unwrap_or("");
        let mode_opt = |v: &str, text: &str| {
            let sel = if v == m { " selected" } else { "" };
            format!("<option value=\"{v}\"{sel}>{text}</option>")
        };
        let _ = write!(
            lic_rows,
            "<tr><td>{buyer}</td><td>{status}</td><td>{pkgs}</td><td>\
             <form class=inline method=post action=\"/r/{slug}/license/policy\">\
             <input type=hidden name=id value=\"{id}\">\
             <select name=mode>{inherit}{auto}{manual}{delayed}</select>\
             <input name=cooldown_days type=number min=0 placeholder=cooldown style=\"width:5em\" value=\"{cd}\">\
             <button>Set</button></form></td></tr>",
            buyer = esc(l.buyer.as_deref().unwrap_or("—")),
            status = esc(&l.status),
            pkgs = esc(&l.packages.join(", ")),
            id = l.id,
            inherit = mode_opt("", "inherit"),
            auto = mode_opt("auto", "auto"),
            manual = mode_opt("manual", "manual"),
            delayed = mode_opt("delayed", "delayed"),
            cd = l.policy.cooldown_days.map_or_else(String::new, |d| d.to_string()),
        );
    }
    if licenses.is_empty() {
        lic_rows = "<tr><td colspan=4 class=muted>none</td></tr>".into();
    }
    let licenses_section = format!(
        "<h2>License keys</h2><table><tr><th>Buyer</th><th>Status</th><th>Entitled packages</th><th>Policy</th></tr>{lic_rows}</table>\
         <form class=row method=post action=\"/r/{slug}/license\">buyer <input name=buyer> \
         packages <input name=packages placeholder=\"vendor/a vendor/b\" required> <button>Issue license</button></form>"
    );

    let token_rows = tokens.iter().fold(String::new(), |mut acc, t| {
        use std::fmt::Write as _;
        let name = t.label.as_deref().map_or("<em>unnamed</em>".to_owned(), esc);
        let expiry = match (t.expires.as_deref(), t.expired) {
            (Some(d), true) => format!("<span style=\"color:#a12\">expired {}</span>", esc(d)),
            (Some(d), false) => esc(d),
            (None, _) => "never".to_owned(),
        };
        let last = t.last_used.as_deref().map_or("never".to_owned(), esc);
        // Per-credential supply-chain policy: an inline form for labelled tokens
        // (the override is keyed by label); unnamed tokens just show "inherit".
        let policy_cell = if let Some(label) = &t.label {
            let m = t.policy.update_mode.as_deref().unwrap_or("");
            let mode_opt = |v: &str, text: &str| {
                let sel = if v == m { " selected" } else { "" };
                format!("<option value=\"{v}\"{sel}>{text}</option>")
            };
            format!(
                "<form class=inline method=post action=\"/r/{slug}/token/policy\">\
                 <input type=hidden name=label value=\"{lbl}\">\
                 <select name=mode>{inherit}{auto}{manual}{delayed}</select>\
                 <input name=cooldown_days type=number min=0 placeholder=cooldown style=\"width:5em\" value=\"{cd}\">\
                 <button>Set</button></form>",
                lbl = esc(label),
                inherit = mode_opt("", "inherit"),
                auto = mode_opt("auto", "auto"),
                manual = mode_opt("manual", "manual"),
                delayed = mode_opt("delayed", "delayed"),
                cd = t.policy.cooldown_days.map_or_else(String::new, |d| d.to_string()),
            )
        } else {
            "<span class=muted>inherit</span>".to_owned()
        };
        let origin_tone = match t.origin.as_str() {
            "ci" => "violet",
            "session" => "blue",
            _ => "slate",
        };
        let origin = format!("<span class='badge {origin_tone}'>{}</span>", esc(&t.origin));
        let _ = write!(
            acc,
            "<tr><td>{name}</td><td>{origin}</td><td>{created}</td><td>{last}</td><td>{expiry}</td>\
             <td>{policy_cell}</td>\
             <td><form class=inline method=post action=\"/r/{slug}/token/revoke\" \
             onsubmit=\"return confirm('Revoke this token? Installs using it will stop working.')\">\
             <input type=hidden name=id value=\"{id}\"><button>Revoke</button></form></td></tr>",
            created = esc(&t.created),
            id = t.id,
        );
        acc
    });
    // Overview hero: the copy-paste install instructions (the brief's hero).
    let install_hero = format!(
        "<div class=hero><h2>Install</h2>\
         <pre>composer config repositories.{r} composer {base}/{slug}\ncomposer require &lt;package&gt;</pre>\
         <p class=muted style=\"margin:.6rem 0 0\">Authenticate with a token (under <a href=\"#tokens\">Tokens</a>); \
         it's the http-basic <em>password</em>.</p></div>",
        r = esc(&repo),
        base = esc(s.public_base_url.trim_end_matches('/')),
    );
    let tokens_section = format!(
        "<h2 id=tokens>Tokens</h2>\
         <table><tr><th>Name</th><th>Origin</th><th>Created</th><th>Last used</th><th>Expires</th><th>Policy</th><th></th></tr>{token_rows}</table>\
         <p class=muted>Policy tightens the repo's supply-chain gate for that credential only (e.g. <code>delayed</code> + cooldown for a conservative buyer); it can never loosen it.</p>\
         <form class=row method=post action=\"/r/{slug}/token\">\
         name <input name=label placeholder=\"e.g. ci-deploy\"> \
         expires in <input name=expires_days type=number min=1 placeholder=days style=\"width:6em\"> days \
         <button>Create token</button></form>"
    );

    // Members get a read-only view: hide every management form on this page
    // (scoped so the nav's log-out stays). Mutations are also enforced server-side.
    let (ro_open, ro_close) = if user.can_admin(summary.org_id) {
        (String::new(), String::new())
    } else {
        (
            "<style>.ro form{display:none}</style>\
             <p class=banner>Read-only (member) access — ask an org admin to make changes.</p>\
             <div class=ro>"
                .to_owned(),
            "</div>".to_owned(),
        )
    };
    // Overview header badges: visibility + overall sync status (from upstreams).
    let repo_cfg = s.catalog.repo_settings(summary.id).await.map_err(e500)?;
    let vis_badge = if repo_cfg.allow_private_packages {
        "<span class='badge slate'>private packages</span>"
    } else {
        "<span class='badge blue'>public-only</span>"
    };
    let has_status = |st: &str| upstreams.iter().any(|u| u.job_status.as_deref() == Some(st));
    let sync_badge = if upstreams.is_empty() {
        "<span class='badge slate'>no upstreams</span>"
    } else if has_status("failed") {
        "<span class='badge held'>sync failing</span>"
    } else if has_status("running") || has_status("pending") {
        "<span class='badge blue'>syncing</span>"
    } else {
        "<span class='badge ok'>synced</span>"
    };
    let broken_note = if broken_count > 0 {
        format!(" · <span style=\"color:#a82c20\">{broken_count} can't sync</span>")
    } else {
        String::new()
    };
    let summary = format!(
        "{} package(s) · {total_versions} version(s){broken_note}",
        packages.len()
    );

    Ok(shell(
        &s,
        &user,
        &slug,
        &format!(
            "<div class=repohead><h1>{slug}</h1> {vis_badge} {sync_badge} \
             <a class=muted style=\"font-size:.85rem\" href=\"/r/{slug}/settings\">settings</a></div>\
             {attention_banner}<p class=summary>{summary}</p>{install_hero}\
             {ro_open}{policy}\
             <h2>Packages &amp; versions</h2><table>\
             <tr><th>Package</th><th>Version</th><th>Stability</th><th>State</th><th>Actions</th></tr>{rows}</table>{pager}\
             {health_section}{upstreams_section}{deps_section}{grants_section}{licenses_section}{tokens_section}{ro_close}"
        ),
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
        "unyank" => s.catalog.unyank_version(id, &f.package, &f.normalized).await,
        _ => return Err(StatusCode::BAD_REQUEST),
    }
    .map_err(e500)?;
    Ok(Redirect::to(&format!("/r/{org}/{repo}")))
}

#[derive(Deserialize)]
struct PackageActionForm {
    package: String,
    action: String,
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

#[derive(Deserialize)]
struct GrantForm {
    package: String,
    from: String,
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
    credential_type: Option<String>,
    package_filter: Option<String>,
}

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
    let package_filter = f
        .package_filter
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty());
    // A composer upstream must be scoped — refuse to register one that would
    // mirror the whole registry on sync.
    if f.kind == "composer" && package_filter.is_none() {
        let slug = format!("{}/{}", esc(&org), esc(&repo));
        return Ok(shell(
            &s,
            &user,
            "Upstream not added",
            &format!(
                "<h1>Upstream not added</h1>\
                 <p>A composer upstream needs a <strong>match</strong> filter (a regex like \
                 <code>^vendor/</code>) — an unfiltered registry mirror is refused.</p>\
                 <p><a href=\"/r/{slug}\">← back to {slug}</a></p>"
            ),
        )
        .into_response());
    }
    let label = f.label.as_deref().map(str::trim).filter(|l| !l.is_empty());
    // Public upstreams carry no credential — ignore any submitted one (so no key
    // is needed for a public upstream even if the field leaked a value).
    let credential = if matches!(visibility, sconce_catalog::Visibility::Public) {
        None
    } else {
        f.credential
            .as_deref()
            .map(str::trim)
            .filter(|c| !c.is_empty())
    };

    // Encrypt the credential if one was given; needs the key.
    let ciphertext = if let Some(c) = credential {
        let Some(key) = &s.secret_key else {
            // No key configured — tell the user instead of silently dropping it.
            let slug = format!("{}/{}", esc(&org), esc(&repo));
            return Ok(shell(
                &s,
                &user,
                "Upstream not added",
                &format!(
                    "<h1>Upstream not added</h1>\
                     <p>A credential was provided but <code>SCONCE_SECRET_KEY</code> is not \
                     set, so it can't be stored encrypted. Add a credential-free upstream, or \
                     start the UI with that key set.</p>\
                     <p><a href=\"/r/{slug}\">← back to {slug}</a></p>"
                ),
            )
            .into_response());
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
    // Store the composer package filter (required above for composer kind).
    if let Some(p) = package_filter {
        s.catalog
            .set_upstream_filter(repo_id, id, Some(p))
            .await
            .map_err(e500)?;
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
    let id = f.id.parse::<uuid::Uuid>().map_err(|_| StatusCode::BAD_REQUEST)?;
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
    let id = f.id.parse::<uuid::Uuid>().map_err(|_| StatusCode::BAD_REQUEST)?;
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
    let slug = format!("{}/{}", esc(&org), esc(&repo));
    Ok(shell(
        &s,
        &user,
        "License created",
        &format!(
            "<h1>License created</h1><p>Entitled to: {pkgs}. Give this key to the buyer — \
             it won't be shown again.</p><pre>{key}</pre><p><a href=\"/r/{slug}\">← back to {slug}</a></p>",
            pkgs = esc(&packages.join(", ")),
            key = esc(&key),
        ),
    ))
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
            let slug = format!("{}/{}", esc(&org), esc(&repo));
            return Ok(shell(
                &s,
                &user,
                "Token not created",
                &format!(
                    "<h1>Token not created</h1><p>{}</p>\
                     <p><a href=\"/r/{slug}\">← back to {slug}</a></p>",
                    esc(&reason),
                ),
            ));
        }
        Err(sconce_catalog::CreateTokenError::Db(e)) => return Err(e500(e)),
    };
    let slug = format!("{}/{}", esc(&org), esc(&repo));
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
    Ok(shell(
        &s,
        &user,
        "Token created",
        &format!(
            "<h1>Token created</h1>\
             <p>Store it now — it won't be shown again.</p>\
             <pre>{tok}</pre>\
             <h2>Install in Composer</h2>\
             <p>Add the repository, store the token (the token is the password — \
             the username is ignored), then require a package:</p>\
             <pre>composer config repositories.{r} composer {base}/{slug}\n\
             composer config --auth http-basic.{host} token {tok}\n\
             composer require &lt;vendor/package&gt;</pre>\
             <p class=muted>The auth line writes to <code>auth.json</code>. Use \
             <code>--global</code> to reuse the token across projects, or set the \
             <code>COMPOSER_AUTH</code> env var in CI instead of committing it.</p>\
             <p><a href=\"/r/{slug}\">← back to {slug}</a></p>",
            tok = esc(&token),
            r = esc(&repo),
            base = esc(base),
            host = esc(host),
        ),
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
    let token_id = f.id.parse::<uuid::Uuid>().map_err(|_| StatusCode::BAD_REQUEST)?;
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
    let policy = sconce_catalog::PolicyOverride { update_mode, cooldown_days };
    s.catalog
        .set_token_policy(repo_id, &f.label, &policy)
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
    let license_id = f.id.parse::<uuid::Uuid>().map_err(|_| StatusCode::BAD_REQUEST)?;
    let update_mode = match f.mode.as_str() {
        "auto" | "manual" | "delayed" => Some(f.mode.clone()),
        "" => None,
        _ => return Err(StatusCode::BAD_REQUEST),
    };
    let cooldown_days = match f.cooldown_days.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(d) => Some(d.parse::<i32>().map_err(|_| StatusCode::BAD_REQUEST)?),
    };
    let policy = sconce_catalog::PolicyOverride { update_mode, cooldown_days };
    s.catalog
        .set_license_policy(repo_id, license_id, &policy)
        .await
        .map_err(e500)?;
    Ok(Redirect::to(&format!("/r/{org}/{repo}")))
}
