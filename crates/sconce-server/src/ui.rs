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
use axum::extract::{Extension, Form, Path, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use base64::Engine as _;
use sconce_catalog::Catalog;
use serde::Deserialize;
use uuid::Uuid;

#[derive(Clone)]
struct Ui {
    catalog: Catalog,
    public_base_url: String,
    /// Single-tenant mode: no accounts, gated by `admin_password` (or open).
    single_tenant: bool,
    admin_password: Option<String>,
}

/// The viewer's access, resolved per request.
#[derive(Clone)]
struct CurrentUser {
    is_superadmin: bool,
    tenants: HashSet<Uuid>,
}

impl CurrentUser {
    fn all_access() -> Self {
        Self {
            is_superadmin: true,
            tenants: HashSet::new(),
        }
    }
    fn can(&self, org_id: Uuid) -> bool {
        self.is_superadmin || self.tenants.contains(&org_id)
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
    };
    Router::new()
        .route("/", get(index))
        .route("/login", get(login_form).post(login))
        .route("/logout", post(logout))
        .route("/users", get(users_page).post(create_user))
        .route("/users/grant", post(grant_tenant))
        .route("/orgs", post(create_org))
        .route("/repos", post(create_repo))
        .route("/r/{org}/{repo}", get(repo_page))
        .route("/r/{org}/{repo}/policy", post(set_policy))
        .route("/r/{org}/{repo}/version", post(version_action))
        .route("/r/{org}/{repo}/token", post(create_token))
        .route("/r/{org}/{repo}/license", post(create_license))
        .route("/r/{org}/{repo}/grant", post(create_grant))
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
    if s.single_tenant {
        if let Some(expected) = &s.admin_password
            && basic_password(req.headers()).as_deref() != Some(expected.as_str())
        {
            return basic_challenge();
        }
        req.extensions_mut().insert(CurrentUser::all_access());
        return next.run(req).await;
    }

    if req.uri().path() == "/login" {
        return next.run(req).await;
    }
    let user = match session_cookie(req.headers()) {
        Some(token) => s.catalog.resolve_session(&token).await.ok().flatten(),
        None => None,
    };
    match user {
        Some(u) => {
            req.extensions_mut().insert(CurrentUser {
                is_superadmin: u.is_superadmin,
                tenants: u.tenant_org_ids.into_iter().collect(),
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

fn page(title: &str, body: &str) -> Html<String> {
    Html(format!(
        "<!doctype html><html><head><meta charset=utf-8><title>{title} · sconce</title>\
         <style>\
         body{{font:15px/1.5 system-ui,sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem;color:#222}}\
         h1,h2{{font-weight:600}} h2{{margin-top:2rem}} a{{color:#2456a6;text-decoration:none}} a:hover{{text-decoration:underline}}\
         table{{border-collapse:collapse;width:100%;margin:1rem 0}} th,td{{text-align:left;padding:.4rem .6rem;border-bottom:1px solid #eee}}\
         .badge{{display:inline-block;padding:.05rem .4rem;border-radius:.4rem;font-size:.8rem}}\
         .held{{background:#fde2e2;color:#a12}} .ok{{background:#e2f5e6;color:#161}} .muted{{color:#888}}\
         form.inline{{display:inline}} form.row{{margin:.4rem 0}} button{{font:inherit;cursor:pointer}}\
         code,pre{{background:#f6f7f9;border-radius:.3rem}} pre{{padding:.8rem;overflow:auto}} input,select{{font:inherit;padding:.2rem}}\
         nav{{float:right}}\
         </style></head><body><nav class=muted>{nav}</nav><p class=muted><a href=/>sconce admin</a></p>{body}</body></html>",
        nav = "",
    ))
}

// Header nav: a logout + users link (only meaningful in multi-tenant).
fn nav(s: &Ui, user: &CurrentUser) -> String {
    if s.single_tenant {
        return String::new();
    }
    let users = if user.is_superadmin {
        " · <a href=/users>users</a>"
    } else {
        ""
    };
    format!("<form class=inline method=post action=/logout><button>log out</button></form>{users}")
}

fn shell(s: &Ui, user: &CurrentUser, title: &str, body: &str) -> Html<String> {
    let mut html = page(title, body).0;
    // Inject the nav (page() leaves it empty so we can build it per-request).
    html = html.replacen(
        "<nav class=muted></nav>",
        &format!("<nav class=muted>{}</nav>", nav(s, user)),
        1,
    );
    Html(html)
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

// ----- login -----

async fn login_form() -> Html<String> {
    page(
        "Sign in",
        "<h1>Sign in</h1><form method=post action=/login>\
         <p>email <input name=email type=email required></p>\
         <p>password <input name=password type=password required></p>\
         <button>Sign in</button></form>",
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
        return Ok(page(
            "Sign in",
            "<h1>Sign in</h1><p class=held>Invalid email or password.</p>\
             <p><a href=/login>try again</a></p>",
        )
        .into_response());
    };
    let token = s.catalog.create_session(user_id, 7).await.map_err(e500)?;
    let cookie = format!("sconce_session={token}; HttpOnly; Path=/; SameSite=Lax; Max-Age=604800");
    Ok(redirect_with_cookie("/", &cookie))
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
        let _ = write!(
            rows,
            "<tr><td>{email}</td><td>{sa}</td><td>{tenants}</td></tr>",
            email = esc(&u.email),
            sa = if u.is_superadmin { "yes" } else { "" },
            tenants = esc(&u.tenants.join(", ")),
        );
    }
    Ok(shell(
        &s,
        &user,
        "Users",
        &format!(
            "<h1>Users</h1><table><tr><th>Email</th><th>Superadmin</th><th>Tenants</th></tr>{rows}</table>\
             <h2>Create user</h2>\
             <form class=row method=post action=/users>email <input name=email type=email required> \
             password <input name=password type=password required> \
             <label><input type=checkbox name=superadmin value=1> superadmin</label> <button>Create</button></form>\
             <h2>Grant tenant access</h2>\
             <form class=row method=post action=/users/grant>email <input name=email type=email required> \
             tenant <input name=tenant placeholder=org-slug required> <button>Grant</button></form>"
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
}

async fn grant_tenant(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Form(f): Form<GrantTenantForm>,
) -> Result<Redirect, StatusCode> {
    if !user.is_superadmin {
        return Err(StatusCode::FORBIDDEN);
    }
    s.catalog
        .add_user_to_tenant(&f.email, &f.tenant)
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

    let mut body = String::from("<h1>Organizations &amp; repositories</h1>");
    let visible: Vec<_> = orgs.iter().filter(|o| user.can(o.id)).collect();
    if visible.is_empty() {
        body.push_str("<p class=muted>No tenants you can access yet.</p>");
    }
    for o in &visible {
        let label = o
            .name
            .as_deref()
            .filter(|n| !n.is_empty())
            .map(|n| format!(" <span class=muted>({})</span>", esc(n)))
            .unwrap_or_default();
        let _ = write!(body, "<h2>{}{label}</h2>", esc(&o.slug));
        let org_repos: Vec<_> = repos.iter().filter(|r| r.org_id == o.id).collect();
        if org_repos.is_empty() {
            body.push_str("<p class=muted>No repositories yet — add one below.</p>");
            continue;
        }
        body.push_str(
            "<table><tr><th>Repository</th><th>Update mode</th><th>Cooldown (days)</th></tr>",
        );
        for r in org_repos {
            let _ = write!(
                body,
                "<tr><td><a href=\"/r/{o}/{rp}\">{rp}</a></td><td>{mode}</td><td>{cd}</td></tr>",
                o = esc(&r.org),
                rp = esc(&r.repo),
                mode = esc(&r.update_mode),
                cd = r.cooldown_days,
            );
        }
        body.push_str("</table>");
    }

    // Only superadmins (incl. single-tenant all-access) create orgs.
    if user.is_superadmin {
        body.push_str(
            "<h2>Create</h2>\
            <form class=row method=post action=/orgs>org slug <input name=slug required> \
            name <input name=name> <button>Create org</button></form>",
        );
    }
    body.push_str(
        "<form class=row method=post action=/repos>org <input name=org required> \
         repo <input name=repo required> <button>Create repo</button></form>",
    );
    Ok(shell(&s, &user, "Repositories", &body))
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
) -> Result<Redirect, StatusCode> {
    if !user.is_superadmin {
        return Err(StatusCode::FORBIDDEN);
    }
    let name = f.name.as_deref().filter(|n| !n.is_empty());
    s.catalog.create_org(&f.slug, name).await.map_err(e500)?;
    Ok(Redirect::to("/"))
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
) -> Result<Redirect, StatusCode> {
    // Must have access to the target org.
    let org = s
        .catalog
        .list_organizations()
        .await
        .map_err(e500)?
        .into_iter()
        .find(|o| o.slug == f.org)
        .ok_or(StatusCode::BAD_REQUEST)?;
    if !user.can(org.id) {
        return Err(StatusCode::FORBIDDEN);
    }
    s.catalog
        .create_repo(&f.org, &f.repo)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(Redirect::to(&format!("/r/{}/{}", f.org, f.repo)))
}

// ----- repository detail -----

#[allow(clippy::too_many_lines)]
async fn repo_page(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, repo)): Path<(String, String)>,
) -> Result<Html<String>, StatusCode> {
    let summary = lookup(&s, &user, &org, &repo).await?;
    let versions = s
        .catalog
        .admin_package_versions(summary.id)
        .await
        .map_err(e500)?;
    let token_count = s.catalog.repo_token_count(summary.id).await.map_err(e500)?;
    let licenses = s.catalog.list_licenses(summary.id).await.map_err(e500)?;
    let grants = s.catalog.list_grants(summary.id).await.map_err(e500)?;
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
        let mut badges = String::new();
        if v.held {
            badges.push_str("<span class='badge held'>held</span> ");
        }
        if v.approved {
            badges.push_str("<span class='badge ok'>approved</span> ");
        }
        let (hold_label, hold_action) = if v.held {
            ("Unhold", "unhold")
        } else {
            ("Hold", "hold")
        };
        let _ = write!(
            rows,
            "<tr><td>{pkg}</td><td>{ver} <span class=muted>{norm}</span></td><td>{stab}</td>\
             <td>{badges}<span class=muted>{rel}</span></td><td>\
             <form class=inline method=post action=\"/r/{slug}/version\">\
             <input type=hidden name=package value=\"{pkg}\"><input type=hidden name=normalized value=\"{norm}\">\
             <button name=action value={hold_action}>{hold_label}</button> \
             <button name=action value=approve>Approve</button></form></td></tr>",
            pkg = esc(&v.package),
            ver = esc(&v.version),
            norm = esc(&v.normalized_version),
            stab = esc(&v.stability),
            rel = esc(v.released_at.as_deref().unwrap_or("")),
        );
    }
    if versions.is_empty() {
        rows = "<tr><td colspan=5 class=muted>No packages yet. Mirror one with <code>sconce mirror</code>.</td></tr>".into();
    }

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

    let mut lic_rows = String::new();
    for l in &licenses {
        let _ = write!(
            lic_rows,
            "<tr><td>{buyer}</td><td>{status}</td><td>{pkgs}</td></tr>",
            buyer = esc(l.buyer.as_deref().unwrap_or("—")),
            status = esc(&l.status),
            pkgs = esc(&l.packages.join(", ")),
        );
    }
    if licenses.is_empty() {
        lic_rows = "<tr><td colspan=3 class=muted>none</td></tr>".into();
    }
    let licenses_section = format!(
        "<h2>License keys</h2><table><tr><th>Buyer</th><th>Status</th><th>Entitled packages</th></tr>{lic_rows}</table>\
         <form class=row method=post action=\"/r/{slug}/license\">buyer <input name=buyer> \
         packages <input name=packages placeholder=\"vendor/a vendor/b\" required> <button>Issue license</button></form>"
    );

    let install = format!(
        "<h2>Install &amp; tokens</h2><pre>composer config repositories.{r} composer {base}/{slug}\ncomposer require &lt;package&gt;</pre>\
         <p class=muted>{n} token(s) exist.</p>\
         <form class=inline method=post action=\"/r/{slug}/token\"><button>Create token</button></form>",
        r = esc(&repo),
        base = esc(s.public_base_url.trim_end_matches('/')),
        n = token_count,
    );

    Ok(shell(
        &s,
        &user,
        &slug,
        &format!(
            "<h1>{slug}</h1>{policy}\
             <h2>Packages &amp; versions</h2><table>\
             <tr><th>Package</th><th>Version</th><th>Stability</th><th>State</th><th>Actions</th></tr>{rows}</table>\
             {grants_section}{licenses_section}{install}"
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
    let target = lookup(&s, &user, &org, &repo).await?.id;
    let (src_org, src_repo) = f.from.split_once('/').ok_or(StatusCode::BAD_REQUEST)?;
    let source = lookup(&s, &user, src_org, src_repo).await?.id;
    s.catalog
        .grant_package(target, source, &f.package)
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
    let repo_id = lookup(&s, &user, &org, &repo).await?.id;
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

async fn create_token(
    State(s): State<Ui>,
    Extension(user): Extension<CurrentUser>,
    Path((org, repo)): Path<(String, String)>,
) -> Result<Html<String>, StatusCode> {
    let repo_id = lookup(&s, &user, &org, &repo).await?.id;
    let token = s.catalog.create_token(repo_id, None).await.map_err(e500)?;
    let slug = format!("{}/{}", esc(&org), esc(&repo));
    Ok(shell(
        &s,
        &user,
        "Token created",
        &format!(
            "<h1>Token created</h1><p>Store it now — it won't be shown again.</p>\
             <pre>{tok}</pre><p><a href=\"/r/{slug}\">← back to {slug}</a></p>",
            tok = esc(&token),
        ),
    ))
}
