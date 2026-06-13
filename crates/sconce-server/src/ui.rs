//! Admin web UI — a server-rendered management console over the catalog.
//!
//! This is the **operator** surface (manage orgs/repos, supply-chain controls,
//! tokens, licenses, grants), deliberately separate from the public Composer
//! wire API in [`crate`]. Protect it with `--admin-password` (HTTP basic); when
//! no password is set it runs open and should be bound to localhost only.

use std::fmt::Write as _;

use axum::Router;
use axum::extract::{Form, Path, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use base64::Engine as _;
use sconce_catalog::Catalog;
use serde::Deserialize;

#[derive(Clone)]
struct Ui {
    catalog: Catalog,
    /// Public base URL of the Composer-serving endpoint (for install snippets).
    public_base_url: String,
    /// If set, every page requires HTTP basic auth with this as the password.
    admin_password: Option<String>,
}

/// Build the admin UI router.
pub fn router(catalog: Catalog, public_base_url: String, admin_password: Option<String>) -> Router {
    let state = Ui {
        catalog,
        public_base_url,
        admin_password,
    };
    Router::new()
        .route("/", get(index))
        .route("/orgs", post(create_org))
        .route("/repos", post(create_repo))
        .route("/r/{org}/{repo}", get(repo_page))
        .route("/r/{org}/{repo}/policy", post(set_policy))
        .route("/r/{org}/{repo}/version", post(version_action))
        .route("/r/{org}/{repo}/token", post(create_token))
        .route("/r/{org}/{repo}/license", post(create_license))
        .route("/r/{org}/{repo}/grant", post(create_grant))
        .route_layer(middleware::from_fn_with_state(state.clone(), admin_auth))
        .with_state(state)
}

/// Bind `listen` and serve the admin UI.
pub async fn serve(
    catalog: Catalog,
    public_base_url: String,
    admin_password: Option<String>,
    listen: std::net::SocketAddr,
) -> std::io::Result<()> {
    let app = router(catalog, public_base_url, admin_password);
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, app).await
}

/// HTTP-basic gate when an admin password is configured; otherwise open.
async fn admin_auth(State(s): State<Ui>, req: Request, next: Next) -> Response {
    let Some(expected) = s.admin_password.as_deref() else {
        return next.run(req).await;
    };
    match basic_password(req.headers()) {
        Some(pw) if pw == expected => next.run(req).await,
        _ => (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Basic realm=\"sconce admin\"")],
        )
            .into_response(),
    }
}

fn basic_password(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let b64 = value.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    let creds = String::from_utf8(decoded).ok()?;
    creds.split_once(':').map(|(_, p)| p.to_owned())
}

fn e500<E>(_: E) -> StatusCode {
    StatusCode::INTERNAL_SERVER_ERROR
}

/// Minimal HTML-escape for interpolated text.
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
         </style></head><body><p class=muted><a href=/>sconce admin</a></p>{body}</body></html>"
    ))
}

async fn lookup(s: &Ui, org: &str, repo: &str) -> Result<sconce_catalog::RepoSummary, StatusCode> {
    s.catalog
        .list_repositories()
        .await
        .map_err(e500)?
        .into_iter()
        .find(|r| r.org == org && r.repo == repo)
        .ok_or(StatusCode::NOT_FOUND)
}

// ----- index + creation -----

async fn index(State(s): State<Ui>) -> Result<Html<String>, StatusCode> {
    let repos = s.catalog.list_repositories().await.map_err(e500)?;
    let mut rows = String::new();
    for r in &repos {
        let _ = write!(
            rows,
            "<tr><td><a href=\"/r/{o}/{rp}\">{o}/{rp}</a></td><td>{mode}</td><td>{cd}</td></tr>",
            o = esc(&r.org),
            rp = esc(&r.repo),
            mode = esc(&r.update_mode),
            cd = r.cooldown_days,
        );
    }
    if repos.is_empty() {
        rows = "<tr><td colspan=3 class=muted>No repositories yet — create one below.</td></tr>"
            .into();
    }
    let create = "<h2>Create</h2>\
        <form class=row method=post action=/orgs>org slug <input name=slug required> \
        name <input name=name> <button>Create org</button></form>\
        <form class=row method=post action=/repos>org <input name=org required> \
        repo <input name=repo required> <button>Create repo</button></form>";
    Ok(page(
        "Repositories",
        &format!(
            "<h1>Repositories</h1><table>\
             <tr><th>Repository</th><th>Update mode</th><th>Cooldown (days)</th></tr>{rows}</table>{create}"
        ),
    ))
}

#[derive(Deserialize)]
struct OrgForm {
    slug: String,
    name: Option<String>,
}

async fn create_org(State(s): State<Ui>, Form(f): Form<OrgForm>) -> Result<Redirect, StatusCode> {
    let name = f.name.as_deref().filter(|n| !n.is_empty());
    s.catalog.create_org(&f.slug, name).await.map_err(e500)?;
    Ok(Redirect::to("/"))
}

#[derive(Deserialize)]
struct RepoForm {
    org: String,
    repo: String,
}

async fn create_repo(State(s): State<Ui>, Form(f): Form<RepoForm>) -> Result<Redirect, StatusCode> {
    // create_repo errors if the org is unknown.
    s.catalog
        .create_repo(&f.org, &f.repo)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(Redirect::to(&format!("/r/{}/{}", f.org, f.repo)))
}

// ----- repository detail -----

// A view function that assembles several HTML sections; length is inherent.
#[allow(clippy::too_many_lines)]
async fn repo_page(
    State(s): State<Ui>,
    Path((org, repo)): Path<(String, String)>,
) -> Result<Html<String>, StatusCode> {
    let summary = lookup(&s, &org, &repo).await?;
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

    // Grants (agency curation).
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

    // Licenses (seller mode).
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

    Ok(page(
        &slug,
        &format!(
            "<h1>{slug}</h1>{policy}\
             <h2>Packages &amp; versions</h2><table>\
             <tr><th>Package</th><th>Version</th><th>Stability</th><th>State</th><th>Actions</th></tr>{rows}</table>\
             {grants_section}{licenses_section}{install}"
        ),
    ))
}

// ----- repo actions -----

#[derive(Deserialize)]
struct PolicyForm {
    mode: String,
    cooldown_days: i32,
}

async fn set_policy(
    State(s): State<Ui>,
    Path((org, repo)): Path<(String, String)>,
    Form(f): Form<PolicyForm>,
) -> Result<Redirect, StatusCode> {
    let summary = lookup(&s, &org, &repo).await?;
    s.catalog
        .set_update_policy(summary.id, &f.mode, f.cooldown_days)
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
    Path((org, repo)): Path<(String, String)>,
    Form(f): Form<VersionForm>,
) -> Result<Redirect, StatusCode> {
    let id = lookup(&s, &org, &repo).await?.id;
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
    Path((org, repo)): Path<(String, String)>,
    Form(f): Form<GrantForm>,
) -> Result<Redirect, StatusCode> {
    let target = lookup(&s, &org, &repo).await?.id;
    let (src_org, src_repo) = f.from.split_once('/').ok_or(StatusCode::BAD_REQUEST)?;
    let source = lookup(&s, src_org, src_repo).await?.id;
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
    Path((org, repo)): Path<(String, String)>,
    Form(f): Form<LicenseForm>,
) -> Result<Html<String>, StatusCode> {
    let repo_id = lookup(&s, &org, &repo).await?.id;
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
        .ok_or(StatusCode::BAD_REQUEST)?; // a package wasn't found in this repo
    let slug = format!("{}/{}", esc(&org), esc(&repo));
    Ok(page(
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
    Path((org, repo)): Path<(String, String)>,
) -> Result<Html<String>, StatusCode> {
    let repo_id = lookup(&s, &org, &repo).await?.id;
    let token = s.catalog.create_token(repo_id, None).await.map_err(e500)?;
    let slug = format!("{}/{}", esc(&org), esc(&repo));
    Ok(page(
        "Token created",
        &format!(
            "<h1>Token created</h1><p>Store it now — it won't be shown again.</p>\
             <pre>{tok}</pre><p><a href=\"/r/{slug}\">← back to {slug}</a></p>",
            tok = esc(&token),
        ),
    ))
}
