//! Admin web UI — a small server-rendered dashboard over the catalog.
//!
//! This is the **operator** surface (manage repos, supply-chain controls,
//! tokens), deliberately separate from the public Composer wire API in
//! [`crate`]. It has no built-in auth and should be bound to localhost (or put
//! behind your own auth/proxy) — `sconce ui` defaults to `127.0.0.1`.

use std::fmt::Write as _;

use axum::Router;
use axum::extract::{Form, Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use sconce_catalog::Catalog;
use serde::Deserialize;

#[derive(Clone)]
struct Ui {
    catalog: Catalog,
    /// Public base URL of the Composer-serving endpoint (for install snippets).
    public_base_url: String,
}

/// Build the admin UI router.
pub fn router(catalog: Catalog, public_base_url: String) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/r/{org}/{repo}", get(repo_page))
        .route("/r/{org}/{repo}/policy", post(set_policy))
        .route("/r/{org}/{repo}/version", post(version_action))
        .route("/r/{org}/{repo}/token", post(create_token))
        .with_state(Ui {
            catalog,
            public_base_url,
        })
}

/// Bind `listen` and serve the admin UI.
pub async fn serve(
    catalog: Catalog,
    public_base_url: String,
    listen: std::net::SocketAddr,
) -> std::io::Result<()> {
    let app = router(catalog, public_base_url);
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, app).await
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
         h1,h2{{font-weight:600}} a{{color:#2456a6;text-decoration:none}} a:hover{{text-decoration:underline}}\
         table{{border-collapse:collapse;width:100%;margin:1rem 0}} th,td{{text-align:left;padding:.4rem .6rem;border-bottom:1px solid #eee}}\
         .badge{{display:inline-block;padding:.05rem .4rem;border-radius:.4rem;font-size:.8rem}}\
         .held{{background:#fde2e2;color:#a12}} .ok{{background:#e2f5e6;color:#161}} .muted{{color:#888}}\
         form.inline{{display:inline}} button{{font:inherit;cursor:pointer}} code,pre{{background:#f6f7f9;border-radius:.3rem}}\
         pre{{padding:.8rem;overflow:auto}} input,select{{font:inherit;padding:.2rem}}\
         </style></head><body><p class=muted><a href=/>sconce admin</a></p>{body}</body></html>"
    ))
}

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
        rows = "<tr><td colspan=3 class=muted>No repositories yet. Create one with <code>sconce repo-create</code>.</td></tr>".into();
    }
    Ok(page(
        "Repositories",
        &format!(
            "<h1>Repositories</h1><table><tr><th>Repository</th><th>Update mode</th><th>Cooldown (days)</th></tr>{rows}</table>"
        ),
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
    let slug = format!("{}/{}", esc(&org), esc(&repo));

    // Policy form.
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

    // Versions table.
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

    let install = format!(
        "<h2>Install instructions</h2><pre>composer config repositories.{r} composer {base}/{slug}\ncomposer require &lt;package&gt;</pre>\
         <p class=muted>Authenticate with a token (below). {n} token(s) exist.</p>\
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
             {install}"
        ),
    ))
}

#[derive(Deserialize)]
struct PolicyForm {
    mode: String,
    cooldown_days: i32,
}

async fn set_policy(
    State(s): State<Ui>,
    Path((org, repo)): Path<(String, String)>,
    Form(f): Form<PolicyForm>,
) -> Result<Redirect, Response> {
    let summary = lookup(&s, &org, &repo)
        .await
        .map_err(IntoResponse::into_response)?;
    s.catalog
        .set_update_policy(summary.id, &f.mode, f.cooldown_days)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST.into_response())?;
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
    let summary = lookup(&s, &org, &repo).await?;
    let id = summary.id;
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

async fn create_token(
    State(s): State<Ui>,
    Path((org, repo)): Path<(String, String)>,
) -> Result<Html<String>, StatusCode> {
    let summary = lookup(&s, &org, &repo).await?;
    let token = s
        .catalog
        .create_token(summary.id, None)
        .await
        .map_err(e500)?;
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
