//! A repository's human index: the page a browser gets at the repository's
//! URL (`/{org}/{repo}/`, or `/` on its custom domain). It says how to add
//! the repository to a project and lists the packages the viewer can
//! install, searchable.
//!
//! The list follows the same access as `packages.json`: a credential sees what
//! it can read, an anonymous visitor the public packages when the repository
//! has anonymous access. Without access the page still shows how to add the
//! repository, and lists nothing.

use std::collections::{BTreeMap, HashSet};

use askama::Template;
use axum::http::{HeaderMap, header};
use axum::response::{Html, IntoResponse, Response};
use sconce_catalog::RepoLocation;

use crate::{Access, AppError, AppState, authorize};

#[derive(Template)]
#[template(path = "repo_index.html")]
struct IndexPage {
    title: String,
    /// The URL to add, without a trailing slash.
    url: String,
    /// Composer's `repositories.<key>` name for it.
    key: String,
    /// The host Composer keys a credential on.
    host: String,
    anonymous: bool,
    listed: bool,
    total: usize,
    shown: usize,
    q: String,
    packages: Vec<IndexPackage>,
}

struct IndexPackage {
    name: String,
    latest: Option<String>,
    description: Option<String>,
    /// Lowercased name + description, what the search matches.
    search_text: String,
    /// Not matching `?q=` (the page still carries it, for live search).
    hidden: bool,
}

/// Render the index of `loc`, served at `base`, for whoever `headers` say.
pub(crate) async fn serve_index(
    s: &AppState,
    loc: &RepoLocation,
    base: &str,
    title: String,
    headers: &HeaderMap,
    q: Option<&str>,
) -> Result<Response, AppError> {
    let anonymous = s.catalog.repo_settings(loc.repo_id).await?.anonymous_access;
    // No credential and no anonymous access: instructions only, not a 401,
    // since this page is for people deciding how to add the repository.
    let access = if headers.contains_key(header::AUTHORIZATION) || anonymous {
        Some(authorize(s, loc.repo_id, headers).await?)
    } else {
        None
    };

    let mut packages = Vec::new();
    if let Some((access, policy)) = &access {
        let allowed: HashSet<String> = match access {
            Access::Full => s.catalog.all_package_names(loc.repo_id).await?,
            Access::Licensed(entitled) => entitled.keys().cloned().collect(),
            Access::Anonymous => s.catalog.anonymous_package_names(loc.repo_id, None).await?,
        }
        .into_iter()
        .collect();
        let (repo_mode, repo_cooldown) = s.catalog.update_policy(loc.repo_id).await?;
        let (mode, cooldown) = policy.effective(&repo_mode, repo_cooldown);
        packages = summarize(
            s.catalog
                .served_version_summaries(loc.repo_id, &mode, cooldown)
                .await?
                .into_iter()
                .filter(|v| allowed.contains(&v.name)),
        );
    }

    let q = q.unwrap_or_default().trim().to_owned();
    let terms: Vec<String> = q
        .to_lowercase()
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    for p in &mut packages {
        p.hidden = !terms.iter().all(|t| p.search_text.contains(t.as_str()));
    }
    let host = base
        .split_once("://")
        .map_or(base, |(_, rest)| rest)
        .split('/')
        .next()
        .unwrap_or_default()
        .to_owned();
    let page = IndexPage {
        title,
        url: base.trim_end_matches('/').to_owned(),
        key: loc.repo_slug.clone(),
        host,
        anonymous,
        listed: access.is_some(),
        total: packages.len(),
        shown: packages.iter().filter(|p| !p.hidden).count(),
        q,
        packages,
    };
    let html = page
        .render()
        .map_err(|e| AppError::Storage(std::io::Error::other(e)))?;
    Ok(Html(html).into_response())
}

/// One entry per package from its served versions (ascending within each
/// package): the newest stable version, else the newest of any stability,
/// with that version's description.
fn summarize(versions: impl Iterator<Item = sconce_catalog::VersionSummary>) -> Vec<IndexPackage> {
    let mut by_name: BTreeMap<String, Vec<sconce_catalog::VersionSummary>> = BTreeMap::new();
    for v in versions {
        by_name.entry(v.name.clone()).or_default().push(v);
    }
    by_name
        .into_iter()
        .map(|(name, versions)| {
            let newest = versions
                .iter()
                .rev()
                .find(|v| v.stability == "stable")
                .or_else(|| versions.last());
            let description = newest
                .and_then(|v| v.description.clone())
                .filter(|d| !d.trim().is_empty());
            let search_text =
                format!("{name} {}", description.as_deref().unwrap_or_default()).to_lowercase();
            IndexPackage {
                latest: newest.map(|v| v.version.clone()),
                name,
                description,
                search_text,
                hidden: false,
            }
        })
        .collect()
}
