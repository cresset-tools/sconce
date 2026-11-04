//! HTTP caching for the Composer read routes, so a CDN in front can carry a
//! repository with anonymous access and clients revalidate cheaply.
//!
//! - Anonymous responses are `public`; any response to a credential is
//!   `private`, so a shared cache never stores what a token or license key
//!   unlocked. Every response varies on `Authorization`, so a cache never hands
//!   an anonymous copy to a credential or the reverse.
//! - Metadata lives a minute, so a security hold or a newly approved version
//!   reaches clients that fast. It carries an `ETag`, so revalidating an
//!   unchanged document is a 304.
//! - A dist's bytes never change (a version is never rewritten), but it lives a
//!   day rather than forever: that bounds how long a cache keeps serving a
//!   package after it is declared private or yanked. A redirect to a presigned
//!   store URL lives well within the URL's own expiry.
//! - Errors are never stored: a 401 must not outlive turning anonymous access
//!   on, nor a 404 the version that fills it.

use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};

/// Which kind of read a route serves.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Kind {
    /// `packages.json` and p2 documents.
    Metadata,
    /// A dist download (bytes, or a redirect to them).
    Dist,
}

/// Seconds metadata may be served from a cache.
const METADATA_MAX_AGE: u64 = 60;
/// Seconds a dist may be served from a cache.
const DIST_MAX_AGE: u64 = 86_400;
/// Seconds a redirect to a presigned URL may be reused. Must stay well below
/// `DIST_PRESIGN_SECS`, or a cache hands out an expired signature.
const REDIRECT_MAX_AGE: u64 = 60;
const _: () = assert!(REDIRECT_MAX_AGE * 2 < crate::DIST_PRESIGN_SECS);

/// Middleware for one read route (`from_fn_with_state(kind, cache)`).
pub(crate) async fn cache(State(kind): State<Kind>, req: Request, next: Next) -> Response {
    let anonymous = !req.headers().contains_key(header::AUTHORIZATION);
    let if_none_match = req.headers().get(header::IF_NONE_MATCH).cloned();
    let mut resp = next.run(req).await;
    let status = resp.status();
    resp.headers_mut()
        .append(header::VARY, HeaderValue::from_static("Authorization"));

    let scope = if anonymous { "public" } else { "private" };
    let max_age = match (kind, status) {
        (_, s) if !s.is_success() && !s.is_redirection() => {
            set(&mut resp, "no-store");
            return resp;
        }
        (Kind::Metadata, StatusCode::OK) => METADATA_MAX_AGE,
        (Kind::Dist, StatusCode::OK) => DIST_MAX_AGE,
        (Kind::Dist, StatusCode::FOUND) => REDIRECT_MAX_AGE,
        // Anything else (a renamed slug's 301) keeps its defaults.
        _ => return resp,
    };
    set(&mut resp, &format!("{scope}, max-age={max_age}"));

    if matches!(kind, Kind::Metadata) && status == StatusCode::OK {
        return with_etag(resp, if_none_match.as_ref()).await;
    }
    resp
}

fn set(resp: &mut Response, value: &str) {
    if let Ok(v) = HeaderValue::from_str(value) {
        resp.headers_mut().insert(header::CACHE_CONTROL, v);
    }
}

/// Tag a metadata document by its content, and answer a matching
/// `If-None-Match` with a 304 that keeps the caching headers.
async fn with_etag(resp: Response, if_none_match: Option<&HeaderValue>) -> Response {
    let (mut parts, body) = resp.into_parts();
    // Metadata is rendered in memory already; this only collects it.
    let Ok(bytes) = to_bytes(body, usize::MAX).await else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let digest = Sha256::digest(&bytes);
    let etag = format!("\"{}\"", hex32(&digest[..16]));
    let Ok(etag_value) = HeaderValue::from_str(&etag) else {
        return Response::from_parts(parts, Body::from(bytes));
    };
    parts.headers.insert(header::ETAG, etag_value);
    if if_none_match.is_some_and(|v| matches_etag(v, &etag)) {
        parts.status = StatusCode::NOT_MODIFIED;
        parts.headers.remove(header::CONTENT_LENGTH);
        parts.headers.remove(header::CONTENT_TYPE);
        return Response::from_parts(parts, Body::empty());
    }
    Response::from_parts(parts, Body::from(bytes))
}

/// Whether an `If-None-Match` value names `etag` (or is `*`). Weak tags
/// compare equal to their strong form, as RFC 9110 asks for this header.
fn matches_etag(header: &HeaderValue, etag: &str) -> bool {
    let Ok(list) = header.to_str() else {
        return false;
    };
    list.split(',').map(str::trim).any(|candidate| {
        candidate == "*" || candidate.strip_prefix("W/").unwrap_or(candidate) == etag
    })
}

fn hex32(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}
