//! CSRF guard for the admin UI: rejects **cross-origin, browser-sent**
//! state-changing requests, which could otherwise ride on ambient credentials
//! (the session cookie, or — in single-tenant mode — cached HTTP basic
//! credentials, which browsers attach to cross-site requests regardless of any
//! cookie `SameSite` attribute).
//!
//! Origin verification, not per-form tokens: any browser able to send a
//! credentialed cross-site request also reveals the request's provenance in
//! `Sec-Fetch-Site` (all evergreen browsers; Safari since 16.4) or, failing
//! that, `Origin` (sent on non-GET since long before that). Checking those
//! headers in one route layer covers every form at once — including the
//! pre-auth `/login` form (login CSRF) and single-tenant basic-auth mode,
//! which has no session to bind a synchronizer token to. This is the same
//! policy as Go's `net/http` `CrossOriginProtection` and Django's origin
//! checking:
//!
//! - `GET`/`HEAD`/`OPTIONS` always pass (they must stay side-effect-free).
//! - `Sec-Fetch-Site: same-origin` passes, as does `none` (user-initiated:
//!   address bar, bookmark). `cross-site` is rejected, and so is `same-site` —
//!   a sibling subdomain must not be able to forge admin actions.
//! - Without fetch metadata, an `Origin` header must match the request `Host`.
//! - Neither header ⇒ not a browser (curl, server-to-server): there are no
//!   ambient browser credentials to forge, so the request passes.

use axum::extract::Request;
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// Route layer: reject forgeable cross-origin requests with `403` before auth
/// or any handler runs. SCIM is exempt — bearer-token server-to-server calls
/// carry no ambient credentials (mirrors the auth layer's `/scim/` carve-out).
pub async fn guard(req: Request, next: Next) -> Response {
    if !req.uri().path().starts_with("/scim/") && forbids_cross_origin(req.method(), req.headers())
    {
        return (
            StatusCode::FORBIDDEN,
            "cross-origin request rejected (CSRF guard)",
        )
            .into_response();
    }
    next.run(req).await
}

fn forbids_cross_origin(method: &Method, headers: &HeaderMap) -> bool {
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return false;
    }
    if let Some(site) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        return !matches!(site, "same-origin" | "none");
    }
    match headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        // No fetch metadata, but an Origin: allow only an exact host match.
        // An unparsable Origin (e.g. `null` from a sandboxed iframe) rejects.
        Some(origin) => match (
            origin_host(origin),
            headers.get(header::HOST).and_then(|v| v.to_str().ok()),
        ) {
            (Some(origin_host), Some(host)) => !origin_host.eq_ignore_ascii_case(host),
            _ => true,
        },
        None => false,
    }
}

/// The `host[:port]` part of a serialized origin (`scheme://host[:port]`).
fn origin_host(origin: &str) -> Option<&str> {
    let (_scheme, host) = origin.split_once("://")?;
    (!host.is_empty() && !host.contains('/')).then_some(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                axum::http::HeaderName::try_from(*name).unwrap(),
                value.parse().unwrap(),
            );
        }
        map
    }

    #[test]
    fn get_is_never_blocked() {
        let h = headers(&[("sec-fetch-site", "cross-site")]);
        assert!(!forbids_cross_origin(&Method::GET, &h));
        assert!(!forbids_cross_origin(&Method::HEAD, &h));
        assert!(!forbids_cross_origin(&Method::OPTIONS, &h));
    }

    #[test]
    fn same_origin_fetch_metadata_passes() {
        let h = headers(&[("sec-fetch-site", "same-origin")]);
        assert!(!forbids_cross_origin(&Method::POST, &h));
    }

    #[test]
    fn user_initiated_fetch_metadata_passes() {
        let h = headers(&[("sec-fetch-site", "none")]);
        assert!(!forbids_cross_origin(&Method::POST, &h));
    }

    #[test]
    fn cross_site_fetch_metadata_rejected() {
        let h = headers(&[("sec-fetch-site", "cross-site")]);
        assert!(forbids_cross_origin(&Method::POST, &h));
    }

    #[test]
    fn sibling_subdomain_rejected() {
        let h = headers(&[("sec-fetch-site", "same-site")]);
        assert!(forbids_cross_origin(&Method::POST, &h));
    }

    #[test]
    fn fetch_metadata_wins_over_matching_origin() {
        let h = headers(&[
            ("sec-fetch-site", "cross-site"),
            ("origin", "http://admin.example"),
            ("host", "admin.example"),
        ]);
        assert!(forbids_cross_origin(&Method::POST, &h));
    }

    #[test]
    fn origin_matching_host_passes() {
        let h = headers(&[
            ("origin", "http://Admin.Example:8081"),
            ("host", "admin.example:8081"),
        ]);
        assert!(!forbids_cross_origin(&Method::POST, &h));
    }

    #[test]
    fn origin_mismatch_rejected() {
        let h = headers(&[
            ("origin", "https://evil.example"),
            ("host", "admin.example"),
        ]);
        assert!(forbids_cross_origin(&Method::POST, &h));
    }

    #[test]
    fn origin_port_mismatch_rejected() {
        let h = headers(&[
            ("origin", "http://admin.example:8080"),
            ("host", "admin.example:8081"),
        ]);
        assert!(forbids_cross_origin(&Method::POST, &h));
    }

    #[test]
    fn null_origin_rejected() {
        let h = headers(&[("origin", "null"), ("host", "admin.example")]);
        assert!(forbids_cross_origin(&Method::POST, &h));
    }

    #[test]
    fn origin_without_host_header_rejected() {
        let h = headers(&[("origin", "http://admin.example")]);
        assert!(forbids_cross_origin(&Method::POST, &h));
    }

    #[test]
    fn bare_non_browser_request_passes() {
        assert!(!forbids_cross_origin(&Method::POST, &HeaderMap::new()));
    }
}
