//! Dashboard SSO: the OpenID Connect Authorization Code + PKCE flow.
//!
//! Two steps: [`begin`] produces the IdP redirect URL plus the per-login
//! transaction state to persist (`state`/`nonce`/`pkce_verifier`); [`finish`]
//! exchanges the returned code, validates the ID token (signature via JWKS,
//! `iss`/`aud`/`exp`/`nonce`), and returns the verified identity. The caller
//! maps the identity to a session — this module never touches the catalog.
#![allow(clippy::doc_markdown)] // OIDC/PKCE/JWKS acronyms read fine unbacktick'd

use openidconnect::TokenResponse as _;
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, reqwest,
};
use sconce_catalog::OidcConnection;

/// What [`begin`] returns: where to send the browser, and the flow state to
/// store keyed by `state`.
#[derive(Debug)]
pub struct Begin {
    pub auth_url: String,
    pub state: String,
    pub nonce: String,
    pub pkce_verifier: String,
}

/// A verified SSO identity.
#[derive(Debug)]
pub struct Identity {
    pub email: String,
}

/// SSO flow errors (all surfaced to the operator/user as a failed login).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("OIDC configuration is invalid: {0}")]
    Config(String),
    #[error("OIDC discovery/exchange failed: {0}")]
    Network(String),
    #[error("the ID token is missing or invalid: {0}")]
    Token(String),
    #[error("the IdP did not return a verified email")]
    NoEmail,
}

/// A reqwest client that does NOT follow redirects (required for OAuth safety).
fn http_client() -> Result<reqwest::Client, Error> {
    reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| Error::Network(e.to_string()))
}

/// Discover the provider and build a client for `conn`. Returns the built
/// client; left as a macro-free inline helper because openidconnect 4.x clients
/// carry endpoint typestate generics that don't name cleanly across an `fn`
/// boundary — so callers inline this via the `oidc_client!` pattern below.
macro_rules! build_client {
    ($conn:expr, $secret:expr, $http:expr) => {{
        let issuer =
            IssuerUrl::new($conn.issuer_url.clone()).map_err(|e| Error::Config(e.to_string()))?;
        let redirect = RedirectUrl::new($conn.redirect_url.clone())
            .map_err(|e| Error::Config(e.to_string()))?;
        let metadata = CoreProviderMetadata::discover_async(issuer, $http)
            .await
            .map_err(|e| Error::Network(e.to_string()))?;
        CoreClient::from_provider_metadata(
            metadata,
            ClientId::new($conn.client_id.clone()),
            $secret.map(|s: &str| ClientSecret::new(s.to_owned())),
        )
        .set_redirect_uri(redirect)
    }};
}

/// Build the IdP authorize URL (PKCE + state + nonce) for a login.
pub async fn begin(conn: &OidcConnection, client_secret: Option<&str>) -> Result<Begin, Error> {
    let http = http_client()?;
    let client = build_client!(conn, client_secret, &http);
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();

    let mut req = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .set_pkce_challenge(challenge);
    for scope in conn.scopes.split_whitespace() {
        req = req.add_scope(Scope::new(scope.to_owned()));
    }
    let (auth_url, state, nonce) = req.url();

    Ok(Begin {
        auth_url: auth_url.to_string(),
        state: state.secret().clone(),
        nonce: nonce.secret().clone(),
        pkce_verifier: verifier.into_secret(),
    })
}

/// Exchange the code, validate the ID token against the stored `nonce`, and
/// return the verified identity.
pub async fn finish(
    conn: &OidcConnection,
    client_secret: Option<&str>,
    code: &str,
    nonce: &str,
    pkce_verifier: &str,
) -> Result<Identity, Error> {
    let http = http_client()?;
    let client = build_client!(conn, client_secret, &http);

    let token = client
        .exchange_code(AuthorizationCode::new(code.to_owned()))
        .map_err(|e| Error::Config(e.to_string()))?
        .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier.to_owned()))
        .request_async(&http)
        .await
        .map_err(|e| Error::Network(e.to_string()))?;

    let id_token = token.id_token().ok_or_else(|| {
        Error::Token("no id_token in the token response (is 'openid' scope set?)".to_owned())
    })?;
    let claims = id_token
        .claims(&client.id_token_verifier(), &Nonce::new(nonce.to_owned()))
        .map_err(|e| Error::Token(e.to_string()))?;

    let email = claims
        .email()
        .map(|e| e.as_str().to_owned())
        .ok_or(Error::NoEmail)?;
    Ok(Identity { email })
}

/// Whether `email`'s domain is in `domains` (case-insensitive). `None`/empty
/// list means "no restriction" for allow-lists.
#[must_use]
pub fn domain_matches(email: &str, domains: &Option<Vec<String>>) -> bool {
    let Some(list) = domains.as_ref().filter(|l| !l.is_empty()) else {
        return false;
    };
    let Some(domain) = email.rsplit('@').next() else {
        return false;
    };
    list.iter().any(|d| d.eq_ignore_ascii_case(domain))
}

#[cfg(test)]
mod tests {
    use super::domain_matches;

    #[test]
    fn domain_matching_is_case_insensitive_and_empty_safe() {
        let admins = Some(vec!["acme.com".to_owned(), "ops.acme.io".to_owned()]);
        assert!(domain_matches("jane@acme.com", &admins));
        assert!(domain_matches("Bob@ACME.COM", &admins)); // case-insensitive
        assert!(domain_matches("ci@ops.acme.io", &admins));
        assert!(!domain_matches("eve@evil.com", &admins));
        assert!(!domain_matches("malformed-no-at", &admins));
        // No list (or empty) = no match (used for allow/admin gating).
        assert!(!domain_matches("jane@acme.com", &None));
        assert!(!domain_matches("jane@acme.com", &Some(vec![])));
    }
}
