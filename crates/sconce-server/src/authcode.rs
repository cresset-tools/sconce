//! OAuth 2.0 authorization-code grant with PKCE (RFC 6749 §4.1, RFC 7636) for
//! `bougie login` — the shared rules behind the dashboard's `/authorize` page
//! (see `ui.rs`) and the wire server's `/oauth/token` endpoint (see `lib.rs`).
//!
//! There is one client, the bougie CLI, and it is public: it holds no secret,
//! so PKCE is required and the redirect URI is the only other thing tying a
//! code to it. Two redirect URIs are accepted:
//!
//! - a loopback listener the CLI runs for the duration of the login
//!   (`http://127.0.0.1:<port>/callback` or `http://[::1]:<port>/callback`,
//!   RFC 8252 §7.3 — any port, since the CLI picks a free one);
//! - the dashboard's own [`PASTE_PATH`] page, which shows the code for the
//!   user to paste into the terminal when the browser can't reach the CLI
//!   (a remote shell, a container).

/// The only client allowed to request codes.
pub const CLIENT_ID: &str = "bougie-cli";

/// How long an approved code stays redeemable. Long enough to copy it from
/// the paste page into a terminal; the CLI's loopback redemption takes
/// milliseconds.
pub const CODE_TTL_SECS: i64 = 300;

/// The dashboard page that shows a code for pasting.
pub const PASTE_PATH: &str = "/oauth/code/callback";

/// Longest `state` passed through. The CLI sends a few dozen characters.
const MAX_STATE: usize = 512;

/// Whether `uri` is a redirect URI the bougie CLI may use: a loopback
/// `/callback` on an explicit port, or exactly the dashboard's paste page.
/// No query or fragment, no userinfo, no `localhost` (RFC 8252 §8.3: it can
/// resolve somewhere else).
pub fn redirect_uri_allowed(uri: &str, dashboard: &str) -> bool {
    if uri == format!("{}{PASTE_PATH}", dashboard.trim_end_matches('/')) {
        return true;
    }
    let Some(rest) = uri.strip_prefix("http://") else {
        return false;
    };
    let Some(authority) = rest.strip_suffix("/callback") else {
        return false;
    };
    let port = authority
        .strip_prefix("127.0.0.1:")
        .or_else(|| authority.strip_prefix("[::1]:"));
    port.is_some_and(|p| {
        !p.is_empty()
            && p.bytes().all(|b| b.is_ascii_digit())
            && p.parse::<u16>().is_ok_and(|n| n != 0)
    })
}

/// Whether `challenge` has the shape of an S256 challenge: the unpadded
/// base64url of a sha256, so exactly 43 characters.
pub fn challenge_well_formed(challenge: &str) -> bool {
    challenge.len() == 43
        && challenge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Whether `state` can be passed through as-is.
pub fn state_acceptable(state: &str) -> bool {
    state.len() <= MAX_STATE && !state.chars().any(char::is_control)
}

/// Whether `uri` is the loopback listener (as opposed to the paste page).
pub fn is_loopback(uri: &str) -> bool {
    uri.starts_with("http://127.0.0.1:") || uri.starts_with("http://[::1]:")
}

#[cfg(test)]
mod tests {
    use super::*;

    const DASH: &str = "https://repo.example.com";

    #[test]
    fn accepts_loopback_and_the_paste_page() {
        for ok in [
            "http://127.0.0.1:53682/callback",
            "http://[::1]:8080/callback",
            "https://repo.example.com/oauth/code/callback",
        ] {
            assert!(redirect_uri_allowed(ok, DASH), "{ok}");
        }
        assert!(redirect_uri_allowed(
            "https://repo.example.com/oauth/code/callback",
            "https://repo.example.com/"
        ));
    }

    #[test]
    fn rejects_everything_else() {
        for bad in [
            "http://localhost:53682/callback",
            "http://127.0.0.1/callback",
            "http://127.0.0.1:0/callback",
            "http://127.0.0.1:99999/callback",
            "http://127.0.0.1:53682/callback?x=1",
            "http://127.0.0.1:53682/other",
            "http://127.0.0.1:53682@evil.example/callback",
            "http://127.0.0.1:+80/callback",
            "https://127.0.0.1:53682/callback",
            "https://evil.example/oauth/code/callback",
            "https://repo.example.com/oauth/code/callback?x=1",
            "https://repo.example.com.evil.example/oauth/code/callback",
        ] {
            assert!(!redirect_uri_allowed(bad, DASH), "{bad}");
        }
    }

    #[test]
    fn challenge_shape() {
        assert!(challenge_well_formed(
            "Ec9IvtMd785zId6XVxyiEaErn5iBJrDupf7sT_YRe6o"
        ));
        assert!(!challenge_well_formed("plain-verifier"));
        assert!(!challenge_well_formed(
            "Ec9IvtMd785zId6XVxyiEaErn5iBJrDupf7sT_YRe6="
        ));
    }
}
