//! CI OIDC token exchange: validate a CI platform's OIDC JWT against its JWKS
//! and a claim policy, so a workflow can trade it for a short-lived repo token
//! with no stored secret. Signature/`iss`/`aud`/`exp` are checked by the JWT
//! library; the per-policy claim matchers (e.g. `repository`, `ref`) are checked
//! here. Fetching JWKS is split out so the validation core is unit-testable
//! without a network.

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde_json::Value;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid CI token: {0}")]
    Invalid(String),
    #[error("JWKS discovery failed: {0}")]
    Discovery(String),
}

/// Validate a CI OIDC JWT against `jwks`, the expected `issuer`/`audience`, and
/// (implicitly) `exp`. Returns the verified claims on success.
pub fn validate_jwt(
    jwt: &str,
    jwks: &JwkSet,
    issuer: &str,
    audience: &str,
) -> Result<Value, Error> {
    let header = decode_header(jwt).map_err(|e| Error::Invalid(e.to_string()))?;
    let kid = header
        .kid
        .ok_or_else(|| Error::Invalid("token has no `kid`".to_owned()))?;
    let jwk = jwks
        .find(&kid)
        .ok_or_else(|| Error::Invalid("no JWKS key for the token's `kid`".to_owned()))?;
    let key = DecodingKey::from_jwk(jwk).map_err(|e| Error::Invalid(e.to_string()))?;

    let mut v = Validation::new(Algorithm::RS256);
    v.set_issuer(&[issuer]);
    v.set_audience(&[audience]);
    // `exp` is required and validated by default.
    let data = decode::<Value>(jwt, &key, &v).map_err(|e| Error::Invalid(e.to_string()))?;
    Ok(data.claims)
}

/// Whether every matcher in `matchers` equals the corresponding claim. An empty
/// matcher set matches anything (so a policy must set matchers to be useful).
#[must_use]
pub fn claims_match(claims: &Value, matchers: &Value) -> bool {
    matchers
        .as_object()
        .is_none_or(|m| m.iter().all(|(k, want)| claims.get(k) == Some(want)))
}

/// Discover and fetch an issuer's JWKS (via its `openid-configuration`).
pub async fn fetch_jwks(issuer: &str) -> Result<JwkSet, Error> {
    let base = issuer.trim_end_matches('/');
    let cfg: Value = reqwest::get(format!("{base}/.well-known/openid-configuration"))
        .await
        .map_err(|e| Error::Discovery(e.to_string()))?
        .json()
        .await
        .map_err(|e| Error::Discovery(e.to_string()))?;
    let jwks_uri = cfg
        .get("jwks_uri")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Discovery("no jwks_uri in discovery document".to_owned()))?;
    reqwest::get(jwks_uri)
        .await
        .map_err(|e| Error::Discovery(e.to_string()))?
        .json::<JwkSet>()
        .await
        .map_err(|e| Error::Discovery(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header};
    use serde_json::json;

    // A throwaway RSA test key + its public JWK (n/e), generated with openssl.
    const PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC1FsBRmnoKETSG\n\
YoaCmrEctaAjZsfz8ov6ix1yU6f6OlZt1DTXktPFUkV0+PZhPpb1Pi8Pu1AL8gLM\n\
RupRKGuWUUwIf1W4jXUzEnKWx1jPHSaw7kPx2CT4mfdxi8iqSbEyNED+OdCoKiZ2\n\
+kBx9CdOYUPd4guotQzUxvjBR3gydl2Ikzah6FinI2Vv7bdTqo1Q2NSF5NWVWQjE\n\
AaLZp8Y/k1hoEekjYBD7OVktUlUvpSksU0b4Zm9t333BjjTdFSkbtH6LHgwxV8K6\n\
f9E+f3AIS3OLAsuyWkaO5WjipJb76HO02oBHunvH+F0f+/2za39r4zUZgl8NKIaP\n\
GwDUrntLAgMBAAECggEAFSX0tyhTlky6FfOjAn+vAsunSbBy1jzTjM1QVri0W6xn\n\
yZMdygs+AMOslDjltSefw5ZL3V93vV1kZuzlPS3Q8BDLJgw7kOkG8JGioOnjp5R0\n\
9KFu0pX2g131IDqTPb02HMcuIUJ+lBUQFuxU4w9WGSOSJHMwqgwy1RVDmcw576fh\n\
e22FVm8zzbIqVIvIE9wof09b7ypcv3HKKIuIfrp2YeVDBPT5XQlWsUpiUS9kqEOi\n\
9Np99nL1mh/ZTlBmjxY09681l0pdNPQsG3o/DxtMW9HHxfiQNkMmUS9oha+P/D16\n\
qTsx/0VZ9U+p8WXcyOftOy1Xf4BnkXy8Kt1nKKVwcQKBgQDeBCGFVOtCqCh0slIo\n\
rcBq6ce3/g8ZqQbvPaqx31SmU6GCZiWq3eM25HnQAnKnctiAnA8c8HFaoGEhCKdr\n\
bM+WmdZOOEF0PcsFzcscCekV07VkEY2P1YtXshyyxGUB7/6HC6tI9ApKZaOOzdHh\n\
S+EvgIwm4sPwBujUaG5hm7556QKBgQDQztrOJUSLlJJs9Dafqa+zLBpQCL6rQuZP\n\
XWjYh5xOJWAsNPb4JyNU7vyxIUXP1/jCAyJSKNbgQMj1jU5m5UIrgI66twGukuq5\n\
kboCFFe2AVEdisXTiGgpTqZ4bPtv8rkX+X94+x4NA91JpEkwb7jvI7m0YLDiiQJf\n\
+5AidauXEwKBgQCTfAsIl7DxRuQZIZySiVoZq9OQ1qURVsfUhhKutr11AHl6NoEv\n\
UNdvz7dcB0RDGHfad9FSWCf1HDVpzGXrZw0/7lH/BD/3CFWmNV+H8M12Qn1tTHvN\n\
4P3/88I8v1qaPuPGsmnGvNdZNMvCQdf64n1lIO/5pQqkmPJyqC0rilqugQKBgQCn\n\
SwO9I9iuKAPErUjSVOZDG/Oc6dSxa/EP5xvoV4Ygigtqf6jbGqhRFQR5ednv8u4H\n\
qvEleDjoBJ+9NFB7WfTQ27f+2j7LukO7F4k6v0eit51gmN10ZBZn+e6gD1jH0WUA\n\
U1IRAMiLzuvNY4WL/Abj+fCAFvPBG9o+QlOxeCtY5wKBgA1wJY76MVNodPYibm+E\n\
LEga5VtDrL4ORF96b4O85xhLkgn4Z1uFkyTpzQUqnujCQI8/AGPtTNgwDO+3MnbE\n\
OXs7a/RdHA7gfudBEgU8KNL17rvquOlU6rpLzcupHG1qt+mHqBr/EKBqVLuow3zH\n\
+kJj4m5RaVkcPOQnkJ8cnt5e\n\
-----END PRIVATE KEY-----\n";

    const JWK_N: &str = "tRbAUZp6ChE0hmKGgpqxHLWgI2bH8_KL-osdclOn-jpWbdQ015LTxVJFdPj2YT6W9T4vD7tQC_ICzEbqUShrllFMCH9VuI11MxJylsdYzx0msO5D8dgk-Jn3cYvIqkmxMjRA_jnQqComdvpAcfQnTmFD3eILqLUM1Mb4wUd4MnZdiJM2oehYpyNlb-23U6qNUNjUheTVlVkIxAGi2afGP5NYaBHpI2AQ-zlZLVJVL6UpLFNG-GZvbd99wY403RUpG7R-ix4MMVfCun_RPn9wCEtziwLLslpGjuVo4qSW--hztNqAR7p7x_hdH_v9s2t_a-M1GYJfDSiGjxsA1K57Sw";

    fn jwks() -> JwkSet {
        serde_json::from_value(json!({
            "keys": [{ "kty": "RSA", "kid": "test", "use": "sig", "alg": "RS256", "n": JWK_N, "e": "AQAB" }]
        }))
        .unwrap()
    }

    fn sign(claims: &Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test".to_owned());
        let key = EncodingKey::from_rsa_pem(PEM.as_bytes()).unwrap();
        jsonwebtoken::encode(&header, claims, &key).unwrap()
    }

    fn future_exp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600
    }

    #[test]
    fn validates_signature_issuer_audience_and_matches_claims() {
        let claims = json!({
            "iss": "https://idp.test", "aud": "sconce", "exp": future_exp(),
            "sub": "repo:acme/app:ref:refs/heads/main",
            "repository": "acme/app", "ref": "refs/heads/main",
        });
        let jwt = sign(&claims);

        let got = validate_jwt(&jwt, &jwks(), "https://idp.test", "sconce").unwrap();
        assert_eq!(got["repository"], "acme/app");
        assert!(claims_match(
            &got,
            &json!({"repository": "acme/app", "ref": "refs/heads/main"})
        ));
        assert!(!claims_match(&got, &json!({"repository": "evil/x"})));

        // Wrong audience / issuer are rejected by the signature/claims validator.
        assert!(validate_jwt(&jwt, &jwks(), "https://idp.test", "other").is_err());
        assert!(validate_jwt(&jwt, &jwks(), "https://evil.test", "sconce").is_err());
    }

    #[test]
    fn expired_token_is_rejected() {
        let claims = json!({ "iss": "https://idp.test", "aud": "sconce", "exp": 1000, "repository": "acme/app" });
        let jwt = sign(&claims);
        assert!(validate_jwt(&jwt, &jwks(), "https://idp.test", "sconce").is_err());
    }
}
