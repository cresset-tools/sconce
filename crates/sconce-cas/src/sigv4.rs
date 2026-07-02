//! AWS Signature Version 4 — exactly the two shapes the S3 CAS backend needs:
//! header-signed requests (PUT/GET/HEAD a blob) and presigned GET URLs (the
//! dist handler's 302 target). Pure computation, no I/O, no clock — callers
//! pass the timestamp — so every path is unit-testable against AWS's
//! documented example vectors.
//!
//! Hand-rolled deliberately: the full `object_store`/AWS-SDK stack is async
//! and heavy, while sconce's store trait is sync (the mirror worker is
//! blocking end to end) and a CAS needs only three verbs on fixed-shape keys.
//! `SigV4` itself is a short HMAC chain over a canonical request; the
//! subtleties live in canonicalization, which the fixed key shape
//! (`/bucket/prefix/hex`) keeps trivial.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// Everything constant across one request signature.
pub struct SigningParams<'a> {
    pub access_key: &'a str,
    pub secret_key: &'a str,
    pub region: &'a str,
    /// `YYYYMMDD'T'HHMMSS'Z'` — also provides the date scope (first 8 chars).
    pub amz_date: &'a str,
}

impl std::fmt::Debug for SigningParams<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the secret key.
        f.debug_struct("SigningParams")
            .field("access_key", &self.access_key)
            .field("region", &self.region)
            .field("amz_date", &self.amz_date)
            .finish_non_exhaustive()
    }
}

/// The sha256 of an empty payload — GET/HEAD requests sign this.
pub const EMPTY_PAYLOAD_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// `Authorization` header value for a header-signed request whose signed
/// headers are exactly `host`, `x-amz-content-sha256`, and `x-amz-date` (the
/// caller must send those three with the same values).
pub fn authorization_header(
    p: &SigningParams<'_>,
    method: &str,
    host: &str,
    canonical_uri: &str,
    payload_sha256_hex: &str,
) -> String {
    let canonical_request = format!(
        "{method}\n{canonical_uri}\n\nhost:{host}\nx-amz-content-sha256:{payload_sha256_hex}\nx-amz-date:{}\n\nhost;x-amz-content-sha256;x-amz-date\n{payload_sha256_hex}",
        p.amz_date
    );
    let signature = sign(p, &canonical_request);
    format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={signature}",
        p.access_key,
        scope(p)
    )
}

/// A complete presigned GET URL, valid for `expires_secs` from `amz_date`.
/// `endpoint` is `scheme://authority` (no trailing slash); `canonical_uri` is
/// the absolute path (`/bucket/key…`, already URI-safe).
pub fn presigned_get_url(
    p: &SigningParams<'_>,
    endpoint: &str,
    host: &str,
    canonical_uri: &str,
    expires_secs: u64,
) -> String {
    // Already in canonical (byte-sorted) key order.
    let query = format!(
        "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential={}&X-Amz-Date={}&X-Amz-Expires={expires_secs}&X-Amz-SignedHeaders=host",
        uri_encode(&format!("{}/{}", p.access_key, scope(p))),
        p.amz_date
    );
    let canonical_request =
        format!("GET\n{canonical_uri}\n{query}\nhost:{host}\n\nhost\nUNSIGNED-PAYLOAD");
    let signature = sign(p, &canonical_request);
    format!("{endpoint}{canonical_uri}?{query}&X-Amz-Signature={signature}")
}

/// The credential scope: `<date>/<region>/s3/aws4_request`.
fn scope(p: &SigningParams<'_>) -> String {
    format!("{}/{}/s3/aws4_request", &p.amz_date[..8], p.region)
}

/// Canonical request → string-to-sign → HMAC chain → hex signature.
fn sign(p: &SigningParams<'_>, canonical_request: &str) -> String {
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        p.amz_date,
        scope(p),
        hex(&Sha256::digest(canonical_request))
    );
    let mut key = hmac_sha256(format!("AWS4{}", p.secret_key).as_bytes(), &p.amz_date[..8]);
    for part in [p.region, "s3", "aws4_request"] {
        key = hmac_sha256(&key, part);
    }
    hex(&hmac_sha256(&key, &string_to_sign))
}

fn hmac_sha256(key: &[u8], data: &str) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(data.as_bytes());
    mac.finalize().into_bytes().into()
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[usize::from(b >> 4)] as char);
        s.push(HEX[usize::from(b & 0x0f)] as char);
    }
    s
}

/// RFC 3986 strict percent-encoding (AWS "URI encode"): unreserved characters
/// pass, everything else — including `/` — becomes uppercase `%XX`. Used for
/// query values; our canonical URIs (`/bucket/blobs/<hex>`) need no encoding.
pub fn uri_encode(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push(HEX[usize::from(b >> 4)] as char);
                out.push(HEX[usize::from(b & 0x0f)] as char);
            }
        }
    }
    out
}

/// `YYYYMMDD'T'HHMMSS'Z'` for a unix timestamp (UTC). No chrono dependency —
/// the civil-from-days algorithm (Howard Hinnant) is a dozen lines.
pub fn amz_date(unix_secs: u64) -> String {
    let days = unix_secs / 86_400;
    let tod = unix_secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

/// Proleptic-Gregorian date from days since 1970-01-01. All intermediate
/// ranges are proven in the algorithm's derivation; inputs are post-1970.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AWS's own creds/date used throughout their `SigV4` documentation.
    fn aws_doc_params() -> SigningParams<'static> {
        SigningParams {
            access_key: "AKIAIOSFODNN7EXAMPLE",
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            region: "us-east-1",
            amz_date: "20130524T000000Z",
        }
    }

    /// The documented presigned-GET example ("Authenticating Requests: Using
    /// Query Parameters"): GET examplebucket/test.txt, 86400s expiry. The
    /// expected signature is printed verbatim in the AWS docs, so this pins
    /// the whole chain — canonicalization, scope, key derivation, signing.
    #[test]
    fn presigned_get_matches_the_aws_documented_vector() {
        let url = presigned_get_url(
            &aws_doc_params(),
            "https://examplebucket.s3.amazonaws.com",
            "examplebucket.s3.amazonaws.com",
            "/test.txt",
            86400,
        );
        assert!(
            url.ends_with(
                "&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
            ),
            "unexpected signature in {url}"
        );
        assert!(url.starts_with("https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host"));
    }

    /// The documented header-signed GET example ("Authenticating Requests:
    /// Using the Authorization Header" — the empty-payload variant, signed
    /// headers reduced to our fixed three-set is checked live against Garage;
    /// here we pin that the header assembles with the right shape and scope.
    #[test]
    fn authorization_header_shape() {
        let auth = authorization_header(
            &aws_doc_params(),
            "GET",
            "examplebucket.s3.amazonaws.com",
            "/test.txt",
            EMPTY_PAYLOAD_SHA256,
        );
        assert!(auth.starts_with(
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature="
        ));
        // 64 hex chars of signature.
        let sig = auth.rsplit('=').next().unwrap();
        assert_eq!(sig.len(), 64);
        assert!(sig.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn amz_date_formats_utc() {
        assert_eq!(amz_date(0), "19700101T000000Z");
        // 2013-05-24T00:00:00Z, the AWS docs timestamp.
        assert_eq!(amz_date(1_369_353_600), "20130524T000000Z");
        // A leap-year date with time-of-day parts (2024-03-01T12:03:37Z).
        assert_eq!(amz_date(1_709_294_617), "20240301T120337Z");
    }

    #[test]
    fn uri_encode_is_rfc3986_strict() {
        assert_eq!(uri_encode("abc-._~XYZ019"), "abc-._~XYZ019");
        assert_eq!(uri_encode("a/b c+d"), "a%2Fb%20c%2Bd");
        assert_eq!(uri_encode("key=/aws4_request"), "key%3D%2Faws4_request");
    }
}
