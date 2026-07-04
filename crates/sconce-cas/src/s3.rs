//! S3-compatible CAS backend: Cloudflare R2, AWS S3, Garage, `MinIO`, Backblaze
//! B2 — anything speaking `SigV4` + path-style requests.
//!
//! A CAS needs the S3 API's absolute minimum — `PUT`/`GET`/`HEAD` on
//! fixed-shape keys (`<prefix><sha256-hex>`) plus presigned GET URLs for the
//! dist handler's 302 redirect. Notably NOT needed: multipart (package zips
//! are single-request sized), listing (the catalog knows every key), and
//! conditional writes (content-addressed keys make overwrites idempotent —
//! which is exactly why Garage's missing `If-None-Match` doesn't matter here).
//!
//! Blocking on purpose: the mirror worker that writes blobs is blocking end to
//! end (ureq, gix), and the async server's read path never touches the network
//! — `presigned_get` is pure computation, and the wire handler redirects the
//! client straight to the store.

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::sigv4::{
    EMPTY_PAYLOAD_SHA256, SigningParams, amz_date, authorization_header, presigned_get_url,
};
use crate::{BlobId, BlobStore};

/// Connection settings, read from `SCONCE_S3_*` environment variables.
#[derive(Clone)]
pub struct S3Config {
    /// `scheme://authority`, no trailing slash — e.g. `http://127.0.0.1:3900`
    /// (Garage) or `https://<account>.r2.cloudflarestorage.com` (R2).
    pub endpoint: String,
    /// `SigV4` signing region. R2 uses `auto` (our default); Garage checks it
    /// against its `s3_api.s3_region` config (default `garage`).
    pub region: String,
    pub bucket: String,
    /// Key prefix inside the bucket (default `blobs/`), so a shared bucket
    /// stays tidy and future per-tenant prefixes have somewhere to live.
    pub prefix: String,
    pub access_key: String,
    pub secret_key: String,
}

impl std::fmt::Debug for S3Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the secret key.
        f.debug_struct("S3Config")
            .field("endpoint", &self.endpoint)
            .field("region", &self.region)
            .field("bucket", &self.bucket)
            .field("prefix", &self.prefix)
            .field("access_key", &self.access_key)
            .finish_non_exhaustive()
    }
}

impl S3Config {
    /// Read `SCONCE_S3_*`: `None` when `SCONCE_S3_BUCKET` is unset (the
    /// filesystem store applies); an error when the backend is switched on but
    /// incompletely configured — half-configured storage must not fall back
    /// silently to a local directory.
    pub fn from_env() -> io::Result<Option<Self>> {
        let var = |name: &str| std::env::var(name).ok().filter(|v| !v.trim().is_empty());
        let Some(bucket) = var("SCONCE_S3_BUCKET") else {
            return Ok(None);
        };
        let require = |name: &str| {
            var(name).ok_or_else(|| {
                io::Error::other(format!(
                    "SCONCE_S3_BUCKET is set but {name} is missing — the S3 CAS backend needs \
                     SCONCE_S3_ENDPOINT, SCONCE_S3_ACCESS_KEY and SCONCE_S3_SECRET_KEY \
                     (optional: SCONCE_S3_REGION, default `auto`; SCONCE_S3_PREFIX, default `blobs/`)"
                ))
            })
        };
        Ok(Some(Self {
            endpoint: require("SCONCE_S3_ENDPOINT")?
                .trim_end_matches('/')
                .to_owned(),
            region: var("SCONCE_S3_REGION").unwrap_or_else(|| "auto".to_owned()),
            bucket,
            prefix: var("SCONCE_S3_PREFIX").unwrap_or_else(|| "blobs/".to_owned()),
            access_key: require("SCONCE_S3_ACCESS_KEY")?,
            secret_key: require("SCONCE_S3_SECRET_KEY")?,
        }))
    }
}

/// S3-backed [`BlobStore`]. Cheap to clone (the agent pools connections
/// behind an `Arc`).
#[derive(Debug, Clone)]
pub struct S3BlobStore {
    cfg: S3Config,
    /// The authority part of `endpoint` (`host[:port]`) — `SigV4` signs it.
    host: String,
    agent: ureq::Agent,
}

impl S3BlobStore {
    pub fn new(cfg: S3Config) -> io::Result<Self> {
        let host = cfg
            .endpoint
            .strip_prefix("https://")
            .or_else(|| cfg.endpoint.strip_prefix("http://"))
            .filter(|h| !h.is_empty() && !h.contains('/'))
            .ok_or_else(|| {
                io::Error::other(format!(
                    "SCONCE_S3_ENDPOINT must be scheme://host[:port] with no path, got {:?}",
                    cfg.endpoint
                ))
            })?
            .to_owned();
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_mins(2))
            .build();
        Ok(Self { cfg, host, agent })
    }

    /// Absolute path of a blob's object (path-style addressing):
    /// `/<bucket>/<prefix><hex>`. Hex keys and sane prefixes need no escaping.
    fn canonical_uri(&self, id: &BlobId) -> String {
        format!("/{}/{}{}", self.cfg.bucket, self.cfg.prefix, id.to_hex())
    }

    fn url(&self, id: &BlobId) -> String {
        format!("{}{}", self.cfg.endpoint, self.canonical_uri(id))
    }

    fn params<'a>(&'a self, amz_date: &'a str) -> SigningParams<'a> {
        SigningParams {
            access_key: &self.cfg.access_key,
            secret_key: &self.cfg.secret_key,
            region: &self.cfg.region,
            amz_date,
        }
    }

    /// A signed request builder for `method` on a blob's object.
    fn request(&self, method: &str, id: &BlobId, payload_sha256_hex: &str) -> ureq::Request {
        let date = amz_date(now_unix());
        let auth = authorization_header(
            &self.params(&date),
            method,
            &self.host,
            &self.canonical_uri(id),
            payload_sha256_hex,
        );
        self.agent
            .request(method, &self.url(id))
            .set("x-amz-date", &date)
            .set("x-amz-content-sha256", payload_sha256_hex)
            .set("authorization", &auth)
    }

    /// A presigned GET URL for a blob, valid `expires_secs` from now. Pure
    /// computation — no round-trip — so it's safe on the async serving path.
    #[must_use]
    pub fn presigned_get(&self, id: &BlobId, expires_secs: u64) -> String {
        let date = amz_date(now_unix());
        presigned_get_url(
            &self.params(&date),
            &self.cfg.endpoint,
            &self.host,
            &self.canonical_uri(id),
            expires_secs,
        )
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Map a ureq error to `Ok(None)`-style absence (404) or an `io::Error` carrying
/// the S3 status and body (S3 errors are short XML documents worth surfacing).
fn classify(op: &str, err: ureq::Error) -> Result<(), io::Error> {
    match err {
        ureq::Error::Status(404, _) => Ok(()),
        ureq::Error::Status(code, resp) => {
            let body = resp.into_string().unwrap_or_default();
            Err(io::Error::other(format!(
                "S3 {op} failed with {code}: {}",
                body.trim()
            )))
        }
        ureq::Error::Transport(t) => Err(io::Error::other(format!("S3 {op} transport: {t}"))),
    }
}

impl BlobStore for S3BlobStore {
    fn put(&self, bytes: &[u8]) -> io::Result<BlobId> {
        let id = BlobId::of(bytes);
        // Put-if-absent: skip the upload when the content is already there.
        // (A lost race just re-PUTs identical bytes to the same key — the
        // overwrite is idempotent by content-addressing.)
        if self.exists(&id)? {
            return Ok(id);
        }
        let payload_hex = id.to_hex(); // the blob id IS the payload hash
        match self
            .request("PUT", &id, &payload_hex)
            .set("content-type", "application/octet-stream")
            .send_bytes(bytes)
        {
            Ok(_) => Ok(id),
            Err(e) => {
                classify("PUT", e)?;
                // A 404 on PUT means the bucket itself is missing.
                Err(io::Error::other(
                    "S3 PUT returned 404 — does the bucket exist?",
                ))
            }
        }
    }

    fn exists(&self, id: &BlobId) -> io::Result<bool> {
        match self.request("HEAD", id, EMPTY_PAYLOAD_SHA256).call() {
            Ok(_) => Ok(true),
            Err(e) => {
                classify("HEAD", e)?;
                Ok(false)
            }
        }
    }

    fn get(&self, id: &BlobId) -> io::Result<Option<Vec<u8>>> {
        match self.request("GET", id, EMPTY_PAYLOAD_SHA256).call() {
            Ok(resp) => {
                let mut bytes = Vec::new();
                io::Read::read_to_end(&mut resp.into_reader(), &mut bytes)?;
                Ok(Some(bytes))
            }
            Err(e) => {
                classify("GET", e)?;
                Ok(None)
            }
        }
    }

    fn delete(&self, id: &BlobId) -> io::Result<()> {
        // DELETE is idempotent on S3 (a missing key still returns 204); the
        // 404 classification keeps any stricter backend idempotent too.
        match self.request("DELETE", id, EMPTY_PAYLOAD_SHA256).call() {
            Ok(_) => Ok(()),
            Err(e) => classify("DELETE", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> S3Config {
        S3Config {
            endpoint: "http://127.0.0.1:3900".to_owned(),
            region: "garage".to_owned(),
            bucket: "sconce".to_owned(),
            prefix: "blobs/".to_owned(),
            access_key: "GK-test".to_owned(),
            secret_key: "secret".to_owned(),
        }
    }

    #[test]
    fn canonical_uri_and_url_are_path_style() {
        let store = S3BlobStore::new(cfg()).unwrap();
        let id = BlobId::of(b"x");
        assert_eq!(
            store.canonical_uri(&id),
            format!("/sconce/blobs/{}", id.to_hex())
        );
        assert!(
            store
                .url(&id)
                .starts_with("http://127.0.0.1:3900/sconce/blobs/")
        );
        assert_eq!(store.host, "127.0.0.1:3900");
    }

    #[test]
    fn endpoint_with_a_path_is_rejected() {
        let mut c = cfg();
        c.endpoint = "http://127.0.0.1:3900/extra".to_owned();
        assert!(S3BlobStore::new(c).is_err());
    }

    #[test]
    fn presigned_get_carries_the_query_signature() {
        let store = S3BlobStore::new(cfg()).unwrap();
        let id = BlobId::of(b"x");
        let url = store.presigned_get(&id, 300);
        assert!(url.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"));
        assert!(url.contains("X-Amz-Expires=300"));
        assert!(url.contains("%2Fgarage%2Fs3%2Faws4_request"));
        assert!(url.contains("&X-Amz-Signature="));
    }

    #[test]
    fn debug_never_prints_the_secret() {
        let printed = format!("{:?}", S3BlobStore::new(cfg()).unwrap());
        assert!(!printed.contains("secret"), "{printed}");
    }
}
