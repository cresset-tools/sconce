//! Render Composer **v2** repository metadata from catalog rows.
//!
//! Two documents make up the v2 wire format a Composer 2 client consumes:
//!
//! - The **root** `packages.json` ([`render_root`]) — tells the client where to
//!   find per-package metadata via a `metadata-url` template and (optionally)
//!   lists the `available-packages`.
//! - The **per-package** document at `p2/{vendor}/{name}.json`
//!   ([`render_package`]) — the list of versions, each being that version's
//!   `composer.json` plus `version`, `version_normalized`, and a `dist` block
//!   pointing at our content-addressed download endpoint.
//!
//! These are pure functions over [`sconce_catalog`] data, so they're trivially
//! testable and the HTTP layer is thin glue on top. (Composer v1
//! `provider-includes` output is a later addition; modern clients only need v2.)

#![forbid(unsafe_code)]

use composer_wire::{PackageDocument, RootManifest};
use sconce_catalog::PackageVersion;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

/// Render the root `packages.json`.
///
/// `base_url` is the repository's public base (no trailing slash needed); the
/// emitted `metadata-url` is `<base>/p2/%package%.json`, the template Composer
/// expands per package.
///
/// # Panics
/// Never in practice: serializing a [`RootManifest`] is infallible for its
/// plain `String`/`Vec`/`Map` fields.
#[must_use]
pub fn render_root(package_names: &[String], base_url: &str) -> Value {
    let root = RootManifest::v2(base_url, package_names.to_vec());
    serde_json::to_value(root).expect("RootManifest always serializes")
}

/// Render the per-package document for `name` at `p2/{name}.json`.
///
/// # Panics
/// Never in practice: serializing a [`PackageDocument`] is infallible for its
/// plain `String`/`Map` contents.
#[must_use]
pub fn render_package(name: &str, versions: &[PackageVersion], base_url: &str) -> Value {
    let base = base_url.trim_end_matches('/');
    let entries: Vec<Map<String, Value>> = versions
        .iter()
        .map(|v| version_entry(name, v, base))
        .collect();
    let mut packages = BTreeMap::new();
    packages.insert(name.to_owned(), entries);
    serde_json::to_value(PackageDocument::flat(packages))
        .expect("PackageDocument always serializes")
}

/// One version entry: the stored `composer.json` with `version`,
/// `version_normalized`, and `dist` injected/overridden.
fn version_entry(name: &str, v: &PackageVersion, base: &str) -> Map<String, Value> {
    let mut obj = match &v.composer_json {
        Value::Object(m) => m.clone(),
        // A non-object composer.json is malformed; start from nothing rather
        // than propagate it.
        _ => Map::new(),
    };
    obj.insert("name".to_owned(), json!(name));
    obj.insert("version".to_owned(), json!(v.version));
    obj.insert("version_normalized".to_owned(), json!(v.normalized_version));

    if let Some(sha256) = v.dist_blob_sha256 {
        let hex = hex32(&sha256);
        let mut dist = Map::new();
        dist.insert("type".to_owned(), json!("zip"));
        // Content-addressed download path; the dist endpoint resolves the hex
        // back to the CAS blob.
        dist.insert(
            "url".to_owned(),
            json!(format!("{base}/dist/{name}/{hex}.zip")),
        );
        if let Some(shasum) = &v.dist_shasum {
            dist.insert("shasum".to_owned(), json!(shasum));
        }
        obj.insert("dist".to_owned(), Value::Object(dist));
    }

    obj
}

/// Lowercase hex of a 32-byte digest.
fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(composer_json: Value, dist: Option<([u8; 32], &str)>) -> PackageVersion {
        PackageVersion {
            version: "v1.2.0".to_owned(),
            normalized_version: "1.2.0.0".to_owned(),
            stability: "stable".to_owned(),
            composer_json,
            dist_blob_sha256: dist.map(|(s, _)| s),
            dist_shasum: dist.map(|(_, h)| h.to_owned()),
            source_reference: None,
        }
    }

    #[test]
    fn root_has_metadata_url_and_available_packages() {
        let root = render_root(
            &["acme/widget".to_owned(), "acme/gadget".to_owned()],
            "https://r.test/",
        );
        assert_eq!(root["metadata-url"], "https://r.test/p2/%package%.json");
        assert_eq!(
            root["available-packages"],
            json!(["acme/widget", "acme/gadget"])
        );
    }

    #[test]
    fn package_entry_merges_composer_json_with_version_and_dist() {
        let cj = json!({
            "name": "acme/widget",
            "require": {"php": ">=8.1"},
            "autoload": {"psr-4": {"Acme\\Widget\\": "src/"}},
        });
        let v = version(
            cj,
            Some(([0xab; 32], "da39a3ee5e6b4b0d3255bfef95601890afd80709")),
        );
        let doc = render_package("acme/widget", &[v], "https://r.test");

        let entry = &doc["packages"]["acme/widget"][0];
        // composer.json fields preserved.
        assert_eq!(entry["require"]["php"], ">=8.1");
        assert_eq!(entry["autoload"]["psr-4"]["Acme\\Widget\\"], "src/");
        // version fields injected.
        assert_eq!(entry["version"], "v1.2.0");
        assert_eq!(entry["version_normalized"], "1.2.0.0");
        // dist block points at the content-addressed endpoint with the sha1.
        assert_eq!(entry["dist"]["type"], "zip");
        assert_eq!(
            entry["dist"]["url"],
            format!("https://r.test/dist/acme/widget/{}.zip", "ab".repeat(32))
        );
        assert_eq!(
            entry["dist"]["shasum"],
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }

    #[test]
    fn no_dist_block_when_no_blob() {
        let v = version(json!({"name": "acme/widget"}), None);
        let doc = render_package("acme/widget", &[v], "https://r.test");
        assert!(doc["packages"]["acme/widget"][0].get("dist").is_none());
    }
}
