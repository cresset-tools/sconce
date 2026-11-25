//! `sconce org-export` / `sconce org-import`: an organization moved between
//! instances as one gzipped tar.
//!
//! ```text
//! manifest.json            format, sconce version, org, migrations, row counts
//! tables/NN-<table>.jsonl  one JSON row per line, in import order
//! blobs/<sha256 hex>       every dist and snapshot the rows reference
//! ```
//!
//! The rows are [`sconce_catalog::transfer::OrgDump`]; this module adds the
//! blob bytes and the file. Entries are written in that order, so an import
//! reads the rows, checks the target will take them, stores the blobs, and only
//! then writes the rows — a refused import leaves no stray blobs behind.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};
use sconce_cas::{BlobId, BlobStore};
use sconce_catalog::transfer::OrgDump;
use serde_json::{Value, json};

/// Bundle format identifier (manifest `format`).
const FORMAT: &str = "sconce-org-export";
/// Bundle format version; bump on an incompatible layout change.
const FORMAT_VERSION: u64 = 1;

/// Write `org`'s rows and blobs to `out`.
pub fn export(org: &str, out: &Path, cas: Option<&Path>, database_url: &str) -> Result<()> {
    let store = crate::open_store(cas)?;
    let runtime = tokio::runtime::Runtime::new().context("starting async runtime")?;
    let dump = runtime.block_on(async {
        let catalog = sconce_catalog::Catalog::connect(database_url)
            .await
            .context("connecting to Postgres")?;
        catalog.migrate().await.context("applying migrations")?;
        catalog
            .export_org(org)
            .await
            .with_context(|| format!("reading organization '{org}'"))
    })?;

    let file = create_private(out)?;
    let gz = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
    let mut tar = tar::Builder::new(gz);

    let counts: serde_json::Map<String, Value> = dump
        .tables
        .iter()
        .map(|(t, rows)| (t.clone(), json!(rows.len())))
        .collect();
    let blobs = dump.blobs();
    let manifest = json!({
        "format": FORMAT,
        "format_version": FORMAT_VERSION,
        "sconce_version": env!("CARGO_PKG_VERSION"),
        "org": dump.org,
        "migrations": dump.migrations,
        "rows": counts,
        "blobs": blobs.len(),
        "secrets": dump.has_secrets(),
    });
    append(
        &mut tar,
        "manifest.json",
        &serde_json::to_vec_pretty(&manifest)?,
    )?;

    for (i, (table, rows)) in dump.tables.iter().enumerate() {
        let mut body = Vec::new();
        for row in rows {
            serde_json::to_writer(&mut body, row)?;
            body.push(b'\n');
        }
        append(&mut tar, &format!("tables/{i:02}-{table}.jsonl"), &body)?;
    }

    let mut bytes_total: u64 = 0;
    for (sha, _) in &blobs {
        let id = BlobId::from_bytes(*sha);
        let bytes = store.get(&id).context("reading a blob")?.with_context(|| {
            format!(
                "blob {} is in the catalog but not in the store",
                id.to_hex()
            )
        })?;
        bytes_total += bytes.len() as u64;
        append(&mut tar, &format!("blobs/{}", id.to_hex()), &bytes)?;
    }
    tar.into_inner()?.finish()?.flush()?;

    eprintln!(
        "Exported {org}: {} rows, {} blobs ({}) to {}.",
        dump.tables.iter().map(|(_, r)| r.len()).sum::<usize>(),
        blobs.len(),
        human_bytes(bytes_total),
        out.display()
    );
    for (table, n) in &dump.left_behind {
        eprintln!("  left behind: {n} {table} row(s) referencing another organization");
    }
    if dump.has_secrets() {
        eprintln!(
            "  {} holds decrypted upstream credentials or license keys: keep it private \
             and delete it after the import.",
            out.display()
        );
    }
    Ok(())
}

/// Read a bundle written by [`export`] into this instance.
pub fn import(bundle: &Path, cas: Option<&Path>, database_url: &str) -> Result<()> {
    let store = crate::open_store(cas)?;
    let runtime = tokio::runtime::Runtime::new().context("starting async runtime")?;
    let catalog = runtime.block_on(async {
        let catalog = sconce_catalog::Catalog::connect(database_url)
            .await
            .context("connecting to Postgres")?;
        catalog.migrate().await.context("applying migrations")?;
        anyhow::Ok(catalog)
    })?;

    let file =
        std::fs::File::open(bundle).with_context(|| format!("opening {}", bundle.display()))?;
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(file));

    let mut manifest: Option<Value> = None;
    let mut tables: Vec<(String, String, Vec<Value>)> = Vec::new();
    let mut dump: Option<OrgDump> = None;
    let mut want_blobs: Vec<([u8; 32], i64)> = Vec::new();
    let mut stored = 0usize;

    for entry in tar.entries().context("reading the bundle")? {
        let mut entry = entry.context("reading the bundle")?;
        let path = entry.path()?.to_string_lossy().into_owned();
        if path == "manifest.json" {
            let m: Value = serde_json::from_reader(&mut entry).context("reading manifest.json")?;
            check_manifest(&m)?;
            manifest = Some(m);
        } else if let Some(name) = path.strip_prefix("tables/") {
            let (order, table) = name
                .strip_suffix(".jsonl")
                .and_then(|n| n.split_once('-'))
                .with_context(|| format!("unexpected bundle entry {path}"))?;
            let mut rows = Vec::new();
            for line in BufReader::new(&mut entry).lines() {
                let line = line?;
                if !line.is_empty() {
                    rows.push(
                        serde_json::from_str(&line).with_context(|| format!("reading {path}"))?,
                    );
                }
            }
            tables.push((order.to_owned(), table.to_owned(), rows));
        } else if let Some(hex) = path.strip_prefix("blobs/") {
            // The first blob ends the rows: check the target accepts them before
            // storing anything.
            if dump.is_none() {
                let d = assemble(manifest.as_ref(), std::mem::take(&mut tables))?;
                runtime
                    .block_on(catalog.check_import(&d))
                    .context("this instance cannot take the bundle")?;
                want_blobs = d.blobs();
                dump = Some(d);
            }
            let mut bytes = Vec::with_capacity(usize::try_from(entry.size()).unwrap_or(0));
            entry.read_to_end(&mut bytes)?;
            let id = store.put(&bytes).context("storing a blob")?;
            if id.to_hex() != hex {
                bail!("blob {hex} in the bundle does not match its contents");
            }
            stored += 1;
        } else {
            bail!("unexpected bundle entry {path}");
        }
    }
    let dump = if let Some(d) = dump {
        d
    } else {
        let d = assemble(manifest.as_ref(), tables)?;
        runtime
            .block_on(catalog.check_import(&d))
            .context("this instance cannot take the bundle")?;
        want_blobs = d.blobs();
        d
    };
    if stored != want_blobs.len() {
        bail!(
            "the bundle has {stored} blobs but its rows reference {}; it is truncated",
            want_blobs.len()
        );
    }

    let report = runtime
        .block_on(catalog.import_org(&dump))
        .with_context(|| format!("importing organization '{}'", dump.org))?;
    let rows: u64 = report.rows.iter().map(|(_, n)| n).sum();
    eprintln!("Imported {}: {rows} rows, {stored} blobs.", dump.org);
    for (table, n) in report.rows.iter().filter(|(_, n)| *n > 0) {
        eprintln!("  {table}: {n}");
    }
    Ok(())
}

/// `1.2 MB`-style size, in whole tenths.
fn human_bytes(n: u64) -> String {
    let (unit, div) = match n {
        0..1_000_000 => ("kB", 1_000),
        1_000_000..1_000_000_000 => ("MB", 1_000_000),
        _ => ("GB", 1_000_000_000),
    };
    let tenths = n * 10 / div;
    format!("{}.{} {unit}", tenths / 10, tenths % 10)
}

fn check_manifest(m: &Value) -> Result<()> {
    if m.get("format").and_then(Value::as_str) != Some(FORMAT) {
        bail!("not a sconce organization export");
    }
    let version = m.get("format_version").and_then(Value::as_u64).unwrap_or(0);
    if version != FORMAT_VERSION {
        bail!(
            "bundle format {version} is not supported by sconce {} (it reads format {FORMAT_VERSION})",
            env!("CARGO_PKG_VERSION")
        );
    }
    Ok(())
}

/// Build the dump from the manifest and the table entries, in their order.
fn assemble(
    manifest: Option<&Value>,
    mut tables: Vec<(String, String, Vec<Value>)>,
) -> Result<OrgDump> {
    let m = manifest.context("the bundle has no manifest.json")?;
    let org = m
        .get("org")
        .and_then(Value::as_str)
        .context("manifest.json has no org")?
        .to_owned();
    let migrations = m
        .get("migrations")
        .and_then(Value::as_array)
        .context("manifest.json has no migrations")?
        .iter()
        .filter_map(|v| v.as_str().map(ToOwned::to_owned))
        .collect();
    tables.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(OrgDump {
        org,
        migrations,
        tables: tables.into_iter().map(|(_, t, rows)| (t, rows)).collect(),
        left_behind: Vec::new(),
    })
}

fn append<W: Write>(tar: &mut tar::Builder<W>, path: &str, bytes: &[u8]) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o600);
    header.set_mtime(0);
    header.set_cksum();
    tar.append_data(&mut header, path, bytes)
        .with_context(|| format!("writing {path}"))
}

/// Create `path` readable by its owner only: the bundle can hold secrets.
fn create_private(path: &Path) -> Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    opts.open(path)
        .with_context(|| format!("creating {} (it must not exist yet)", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_must_be_an_org_export_of_this_format() {
        assert!(check_manifest(&json!({"format": FORMAT, "format_version": 1})).is_ok());
        assert!(check_manifest(&json!({"format": "other", "format_version": 1})).is_err());
        assert!(check_manifest(&json!({"format": FORMAT, "format_version": 2})).is_err());
    }

    #[test]
    fn sizes_read_in_tenths() {
        assert_eq!(human_bytes(4_108), "4.1 kB");
        assert_eq!(human_bytes(249_000_000), "249.0 MB");
        assert_eq!(human_bytes(12_300_000_000), "12.3 GB");
    }

    #[test]
    fn tables_are_assembled_in_bundle_order() {
        let m = json!({"org": "acme", "migrations": ["0001"]});
        let tables = vec![
            ("01".to_owned(), "repositories".to_owned(), vec![]),
            (
                "00".to_owned(),
                "organizations".to_owned(),
                vec![json!({"id": "x"})],
            ),
        ];
        let dump = assemble(Some(&m), tables).unwrap();
        assert_eq!(dump.org, "acme");
        assert_eq!(dump.tables[0].0, "organizations");
        assert_eq!(dump.tables[1].0, "repositories");
    }
}
