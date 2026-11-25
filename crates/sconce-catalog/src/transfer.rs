//! Moving an organization between sconce instances: every catalog row that
//! belongs to it, read out as JSON ([`Catalog::export_org`]) and written into
//! another catalog ([`Catalog::import_org`]).
//!
//! Rows travel whole (`to_jsonb` out, `jsonb_populate_recordset` in), with
//! their ids, so every reference inside the org survives unchanged and a
//! column added by a later migration is carried without touching this file.
//! What *does* need this file is a new **table**: [`TABLES`] says how to find
//! an org's rows in it, [`NOT_EXPORTED`] lists the ones deliberately left
//! behind, and a test fails when a table is in neither.
//!
//! Two kinds of value need more than a copy:
//!
//! - **Encrypted secrets** (upstream credentials, recoverable license keys) are
//!   sealed with the instance's `SCONCE_SECRET_KEY`, which the target does not
//!   share. Export decrypts them into the dump and import encrypts them under
//!   the target's key, so a dump holding them is itself a secret.
//! - **Blob refcounts** are maintained by triggers on the rows that reference a
//!   blob, so `blobs` rows are imported with a zero count and the version and
//!   snapshot rows inserted after them bring it to the right value.
//!
//! Token hashes are plain SHA-256 of the token, so read, service and publish
//! tokens keep working on the new instance, as do license keys.

use crate::Catalog;
use crate::secret::{SecretError, SecretKey};
use base64::Engine as _;
use serde_json::Value;
use uuid::Uuid;

/// The repositories of the org being exported (`$1` is the org id).
const REPOS: &str = "(select id from repositories where org_id = $1)";

/// Where an org's rows are, in the order an import must insert them (a row's
/// references come before it). Each filter is a `where` clause over the table
/// with `$1` bound to the org id.
const TABLES: &[(&str, &str)] = &[
    ("organizations", "id = $1"),
    ("org_settings", "org_id = $1"),
    ("org_entitlements", "org_id = $1"),
    (
        "slug_history",
        "org_id = $1 or (entity_type = 'org' and entity_id = $1)",
    ),
    ("repositories", "org_id = $1"),
    (
        "repository_members",
        "repo_id in REPOS and member_repo_id in REPOS",
    ),
    ("upstreams", "repo_id in REPOS"),
    ("upstream_requires", "upstream_id in UPSTREAMS"),
    ("upstream_source_paths", "upstream_id in UPSTREAMS"),
    (
        "blobs",
        "sha256 in (select dist_blob_sha256 from package_versions where package_id in PACKAGES \
         union select blob_sha256 from snapshots where repo_id in REPOS)",
    ),
    ("packages", "repo_id in REPOS"),
    ("package_versions", "package_id in PACKAGES"),
    (
        "version_conflicts",
        "package_id in PACKAGES and (upstream_id is null or upstream_id in UPSTREAMS)",
    ),
    ("package_sets", "org_id = $1"),
    (
        "package_set_members",
        "set_id in SETS and package_id in PACKAGES",
    ),
    ("package_set_rules", "set_id in SETS"),
    ("editions", "repo_id in REPOS and set_id in SETS"),
    ("license_keys", "repo_id in REPOS"),
    (
        "entitlements",
        "license_key_id in LICENSES and package_id in PACKAGES",
    ),
    (
        "license_set_entitlements",
        "license_key_id in LICENSES and set_id in SETS",
    ),
    ("license_renewals", "license_key_id in LICENSES"),
    (
        "repository_grants",
        "repo_id in REPOS and package_id in PACKAGES",
    ),
    (
        "repository_grant_rules",
        "target_repo_id in REPOS and set_id in SETS",
    ),
    ("tokens", "org_id = $1 or repo_id in REPOS"),
    ("service_tokens", "repo_id in REPOS"),
    ("publish_tokens", "repo_id in REPOS"),
    ("ci_oidc_policies", "repo_id in REPOS"),
    ("scim_tokens", "org_id = $1"),
    ("snapshots", "repo_id in REPOS"),
    ("snapshot_latest", "repo_id in REPOS"),
    ("org_remotes", "org_id = $1"),
    ("org_remote_recipes", "org_remote_id in REMOTES"),
    ("org_remote_sources", "org_remote_id in REMOTES"),
];

/// Tables an org export leaves behind, and why: they belong to the instance
/// (accounts, sign-in), are in-flight work, or are caches a sync rebuilds.
pub const NOT_EXPORTED: &[&str] = &[
    "_sconce_migrations",
    // Accounts and sign-in are per instance: users sign up (or SSO) again.
    "users",
    "user_tenants",
    "sessions",
    "password_resets",
    "oidc_connections",
    "oidc_flows",
    "device_flows",
    "authorization_codes",
    // In-flight work.
    "upload_sessions",
    "upload_parts",
    "mirror_jobs",
    // Caches the next sync or resolve rebuilds.
    "upstream_validators",
    "dependency_plan",
];

/// Rows that reference something outside the org and so cannot come along:
/// `(table, filter over the org's side of the reference)`. Export counts them
/// so the operator sees what an import will be missing.
const CROSS_ORG: &[(&str, &str)] = &[
    (
        "repository_members",
        "repo_id in REPOS and member_repo_id not in REPOS",
    ),
    (
        "repository_grants",
        "repo_id in REPOS and package_id not in PACKAGES",
    ),
    (
        "package_set_members",
        "set_id in SETS and package_id not in PACKAGES",
    ),
];

/// Encrypted columns: `(table, column)`. Export replaces each with its
/// plaintext under [`secret_field`]; import seals it again.
const SECRET_COLUMNS: &[(&str, &str)] = &[
    ("upstreams", "credential"),
    ("license_keys", "key_ciphertext"),
];

/// Rows per `jsonb_populate_recordset` insert.
const INSERT_BATCH: usize = 500;

/// The JSON field a decrypted secret travels in.
fn secret_field(column: &str) -> String {
    format!("_sconce_plaintext_{column}")
}

/// Expand the subquery names in a filter.
fn expand(filter: &str) -> String {
    filter
        .replace(
            "UPSTREAMS",
            "(select id from upstreams where repo_id in REPOS)",
        )
        .replace(
            "PACKAGES",
            "(select id from packages where repo_id in REPOS)",
        )
        .replace(
            "LICENSES",
            "(select id from license_keys where repo_id in REPOS)",
        )
        .replace("SETS", "(select id from package_sets where org_id = $1)")
        .replace("REMOTES", "(select id from org_remotes where org_id = $1)")
        .replace("REPOS", REPOS)
}

/// Errors exporting or importing an org.
#[derive(Debug, thiserror::Error)]
pub enum TransferError {
    #[error("no such organization '{0}'")]
    NoSuchOrg(String),
    #[error("organization '{0}' already exists here")]
    OrgExists(String),
    #[error(
        "the dump was made with migrations this instance does not have ({0}); \
         upgrade sconce here first"
    )]
    NewerSchema(String),
    #[error("the dump has no rows for table '{0}' (it is not an org dump)")]
    MissingTable(String),
    #[error("{table}.{column} is encrypted but SCONCE_SECRET_KEY is not set")]
    NoKey { table: String, column: String },
    #[error("decrypting {table}.{column}: {source}")]
    Decrypt {
        table: String,
        column: String,
        source: SecretError,
    },
    #[error("malformed {0} row in the dump")]
    BadRow(String),
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

/// Everything a catalog holds for one organization.
#[derive(Debug, Clone)]
pub struct OrgDump {
    /// The org's slug.
    pub org: String,
    /// Migrations applied on the source (the import side must have them all).
    pub migrations: Vec<String>,
    /// `(table, rows)`, in [`TABLES`] order.
    pub tables: Vec<(String, Vec<Value>)>,
    /// Rows referencing another org, which the dump leaves out: `(table, count)`.
    pub left_behind: Vec<(String, i64)>,
}

impl OrgDump {
    /// The blobs the dump's rows reference: `(sha256, size)`.
    #[must_use]
    pub fn blobs(&self) -> Vec<([u8; 32], i64)> {
        self.rows("blobs")
            .iter()
            .filter_map(|r| {
                let sha = decode_bytea(r.get("sha256")?.as_str()?)?;
                let sha: [u8; 32] = sha.try_into().ok()?;
                Some((sha, r.get("size_bytes")?.as_i64()?))
            })
            .collect()
    }

    /// Whether the dump carries decrypted secrets (and so must be kept private).
    #[must_use]
    pub fn has_secrets(&self) -> bool {
        SECRET_COLUMNS.iter().any(|(table, column)| {
            let field = secret_field(column);
            self.rows(table).iter().any(|r| r.get(&field).is_some())
        })
    }

    /// The rows of one table (empty if absent).
    #[must_use]
    pub fn rows(&self, table: &str) -> &[Value] {
        self.tables
            .iter()
            .find(|(t, _)| t == table)
            .map_or(&[], |(_, rows)| rows.as_slice())
    }
}

/// What an import wrote.
#[derive(Debug, Default)]
pub struct ImportReport {
    /// `(table, rows inserted)`.
    pub rows: Vec<(String, u64)>,
}

/// The table names [`Catalog::export_org`] reads, in order.
#[must_use]
pub fn exported_tables() -> Vec<&'static str> {
    TABLES.iter().map(|(t, _)| *t).collect()
}

impl Catalog {
    /// Read every row belonging to the org `slug`. Encrypted secrets are
    /// decrypted with this instance's key (so one must be set if the org has
    /// any).
    pub async fn export_org(&self, slug: &str) -> Result<OrgDump, TransferError> {
        let org_id = self
            .org_id_by_slug(slug)
            .await?
            .ok_or_else(|| TransferError::NoSuchOrg(slug.to_owned()))?;
        // One snapshot of the whole org, so rows written mid-export can't leave
        // a version pointing at a package the dump lacks.
        let mut tx = self.pool.begin().await?;
        sqlx::query("set transaction isolation level repeatable read, read only")
            .execute(&mut *tx)
            .await?;
        let migrations: Vec<String> =
            sqlx::query_scalar("select name from _sconce_migrations order by name")
                .fetch_all(&mut *tx)
                .await?;
        let mut tables = Vec::with_capacity(TABLES.len());
        for (table, filter) in TABLES {
            let sql = format!("select to_jsonb(t) from {table} t where {}", expand(filter));
            let mut rows: Vec<Value> = sqlx::query_scalar(&sql)
                .bind(org_id)
                .fetch_all(&mut *tx)
                .await?;
            if *table == "blobs" {
                // Only identity and size travel: the count is rebuilt on import.
                for r in &mut rows {
                    if let Value::Object(m) = r {
                        m.retain(|k, _| k == "sha256" || k == "size_bytes");
                    }
                }
            }
            if *table == "org_remotes" {
                // A snapshot source in another org can't come along.
                let repos: Vec<Uuid> =
                    sqlx::query_scalar("select id from repositories where org_id = $1")
                        .bind(org_id)
                        .fetch_all(&mut *tx)
                        .await?;
                for r in &mut rows {
                    drop_foreign_snapshot_repo(r, &repos);
                }
            }
            for (t, column) in SECRET_COLUMNS {
                if t == table {
                    for r in &mut rows {
                        self.reveal(r, table, column)?;
                    }
                }
            }
            tables.push(((*table).to_owned(), rows));
        }
        let mut left_behind = Vec::new();
        for (table, filter) in CROSS_ORG {
            let n: i64 = sqlx::query_scalar(&format!(
                "select count(*) from {table} where {}",
                expand(filter)
            ))
            .bind(org_id)
            .fetch_one(&mut *tx)
            .await?;
            if n > 0 {
                left_behind.push(((*table).to_owned(), n));
            }
        }
        tx.commit().await?;
        Ok(OrgDump {
            org: slug.to_owned(),
            migrations,
            tables,
            left_behind,
        })
    }

    /// Write a dump into this catalog, in one transaction. Refuses when the org
    /// (by slug or id) already exists, or when the dump needs migrations this
    /// instance lacks. Blob *bytes* are the caller's job: store them before
    /// calling this, since the rows point at them.
    pub async fn import_org(&self, dump: &OrgDump) -> Result<ImportReport, TransferError> {
        self.check_import(dump).await?;
        let mut tx = self.pool.begin().await?;
        let mut report = ImportReport::default();
        for (table, _) in TABLES {
            let mut rows = dump.rows(table).to_vec();
            for (t, column) in SECRET_COLUMNS {
                if t == table {
                    for r in &mut rows {
                        self.seal(r, table, column)?;
                    }
                }
            }
            let mut inserted = 0;
            for chunk in rows.chunks(INSERT_BATCH) {
                let sql = if *table == "blobs" {
                    // Shared with whatever else this instance stores: keep an
                    // existing row (and its count) and only start a new one at 0.
                    "insert into blobs (sha256, size_bytes) \
                     select sha256, size_bytes from jsonb_populate_recordset(null::blobs, $1) \
                     on conflict (sha256) do update set last_seen_at = now()"
                        .to_owned()
                } else {
                    format!(
                        "insert into {table} select * from jsonb_populate_recordset(null::{table}, $1)"
                    )
                };
                inserted += sqlx::query(&sql)
                    .bind(Value::Array(chunk.to_vec()))
                    .execute(&mut *tx)
                    .await?
                    .rows_affected();
            }
            report.rows.push(((*table).to_owned(), inserted));
        }
        tx.commit().await?;
        Ok(report)
    }

    /// Whether [`Self::import_org`] would accept `dump`, checked without
    /// writing anything: this instance has every migration the dump was made
    /// with, the org is not here yet (by slug or id), and a secret key is set
    /// if the dump carries secrets.
    pub async fn check_import(&self, dump: &OrgDump) -> Result<(), TransferError> {
        if dump.has_secrets() && self.secret_key.is_none() {
            let (table, column) = SECRET_COLUMNS[0];
            return Err(TransferError::NoKey {
                table: table.to_owned(),
                column: column.to_owned(),
            });
        }
        let have: Vec<String> = sqlx::query_scalar("select name from _sconce_migrations")
            .fetch_all(&self.pool)
            .await?;
        let missing: Vec<&str> = dump
            .migrations
            .iter()
            .filter(|m| !have.contains(m))
            .map(String::as_str)
            .collect();
        if !missing.is_empty() {
            return Err(TransferError::NewerSchema(missing.join(", ")));
        }
        let org = dump
            .rows("organizations")
            .first()
            .ok_or_else(|| TransferError::MissingTable("organizations".to_owned()))?;
        let org_id = org
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| TransferError::BadRow("organizations".to_owned()))?;
        let exists: bool = sqlx::query_scalar(
            "select exists(select 1 from organizations where slug = $1 or id::text = $2)",
        )
        .bind(&dump.org)
        .bind(org_id)
        .fetch_one(&self.pool)
        .await?;
        if exists {
            return Err(TransferError::OrgExists(dump.org.clone()));
        }
        Ok(())
    }

    /// Replace an encrypted column with its plaintext (export side).
    fn reveal(&self, row: &mut Value, table: &str, column: &str) -> Result<(), TransferError> {
        let Value::Object(m) = row else {
            return Err(TransferError::BadRow(table.to_owned()));
        };
        let Some(sealed) = m.get(column).and_then(Value::as_str) else {
            return Ok(());
        };
        let sealed = decode_bytea(sealed).ok_or_else(|| TransferError::BadRow(table.to_owned()))?;
        let key = self.key_for(table, column)?;
        let plain = key
            .decrypt(&sealed)
            .map_err(|source| TransferError::Decrypt {
                table: table.to_owned(),
                column: column.to_owned(),
                source,
            })?;
        m.insert(column.to_owned(), Value::Null);
        m.insert(
            secret_field(column),
            Value::String(base64::engine::general_purpose::STANDARD.encode(plain)),
        );
        Ok(())
    }

    /// Seal a revealed secret under this instance's key (import side).
    fn seal(&self, row: &mut Value, table: &str, column: &str) -> Result<(), TransferError> {
        let Value::Object(m) = row else {
            return Err(TransferError::BadRow(table.to_owned()));
        };
        let Some(plain) = m.remove(&secret_field(column)) else {
            return Ok(());
        };
        let plain = plain
            .as_str()
            .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
            .ok_or_else(|| TransferError::BadRow(table.to_owned()))?;
        let sealed = self.key_for(table, column)?.encrypt(&plain);
        m.insert(column.to_owned(), Value::String(encode_bytea(&sealed)));
        Ok(())
    }

    fn key_for(&self, table: &str, column: &str) -> Result<&SecretKey, TransferError> {
        self.secret_key
            .as_ref()
            .ok_or_else(|| TransferError::NoKey {
                table: table.to_owned(),
                column: column.to_owned(),
            })
    }
}

/// Null an org remote's snapshot source when it is a repository outside the org.
fn drop_foreign_snapshot_repo(row: &mut Value, repos: &[Uuid]) {
    let Some(m) = row.as_object_mut() else { return };
    let foreign = m
        .get("snapshot_repo_id")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
        .is_some_and(|id| !repos.contains(&id));
    if foreign {
        m.insert("snapshot_repo_id".to_owned(), Value::Null);
    }
}

/// `bytea` as `to_jsonb` renders it: `\x` + lowercase hex.
fn decode_bytea(s: &str) -> Option<Vec<u8>> {
    let hex = s.strip_prefix("\\x")?;
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
        .collect()
}

fn encode_bytea(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("\\x");
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytea_round_trips() {
        let bytes = [0u8, 1, 0xab, 0xff];
        assert_eq!(encode_bytea(&bytes), "\\x0001abff");
        assert_eq!(decode_bytea("\\x0001abff").unwrap(), bytes);
        assert!(decode_bytea("0001").is_none());
        assert!(decode_bytea("\\x0g").is_none());
    }

    #[test]
    fn filters_expand_to_plain_sql() {
        for (table, filter) in TABLES.iter().chain(CROSS_ORG) {
            let sql = expand(filter);
            for name in [
                "REPOS",
                "UPSTREAMS",
                "PACKAGES",
                "LICENSES",
                "SETS",
                "REMOTES",
            ] {
                assert!(!sql.contains(name), "{table}: {sql}");
            }
        }
    }

    async fn catalog(key: &str) -> Option<Catalog> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let pool = sqlx::PgPool::connect(&url).await.expect("connect");
        let cat = Catalog::with_secret(pool, Some(SecretKey::from_base64(key).unwrap()));
        cat.migrate().await.expect("migrate");
        Some(cat)
    }

    const KEY_A: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    const KEY_B: &str = "HxweHRwbGhkYFxYVFBMSERAPDg0MCwoJCAcGBQQDAgE=";

    /// A new table must be exported or listed as left behind, or an export
    /// would silently drop it.
    #[tokio::test]
    async fn every_table_is_exported_or_left_behind() {
        let Some(cat) = catalog(KEY_A).await else {
            return;
        };
        let tables: Vec<String> = sqlx::query_scalar(
            "select tablename::text from pg_tables where schemaname = current_schema()",
        )
        .fetch_all(&cat.pool)
        .await
        .unwrap();
        let unclassified: Vec<&String> = tables
            .iter()
            .filter(|t| {
                !exported_tables().contains(&t.as_str()) && !NOT_EXPORTED.contains(&t.as_str())
            })
            .collect();
        assert!(
            unclassified.is_empty(),
            "add to TABLES or NOT_EXPORTED: {unclassified:?}"
        );
    }

    /// Export an org, delete it, import it under another secret key: the rows
    /// come back the same, tokens and license keys still authenticate, and the
    /// secrets decrypt under the new key.
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn org_round_trips_through_a_dump() {
        let Some(a) = catalog(KEY_A).await else {
            return;
        };
        let slug = format!("xfer{}", std::process::id());
        let org_id = a.create_org(&slug, Some("Transfer")).await.unwrap();
        let repo = a.create_repo(&slug, "store").await.unwrap();
        let upstream = a
            .create_upstream(
                repo,
                "composer",
                "https://example.test",
                crate::Visibility::Private,
                Some("vendor"),
                Some(&SecretKey::from_base64(KEY_A).unwrap().encrypt(b"user:pass")),
                "basic",
            )
            .await
            .unwrap();
        let pkg = a
            .upsert_package(
                repo,
                "acme/tool",
                "library",
                None,
                crate::Visibility::Private,
            )
            .await
            .unwrap();
        // Unique per run: other tests share the database and its blobs.
        let mut sha = [0u8; 32];
        sha[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        sha[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        a.upsert_blob(&sha, 123).await.unwrap();
        a.upsert_package_version(
            pkg,
            "1.0.0",
            "1.0.0.0",
            "stable",
            &serde_json::json!({"name": "acme/tool", "version": "1.0.0"}),
            Some(&sha),
            Some("abc"),
            None,
            None,
        )
        .await
        .unwrap();
        let set = a.create_package_set(org_id, "everything").await.unwrap();
        a.add_set_member(set, pkg).await.unwrap();
        a.create_edition(
            repo,
            "Pro",
            Some("pro"),
            set,
            &crate::EditionBound::Perpetual,
            false,
            &crate::PolicyOverride::default(),
        )
        .await
        .unwrap()
        .unwrap();
        let license = a
            .issue_license(repo, Some("buyer-1"), &["acme/tool"])
            .await
            .unwrap()
            .unwrap();
        let token = a.create_token(repo, Some("ci"), None).await.unwrap();
        let (service, _) = a
            .create_service_token(repo, Some("shop"), None)
            .await
            .unwrap();

        let dump = a.export_org(&slug).await.unwrap();
        assert!(dump.has_secrets());
        assert_eq!(dump.blobs(), [(sha, 123)]);
        assert_eq!(dump.rows("package_versions").len(), 1);
        assert_eq!(dump.rows("editions").len(), 1);
        assert_eq!(dump.rows("license_keys").len(), 1);

        // Importing over the live org is refused.
        assert!(matches!(
            a.import_org(&dump).await,
            Err(TransferError::OrgExists(_))
        ));

        sqlx::query("delete from organizations where id = $1")
            .bind(org_id)
            .execute(&a.pool)
            .await
            .unwrap();
        let refcount = |cat: &Catalog| {
            let pool = cat.pool.clone();
            async move {
                sqlx::query_scalar::<_, i32>("select refcount from blobs where sha256 = $1")
                    .bind(&sha[..])
                    .fetch_one(&pool)
                    .await
                    .unwrap()
            }
        };
        assert_eq!(refcount(&a).await, 0);

        let b = catalog(KEY_B).await.unwrap();
        let report = b.import_org(&dump).await.unwrap();
        assert!(
            report
                .rows
                .iter()
                .any(|(t, n)| t == "license_keys" && *n == 1)
        );
        assert_eq!(
            refcount(&b).await,
            1,
            "the imported version counts its blob again"
        );

        // The same rows, secrets included (compared decrypted).
        let again = b.export_org(&slug).await.unwrap();
        for (table, rows) in &dump.tables {
            let mut want = rows.clone();
            let mut got = again.rows(table).to_vec();
            if table == "blobs" {
                continue; // last_seen_at and the count are this instance's
            }
            want.sort_by_key(ToString::to_string);
            got.sort_by_key(ToString::to_string);
            assert_eq!(want, got, "{table}");
        }

        // Credentials authenticate and secrets are sealed under the new key.
        assert!(b.resolve_license(repo, &license).await.unwrap().is_some());
        assert!(b.resolve_service_token(&service).await.unwrap().is_some());
        let token_ok: bool =
            sqlx::query_scalar("select exists(select 1 from tokens where token_hash = $1)")
                .bind(crate::token_hash(&token))
                .fetch_one(&b.pool)
                .await
                .unwrap();
        assert!(token_ok);
        let up = b.get_upstream(upstream).await.unwrap().unwrap();
        let cred = SecretKey::from_base64(KEY_B)
            .unwrap()
            .decrypt(&up.credential.unwrap())
            .unwrap();
        assert_eq!(cred, b"user:pass");
        let license_id = b.resolve_license(repo, &license).await.unwrap().unwrap();
        assert_eq!(
            b.license_key_plaintext(repo, license_id)
                .await
                .unwrap()
                .as_deref(),
            Some(license.as_str())
        );

        sqlx::query("delete from organizations where id = $1")
            .bind(org_id)
            .execute(&b.pool)
            .await
            .unwrap();
    }
}
