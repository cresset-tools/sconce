//! Postgres-backed catalog: packages, their versions, and the blob index.
//!
//! Design choices, deliberately:
//! - **Postgres only.** No database abstraction; we use Postgres features freely.
//! - **Runtime queries only.** No `sqlx::query!` / `migrate!` macros and no
//!   `macros` feature — nothing here needs a database at *compile* time. Rows
//!   are mapped by hand. SQL migrations are plain files applied at runtime.
//!
//! The catalog maps content (a [`sconce_cas`]-style sha256 blob) to meaning:
//! "package X version Y has this `composer.json` and this dist blob". It's the
//! layer the mirror worker writes and the Composer serving reads.
//!
//! [`sconce_cas`]: https://docs.rs/sconce-cas

#![forbid(unsafe_code)]

use serde_json::Value;
use sqlx::{PgPool, Row};
use uuid::Uuid;

/// Migrations, embedded as plain SQL and applied in order at runtime. Adding a
/// migration = append a `(name, include_str!(...))` entry; names are recorded in
/// `_sconce_migrations` so each runs once.
const MIGRATIONS: &[(&str, &str)] = &[("0001_init", include_str!("../migrations/0001_init.sql"))];

/// Arbitrary fixed key for the migration advisory lock (so all sconce instances
/// agree on the same lock).
const MIGRATE_LOCK: i64 = 6_927_654_321;

/// The catalog handle: a Postgres connection pool plus the query methods.
#[derive(Debug, Clone)]
pub struct Catalog {
    pool: PgPool,
}

/// A package version as stored in the catalog.
#[derive(Debug, Clone)]
pub struct PackageVersion {
    pub version: String,
    pub normalized_version: String,
    pub stability: String,
    pub composer_json: Value,
    /// sha256 of the dist archive in the CAS, if one is attached.
    pub dist_blob_sha256: Option<[u8; 32]>,
    pub source_reference: Option<String>,
}

impl Catalog {
    /// Connect to Postgres at `database_url` (e.g.
    /// `postgres://user:pass@host:5432/db`).
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPool::connect(database_url).await?;
        Ok(Self { pool })
    }

    /// Build from an existing pool.
    #[must_use]
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Apply any pending migrations. Idempotent; safe to call on every startup.
    ///
    /// Concurrent migrators (multiple app instances starting at once, or
    /// parallel tests) are serialized with a session-level Postgres advisory
    /// lock: the first holder applies migrations, the rest block and then see
    /// them already applied. No races, no duplicate application.
    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        let mut conn = self.pool.acquire().await?;
        sqlx::query("select pg_advisory_lock($1)")
            .bind(MIGRATE_LOCK)
            .execute(&mut *conn)
            .await?;
        let result = run_migrations(&mut conn).await;
        // Always release the lock, even if a migration failed.
        let _ = sqlx::query("select pg_advisory_unlock($1)")
            .bind(MIGRATE_LOCK)
            .execute(&mut *conn)
            .await;
        result
    }

    /// Record a blob's presence + size (idempotent — the sha256 is the key).
    pub async fn upsert_blob(&self, sha256: &[u8; 32], size_bytes: i64) -> Result<(), sqlx::Error> {
        sqlx::query(
            "insert into blobs (sha256, size_bytes) values ($1, $2) \
             on conflict (sha256) do nothing",
        )
        .bind(&sha256[..])
        .bind(size_bytes)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Upsert a package by name, returning its id.
    pub async fn upsert_package(
        &self,
        name: &str,
        kind: &str,
        source: Option<&Value>,
    ) -> Result<Uuid, sqlx::Error> {
        sqlx::query_scalar(
            "insert into packages (name, kind, source) values ($1, $2, $3) \
             on conflict (name) do update set kind = excluded.kind, source = excluded.source \
             returning id",
        )
        .bind(name)
        .bind(kind)
        .bind(source)
        .fetch_one(&self.pool)
        .await
    }

    /// Upsert a version of a package, returning its id.
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_package_version(
        &self,
        package_id: Uuid,
        version: &str,
        normalized_version: &str,
        stability: &str,
        composer_json: &Value,
        dist_blob_sha256: Option<&[u8; 32]>,
        source_reference: Option<&str>,
    ) -> Result<Uuid, sqlx::Error> {
        let dist = dist_blob_sha256.map(|b| &b[..]);
        sqlx::query_scalar(
            "insert into package_versions \
                 (package_id, version, normalized_version, stability, composer_json, \
                  dist_blob_sha256, source_reference) \
             values ($1, $2, $3, $4, $5, $6, $7) \
             on conflict (package_id, normalized_version) do update set \
                 version = excluded.version, \
                 stability = excluded.stability, \
                 composer_json = excluded.composer_json, \
                 dist_blob_sha256 = excluded.dist_blob_sha256, \
                 source_reference = excluded.source_reference \
             returning id",
        )
        .bind(package_id)
        .bind(version)
        .bind(normalized_version)
        .bind(stability)
        .bind(composer_json)
        .bind(dist)
        .bind(source_reference)
        .fetch_one(&self.pool)
        .await
    }

    /// All non-yanked versions of a package, by name, ordered by normalized
    /// version. This is the read path the Composer metadata serving builds on.
    pub async fn package_versions(&self, name: &str) -> Result<Vec<PackageVersion>, sqlx::Error> {
        let rows = sqlx::query(
            "select pv.version, pv.normalized_version, pv.stability, pv.composer_json, \
                    pv.dist_blob_sha256, pv.source_reference \
             from package_versions pv \
             join packages p on p.id = pv.package_id \
             where p.name = $1 and pv.yanked_at is null \
             order by pv.normalized_version",
        )
        .bind(name)
        .fetch_all(&self.pool)
        .await?;

        rows.iter().map(row_to_version).collect()
    }
}

/// Apply pending migrations on a connection already holding the advisory lock.
async fn run_migrations(conn: &mut sqlx::PgConnection) -> Result<(), sqlx::Error> {
    use sqlx::Connection;

    sqlx::query(
        "create table if not exists _sconce_migrations (\
             name text primary key, \
             applied_at timestamptz not null default now())",
    )
    .execute(&mut *conn)
    .await?;

    for (name, sql) in MIGRATIONS {
        let already: Option<String> =
            sqlx::query_scalar("select name from _sconce_migrations where name = $1")
                .bind(name)
                .fetch_optional(&mut *conn)
                .await?;
        if already.is_some() {
            continue;
        }
        let mut tx = conn.begin().await?;
        // `raw_sql` uses the simple query protocol, so a migration file may
        // contain multiple statements.
        sqlx::raw_sql(sql).execute(&mut *tx).await?;
        sqlx::query("insert into _sconce_migrations (name) values ($1)")
            .bind(name)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
    }
    Ok(())
}

/// Map a row to a [`PackageVersion`] by column name (no derive macros).
fn row_to_version(row: &sqlx::postgres::PgRow) -> Result<PackageVersion, sqlx::Error> {
    let dist: Option<Vec<u8>> = row.try_get("dist_blob_sha256")?;
    let dist_blob_sha256 = dist.map(|v| {
        let mut a = [0u8; 32];
        // A sha256 column is always 32 bytes; truncate/pad defensively rather
        // than panic if somehow not.
        let n = v.len().min(32);
        a[..n].copy_from_slice(&v[..n]);
        a
    });
    Ok(PackageVersion {
        version: row.try_get("version")?,
        normalized_version: row.try_get("normalized_version")?,
        stability: row.try_get("stability")?,
        composer_json: row.try_get("composer_json")?,
        dist_blob_sha256,
        source_reference: row.try_get("source_reference")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Tests need a Postgres; they're skipped unless `DATABASE_URL` is set, so
    /// `cargo test` stays green on machines without one. CI sets it against a
    /// postgres service.
    async fn catalog() -> Option<Catalog> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let cat = Catalog::connect(&url).await.expect("connect");
        cat.migrate().await.expect("migrate");
        Some(cat)
    }

    /// Unique package name per test invocation so parallel tests don't collide
    /// on the global package-name uniqueness.
    fn unique_name(stem: &str) -> String {
        static C: AtomicU64 = AtomicU64::new(0);
        format!(
            "test/{stem}-{}-{}",
            std::process::id(),
            C.fetch_add(1, Ordering::Relaxed)
        )
    }

    #[tokio::test]
    async fn migrate_is_idempotent() {
        let Some(cat) = catalog().await else { return };
        // Second call must be a no-op, not an error.
        cat.migrate().await.expect("re-migrate");
    }

    #[tokio::test]
    async fn upsert_and_read_back_a_version() {
        let Some(cat) = catalog().await else { return };
        let sha = [7u8; 32];
        cat.upsert_blob(&sha, 1234).await.unwrap();

        let name = unique_name("pkg");
        let pkg = cat
            .upsert_package(
                &name,
                "git",
                Some(&serde_json::json!({"git": "https://x/y"})),
            )
            .await
            .unwrap();

        let cj = serde_json::json!({"name": name, "version": "1.2.0"});
        cat.upsert_package_version(
            pkg,
            "v1.2.0",
            "1.2.0.0",
            "stable",
            &cj,
            Some(&sha),
            Some("abc123"),
        )
        .await
        .unwrap();

        let versions = cat.package_versions(&name).await.unwrap();
        assert_eq!(versions.len(), 1);
        let v = &versions[0];
        assert_eq!(v.version, "v1.2.0");
        assert_eq!(v.stability, "stable");
        assert_eq!(v.dist_blob_sha256, Some(sha));
        assert_eq!(v.source_reference.as_deref(), Some("abc123"));
        assert_eq!(v.composer_json, cj);
    }

    #[tokio::test]
    async fn upsert_version_is_idempotent_on_normalized_version() {
        let Some(cat) = catalog().await else { return };
        let name = unique_name("pkg");
        let pkg = cat.upsert_package(&name, "git", None).await.unwrap();
        let cj = serde_json::json!({"name": name});

        let a = cat
            .upsert_package_version(pkg, "v1.0.0", "1.0.0.0", "stable", &cj, None, None)
            .await
            .unwrap();
        // Same normalized version → update, not a second row.
        let b = cat
            .upsert_package_version(pkg, "v1.0.0", "1.0.0.0", "stable", &cj, None, Some("ref2"))
            .await
            .unwrap();
        assert_eq!(a, b, "same (package, normalized_version) → same row id");
        assert_eq!(cat.package_versions(&name).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn unknown_package_has_no_versions() {
        let Some(cat) = catalog().await else { return };
        assert!(
            cat.package_versions(&unique_name("missing"))
                .await
                .unwrap()
                .is_empty()
        );
    }
}
