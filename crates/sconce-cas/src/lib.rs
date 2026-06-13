//! Content-addressed blob store (CAS).
//!
//! Blobs are keyed by the **sha256 of their bytes**. That makes storage
//! inherently deduplicating: the same content — an identical package archive
//! produced from any source, by any tenant — maps to one [`BlobId`] and one
//! file. Writes are **put-if-absent** (an existing blob is never rewritten) and
//! **atomic** (temp file + `rename` within the same filesystem), so a blob is
//! either fully present or absent, never half-written, and concurrent writers of
//! identical content are harmless (they produce the same bytes).
//!
//! This layer is pure content storage. Reference counting and GC live with the
//! catalog (which knows what *references* a blob); the store itself just keeps
//! immutable bytes addressable by hash.
//!
//! The [`BlobStore`] trait is the backend seam: [`FsBlobStore`] (filesystem) is
//! the first impl — zero external deps, ideal for self-hosting — and an
//! object-store backend (R2/S3) slots in behind the same trait later.

#![forbid(unsafe_code)]

use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};

/// A blob's identity: the sha256 of its bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlobId([u8; 32]);

impl BlobId {
    /// Compute the id of some bytes.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(bytes);
        Self(h.finalize().into())
    }

    /// The 64-character lowercase hex form (the on-disk name).
    #[must_use]
    pub fn to_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(64);
        for b in self.0 {
            s.push(HEX[(b >> 4) as usize] as char);
            s.push(HEX[(b & 0x0f) as usize] as char);
        }
        s
    }

    /// The raw 32 bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for BlobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for BlobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlobId({})", self.to_hex())
    }
}

/// Backend-agnostic content-addressed store.
pub trait BlobStore {
    /// Store `bytes` and return their [`BlobId`]. Put-if-absent: if the content
    /// is already present, this is a cheap no-op that returns the same id.
    fn put(&self, bytes: &[u8]) -> io::Result<BlobId>;

    /// Whether a blob is present.
    fn exists(&self, id: &BlobId) -> io::Result<bool>;

    /// Read a blob's bytes, or `None` if absent.
    fn get(&self, id: &BlobId) -> io::Result<Option<Vec<u8>>>;
}

/// Filesystem-backed CAS. Blobs live at `<root>/<ab>/<cd>/<full-hex>`, where the
/// two-level fanout keeps any one directory from accumulating millions of
/// entries.
#[derive(Debug, Clone)]
pub struct FsBlobStore {
    root: PathBuf,
}

impl FsBlobStore {
    /// Open (creating if needed) a store rooted at `root`.
    pub fn open(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    /// The fanned-out directory and final file path for a blob:
    /// `(<root>/<ab>/<cd>, <root>/<ab>/<cd>/<full-hex>)`.
    fn paths_for(&self, id: &BlobId) -> (PathBuf, PathBuf) {
        let hex = id.to_hex();
        let dir = self.root.join(&hex[0..2]).join(&hex[2..4]);
        let file = dir.join(&hex);
        (dir, file)
    }
}

// Process-unique temp suffix without a clock or rng dependency: pid + a counter.
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

impl BlobStore for FsBlobStore {
    fn put(&self, bytes: &[u8]) -> io::Result<BlobId> {
        let id = BlobId::of(bytes);
        let (dir, final_path) = self.paths_for(&id);

        // Put-if-absent: identical content is already stored, nothing to do.
        if final_path.exists() {
            return Ok(id);
        }

        fs::create_dir_all(&dir)?;

        // Write to a temp file in the *same directory* (so the rename is on one
        // filesystem and therefore atomic), fsync, then rename into place. If a
        // concurrent writer beat us, the rename just replaces identical bytes.
        let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = dir.join(format!(".tmp-{}-{n}", std::process::id()));
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(bytes)?;
            f.sync_all()?;
        }
        match fs::rename(&tmp, &final_path) {
            Ok(()) => Ok(id),
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                Err(e)
            }
        }
    }

    fn exists(&self, id: &BlobId) -> io::Result<bool> {
        self.paths_for(id).1.try_exists()
    }

    fn get(&self, id: &BlobId) -> io::Result<Option<Vec<u8>>> {
        match fs::read(self.paths_for(id).1) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn tempdir() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut p = std::env::temp_dir();
        p.push(format!("sconce-cas-test-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn blobid_hex_is_known_sha256() {
        // sha256("") — the canonical empty-input digest.
        assert_eq!(
            BlobId::of(b"").to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn put_get_roundtrip_and_layout() {
        let root = tempdir();
        let store = FsBlobStore::open(&root).unwrap();

        let id = store.put(b"hello sconce").unwrap();
        assert!(store.exists(&id).unwrap());
        assert_eq!(
            store.get(&id).unwrap().as_deref(),
            Some(&b"hello sconce"[..])
        );

        // Stored at the fanned-out content-addressed path.
        let hex = id.to_hex();
        let expected = root.join(&hex[0..2]).join(&hex[2..4]).join(&hex);
        assert!(expected.is_file(), "blob at {expected:?}");

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn put_is_idempotent_and_dedupes() {
        let root = tempdir();
        let store = FsBlobStore::open(&root).unwrap();

        let a = store.put(b"same bytes").unwrap();
        let b = store.put(b"same bytes").unwrap();
        assert_eq!(a, b, "identical content → identical id");

        // Exactly one blob file exists under the store (the dedup).
        let count = walk_files(&root);
        assert_eq!(count, 1, "second put did not create a second file");

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn distinct_content_distinct_ids() {
        let root = tempdir();
        let store = FsBlobStore::open(&root).unwrap();
        let a = store.put(b"one").unwrap();
        let b = store.put(b"two").unwrap();
        assert_ne!(a, b);
        assert_eq!(store.get(&a).unwrap().as_deref(), Some(&b"one"[..]));
        assert_eq!(store.get(&b).unwrap().as_deref(), Some(&b"two"[..]));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn missing_blob_reads_none() {
        let root = tempdir();
        let store = FsBlobStore::open(&root).unwrap();
        let id = BlobId::of(b"never stored");
        assert!(!store.exists(&id).unwrap());
        assert!(store.get(&id).unwrap().is_none());
        fs::remove_dir_all(&root).ok();
    }

    /// Count regular files under `dir`, ignoring our `.tmp-*` scratch files.
    fn walk_files(dir: &Path) -> usize {
        let mut n = 0;
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let ft = entry.file_type().unwrap();
            if ft.is_dir() {
                n += walk_files(&entry.path());
            } else if ft.is_file() && !entry.file_name().to_string_lossy().starts_with(".tmp-") {
                n += 1;
            }
        }
        n
    }
}
