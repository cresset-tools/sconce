//! Deterministic, content-addressable archive writer.
//!
//! sconce re-archives every package version into a *canonical* ZIP so that the
//! same logical file tree always produces byte-identical output — regardless of
//! who builds it, when, or from which source (git clone vs tarball). That
//! property is what makes the content-addressed store (CAS) dedupe identical
//! packages across tenants, and what keeps Composer's `dist.shasum` stable.
//!
//! # The canonical form
//!
//! Every source of ZIP nondeterminism is pinned to a value derived *only* from
//! the file tree:
//!
//! - **Entries sorted** by raw path bytes — insertion/directory order is
//!   irrelevant.
//! - **Fixed timestamp** 1980-01-01 00:00 on every entry — never the wall clock
//!   or commit time (two identical trees built at different times must match).
//! - **No extra fields** — in particular no extended-timestamp (`UT`) or Unix
//!   uid/gid (`ux`) records, the usual silent nondeterminism.
//! - **Canonical Unix modes** in the external attributes: regular files become
//!   `0644`, executables `0755`, symlinks `0777` with the target as content.
//!   Nothing else (git itself only tracks these).
//! - **Stored method (0), never compressed.** Compression is a *transport*
//!   concern handled at the HTTP layer (`Content-Encoding: gzip`), so the hashed
//!   artifact never depends on a DEFLATE implementation. This is the single
//!   biggest determinism win — there is no compressor in the identity to vary
//!   across zlib versions or CPU architectures.
//!
//! # Layout note
//!
//! No wrapping top-level directory and no explicit directory entries: only files
//! and symlinks are emitted, directories are implied by paths. (git tracks no
//! empty directories, so nothing is lost, and it removes an ordering ambiguity.)

#![forbid(unsafe_code)]

/// The canonical kind + permission of an entry. These are exactly the modes git
/// records in a tree (regular, regular+exec, symlink); anything else from a
/// filesystem is normalized into one of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Regular file → `0644`.
    File,
    /// Executable regular file → `0755`.
    Executable,
    /// Symbolic link → `0777`; the entry's content is the (UTF-8) link target.
    Symlink,
}

impl Mode {
    /// The Unix mode bits stored in the ZIP central-directory external
    /// attributes (high 16 bits), including the file-type bits.
    fn unix_mode(self) -> u32 {
        match self {
            Mode::File => 0o100_644,
            Mode::Executable => 0o100_755,
            Mode::Symlink => 0o120_777,
        }
    }
}

/// One archive member: a normalized path, its canonical [`Mode`], and content.
#[derive(Debug, Clone)]
pub struct Entry {
    path: String,
    mode: Mode,
    content: Vec<u8>,
}

impl Entry {
    /// Create an entry. `path` is normalized to forward slashes with any
    /// leading `./` or `/` stripped; the original casing/bytes are otherwise
    /// preserved (they participate in the canonical sort).
    pub fn new(path: impl Into<String>, mode: Mode, content: impl Into<Vec<u8>>) -> Self {
        let raw = path.into();
        let norm = raw.replace('\\', "/");
        let norm = norm.trim_start_matches("./").trim_start_matches('/');
        Self {
            path: norm.to_owned(),
            mode,
            content: content.into(),
        }
    }
}

/// A collection of [`Entry`]s that serializes to a deterministic ZIP.
#[derive(Debug, Default, Clone)]
pub struct CanonicalArchive {
    entries: Vec<Entry>,
}

impl CanonicalArchive {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an entry. Order does not matter — [`Self::into_zip`] sorts.
    pub fn add(&mut self, entry: Entry) -> &mut Self {
        self.entries.push(entry);
        self
    }

    /// Number of entries currently held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Serialize to a canonical, byte-deterministic ZIP (stored method).
    ///
    /// Calling this twice on equal entry sets — in any insertion order, on any
    /// platform — yields identical bytes.
    #[must_use]
    pub fn into_zip(mut self) -> Vec<u8> {
        // THE canonical rule: total order by raw path bytes. Last write wins on
        // duplicate paths is *not* handled here — callers are expected to feed a
        // tree, which has unique paths.
        self.entries
            .sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));

        let mut body = Vec::new(); // local headers + data, in order
        let mut central = Vec::new();
        let mut offsets = Vec::with_capacity(self.entries.len());

        for e in &self.entries {
            offsets.push(u32_field(body.len()));
            write_local_header(&mut body, e);
        }
        for (e, &off) in self.entries.iter().zip(&offsets) {
            write_central_header(&mut central, e, off);
        }

        let cd_offset = u32_field(body.len());
        let cd_size = u32_field(central.len());
        let count = u16_field(self.entries.len());

        let mut out = body;
        out.extend_from_slice(&central);
        write_eocd(&mut out, count, cd_size, cd_offset);
        out
    }
}

// ----- ZIP framing (all fields pinned) -----

// 1980-01-01 00:00:00, the ZIP epoch floor, encoded as DOS date/time.
const DOS_TIME: u16 = 0x0000;
const DOS_DATE: u16 = 0x0021;
const VERSION_NEEDED: u16 = 20; // 2.0
const VERSION_MADE_BY: u16 = 0x0314; // high byte 3 = Unix host, low byte 0x14 = spec 2.0

fn w16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn w32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

/// ZIP's classic header fields are 32-bit sizes/offsets and 16-bit counts.
/// Overflowing them is precisely what triggers Zip64 — not yet implemented, so
/// we fail loudly rather than silently truncate. (PHP packages sit far below
/// these limits; this is a correctness guard, not a practical constraint.)
fn u32_field(n: usize) -> u32 {
    u32::try_from(n).expect("size/offset exceeds 4 GiB — Zip64 not yet implemented")
}
fn u16_field(n: usize) -> u16 {
    u16::try_from(n).expect("count/length exceeds 65535 — Zip64 not yet implemented")
}

fn write_local_header(out: &mut Vec<u8>, e: &Entry) {
    let name = e.path.as_bytes();
    let crc = crc32(&e.content);
    let size = u32_field(e.content.len());

    w32(out, 0x0403_4b50); // local file header signature
    w16(out, VERSION_NEEDED);
    w16(out, 0); // general purpose flag: no streaming descriptor
    w16(out, 0); // method: stored
    w16(out, DOS_TIME);
    w16(out, DOS_DATE);
    w32(out, crc);
    w32(out, size); // compressed size (== uncompressed, stored)
    w32(out, size); // uncompressed size
    w16(out, u16_field(name.len()));
    w16(out, 0); // extra field length: none
    out.extend_from_slice(name);
    out.extend_from_slice(&e.content);
}

fn write_central_header(out: &mut Vec<u8>, e: &Entry, local_offset: u32) {
    let name = e.path.as_bytes();
    let crc = crc32(&e.content);
    let size = u32_field(e.content.len());

    w32(out, 0x0201_4b50); // central directory header signature
    w16(out, VERSION_MADE_BY);
    w16(out, VERSION_NEEDED);
    w16(out, 0); // general purpose flag
    w16(out, 0); // method: stored
    w16(out, DOS_TIME);
    w16(out, DOS_DATE);
    w32(out, crc);
    w32(out, size);
    w32(out, size);
    w16(out, u16_field(name.len()));
    w16(out, 0); // extra field length
    w16(out, 0); // comment length
    w16(out, 0); // disk number start
    w16(out, 0); // internal attributes
    w32(out, e.mode.unix_mode() << 16); // external attributes: unix mode
    w32(out, local_offset);
    out.extend_from_slice(name);
}

fn write_eocd(out: &mut Vec<u8>, count: u16, cd_size: u32, cd_offset: u32) {
    w32(out, 0x0605_4b50); // end of central directory signature
    w16(out, 0); // this disk
    w16(out, 0); // disk with central dir
    w16(out, count); // entries on this disk
    w16(out, count); // total entries
    w32(out, cd_size);
    w32(out, cd_offset);
    w16(out, 0); // archive comment length
}

/// CRC-32 (IEEE 802.3, reflected) — the checksum ZIP entries carry.
fn crc32(buf: &[u8]) -> u32 {
    const POLY: u32 = 0xEDB8_8320;
    let mut crc = 0xFFFF_FFFFu32;
    for &b in buf {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                POLY ^ (crc >> 1)
            } else {
                crc >> 1
            };
        }
    }
    crc ^ 0xFFFF_FFFF
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// A small fixture exercising files, an executable, a symlink, and nested
    /// paths — built here so tests can scramble insertion order.
    fn fixture(reversed: bool) -> CanonicalArchive {
        let mut entries = vec![
            Entry::new("src/Foo.php", Mode::File, b"<?php\nclass Foo {}\n".to_vec()),
            Entry::new(
                "bin/run",
                Mode::Executable,
                b"#!/bin/sh\necho hi\n".to_vec(),
            ),
            Entry::new("README.md", Mode::File, b"# demo\n".to_vec()),
            Entry::new("src/Bar.php", Mode::File, b"<?php\nclass Bar {}\n".to_vec()),
            Entry::new("link", Mode::Symlink, b"src/Foo.php".to_vec()),
        ];
        if reversed {
            entries.reverse();
        }
        let mut a = CanonicalArchive::new();
        for e in entries {
            a.add(e);
        }
        a
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut h = Sha256::new();
        h.update(bytes);
        h.finalize().iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }

    #[test]
    fn deterministic_regardless_of_insertion_order() {
        // Identical content, opposite insertion order → identical bytes.
        assert_eq!(fixture(false).into_zip(), fixture(true).into_zip());
    }

    #[test]
    fn crc32_known_vector() {
        // CRC-32 of "123456789" is the well-known 0xCBF43926.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn starts_with_local_file_signature() {
        let zip = fixture(false).into_zip();
        assert_eq!(&zip[0..4], &[b'P', b'K', 0x03, 0x04]);
    }

    #[test]
    fn ends_with_eocd_signature() {
        let zip = fixture(false).into_zip();
        let n = zip.len();
        assert_eq!(&zip[n - 22..n - 18], &[b'P', b'K', 0x05, 0x06]);
    }

    /// The cross-platform determinism guarantee: a pinned digest. If this ever
    /// fails on a given OS/arch in CI, the archiver has become nondeterministic.
    #[test]
    fn golden_sha256() {
        let zip = fixture(false).into_zip();
        assert_eq!(
            sha256_hex(&zip),
            "e392467d7d30efa77d7ada5184d44d004056c77b41d37acd35e12a125050d8b4",
            "golden archive digest changed — update only if the canonical form \
             intentionally changed (and bump the archive-format-version)"
        );
    }
}
