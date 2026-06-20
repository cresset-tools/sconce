//! Composer-style version normalization for git tags.
//!
//! A thin adapter over [`composer_semver`]: a git tag is normalized with
//! Composer's real `VersionParser`, and only *numeric* versions are kept.
//! Branch refs (`main`, `nightly`, `dev-*`) and anything unparseable return
//! `None` so the mirror logs and skips them — the mirror tracks tagged
//! releases, not branches.

use composer_semver::Version;
use composer_semver::version::VersionKind;

/// A normalized version + its stability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedVersion {
    /// Composer-style normalized version, e.g. `1.2.0.0` or `1.2.0.0-beta2`.
    pub normalized: String,
    /// Composer stability keyword: `stable` | `RC` | `beta` | `alpha` | `dev`.
    pub stability: String,
}

/// Normalize a tag like `v1.2.0` or `1.2.3-beta2`. Returns `None` if the tag
/// isn't a recognizable **numeric** version (branch names and unparseable refs
/// are skipped).
#[must_use]
pub fn normalize_tag(tag: &str) -> Option<ParsedVersion> {
    let version = Version::parse(tag).ok()?;
    // Tagged releases only: skip branch versions (`dev-*`, default branches).
    if !matches!(version.kind, VersionKind::Numeric { .. }) {
        return None;
    }
    Some(ParsedVersion {
        stability: version.stability().as_str().to_owned(),
        normalized: version.normalized,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Always returns Some by design — a comparison helper for the Option that
    // `normalize_tag` returns.
    #[allow(clippy::unnecessary_wraps)]
    fn parsed(normalized: &str, stability: &str) -> Option<ParsedVersion> {
        Some(ParsedVersion {
            normalized: normalized.to_owned(),
            stability: stability.to_owned(),
        })
    }

    #[test]
    fn stable_versions() {
        assert_eq!(normalize_tag("v1.2.0"), parsed("1.2.0.0", "stable"));
        assert_eq!(normalize_tag("1.2.0"), parsed("1.2.0.0", "stable"));
        assert_eq!(normalize_tag("v1.2"), parsed("1.2.0.0", "stable"));
        assert_eq!(normalize_tag("2"), parsed("2.0.0.0", "stable"));
        assert_eq!(normalize_tag("1.2.3.4"), parsed("1.2.3.4", "stable"));
    }

    #[test]
    fn prereleases() {
        // Normalized forms are Composer-canonical: `b`→`beta`, `rc`→`RC`.
        assert_eq!(
            normalize_tag("v1.2.0-beta2"),
            parsed("1.2.0.0-beta2", "beta")
        );
        assert_eq!(normalize_tag("1.0.0-RC1"), parsed("1.0.0.0-RC1", "RC"));
        assert_eq!(
            normalize_tag("v3.0.0-alpha"),
            parsed("3.0.0.0-alpha", "alpha")
        );
        assert_eq!(normalize_tag("1.0.0-b3"), parsed("1.0.0.0-beta3", "beta"));
    }

    #[test]
    fn rejects_non_versions() {
        assert_eq!(normalize_tag("main"), None);
        assert_eq!(normalize_tag("nightly"), None);
        assert_eq!(normalize_tag("1.2.3.4.5"), None);
        assert_eq!(normalize_tag("1.x"), None);
        assert_eq!(normalize_tag("v1.2.0-wat"), None);
    }

    #[test]
    fn skips_branch_tags() {
        // Composer parses `dev-*` as a branch version; the mirror keeps only
        // numeric tags, so these are skipped.
        assert_eq!(normalize_tag("dev-master"), None);
        assert_eq!(normalize_tag("dev-feature-x"), None);
    }
}
