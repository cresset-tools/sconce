//! Composer-style version normalization for git tags.
//!
//! Not a full reimplementation of Composer's `VersionParser` — it covers the
//! shapes real package tags use: an optional `v` prefix, a 1–4 component numeric
//! core, and an optional pre-release modifier (`alpha`/`beta`/`RC`, with an
//! optional number). Tags that don't fit are returned as `None` and skipped by
//! the mirror (logged), rather than guessed at. Branch (`dev-*`) versions are a
//! later addition.

/// A normalized version + its stability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedVersion {
    /// Composer-style normalized version, e.g. `1.2.0.0` or `1.2.0.0-beta2`.
    pub normalized: String,
    /// `stable` | `RC` | `beta` | `alpha`.
    pub stability: String,
}

/// Normalize a tag like `v1.2.0` or `1.2.3-beta2`. Returns `None` if the tag
/// isn't a recognizable version.
#[must_use]
pub fn normalize_tag(tag: &str) -> Option<ParsedVersion> {
    let s = tag.strip_prefix(['v', 'V']).unwrap_or(tag);
    let (core, pre) = match s.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (s, None),
    };

    // Numeric core: 1–4 dot-separated integers, padded to 4.
    let comps: Vec<&str> = core.split('.').collect();
    if comps.is_empty() || comps.len() > 4 {
        return None;
    }
    let mut nums = [0u64; 4];
    for (i, c) in comps.iter().enumerate() {
        nums[i] = c.parse::<u64>().ok()?;
    }
    let core_norm = format!("{}.{}.{}.{}", nums[0], nums[1], nums[2], nums[3]);

    match pre {
        None => Some(ParsedVersion {
            normalized: core_norm,
            stability: "stable".to_owned(),
        }),
        Some(p) => {
            let (stability, norm_pre) = normalize_prerelease(p)?;
            Some(ParsedVersion {
                normalized: format!("{core_norm}-{norm_pre}"),
                stability: stability.to_owned(),
            })
        }
    }
}

/// Map a pre-release suffix to `(stability, normalized_suffix)`, or `None` if it
/// isn't a recognized modifier.
fn normalize_prerelease(pre: &str) -> Option<(&'static str, String)> {
    let cleaned: String = pre
        .to_ascii_lowercase()
        .chars()
        .filter(|c| !matches!(c, '.' | '-' | '_'))
        .collect();
    let split = cleaned
        .find(|c: char| c.is_ascii_digit())
        .unwrap_or(cleaned.len());
    let (word, num) = (&cleaned[..split], &cleaned[split..]);

    let stability = match word {
        "alpha" | "a" => "alpha",
        "beta" | "b" => "beta",
        "rc" => "RC",
        // Composer treats patch/pl as stable-equivalent post-releases.
        "patch" | "pl" | "p" | "stable" => "stable",
        _ => return None,
    };
    let normalized = if num.is_empty() {
        word.to_owned()
    } else {
        format!("{word}{num}")
    };
    Some((stability, normalized))
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
        assert_eq!(
            normalize_tag("v1.2.0-beta2"),
            parsed("1.2.0.0-beta2", "beta")
        );
        assert_eq!(normalize_tag("1.0.0-RC1"), parsed("1.0.0.0-rc1", "RC"));
        assert_eq!(
            normalize_tag("v3.0.0-alpha"),
            parsed("3.0.0.0-alpha", "alpha")
        );
        assert_eq!(normalize_tag("1.0.0-b3"), parsed("1.0.0.0-b3", "beta"));
    }

    #[test]
    fn rejects_non_versions() {
        assert_eq!(normalize_tag("main"), None);
        assert_eq!(normalize_tag("nightly"), None);
        assert_eq!(normalize_tag("1.2.3.4.5"), None);
        assert_eq!(normalize_tag("1.x"), None);
        assert_eq!(normalize_tag("v1.2.0-wat"), None);
    }
}
