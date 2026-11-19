//! Mirror subscriptions: which packages (and which versions) an upstream
//! mirrors. A subscription is an ordered list of require entries; a package is
//! mirrored iff it matches **any** entry (OR-union), and a version is kept iff
//! it satisfies the Composer version constraint of at least one matching entry.
//! This models an upstream's `composer.json` require list (name → constraint):
//! `^3.0` keeps 3.x only, `~2.4` keeps `>=2.4 <3.0`, a bare `2.4` keeps `2.4.*`,
//! and an empty constraint keeps every version.

use crate::Error;
use composer_semver::{Constraint, Version};
use sconce_catalog::UpstreamRequire;

/// How a require entry matches a package name.
#[derive(Debug)]
enum Match {
    /// Every package (an explicit require-all opt-in).
    All,
    /// Names starting with this string (a vendor `mage-os/`, or any prefix).
    Prefix(String),
    /// Exactly this name (a single package).
    Exact(String),
    /// Advanced escape hatch: a regex over the name.
    Regex(regex::Regex),
}

#[derive(Debug)]
struct CompiledRequire {
    matcher: Match,
    /// Composer version constraint; `None` = every version.
    constraint: Option<Constraint>,
}

impl CompiledRequire {
    fn matches_name(&self, name: &str) -> bool {
        match &self.matcher {
            Match::All => true,
            Match::Prefix(p) => name.starts_with(p.as_str()),
            Match::Exact(e) => name == e,
            Match::Regex(re) => re.is_match(name),
        }
    }
}

/// A compiled subscription — the require-list ready to match against names and
/// versions.
#[derive(Debug)]
pub struct Subscription(Vec<CompiledRequire>);

impl Subscription {
    /// Compile an upstream's stored require-list. Errors on a malformed `regex`
    /// entry or a malformed version constraint.
    pub fn compile(reqs: &[UpstreamRequire]) -> Result<Self, Error> {
        let compiled = reqs
            .iter()
            .map(|r| {
                let matcher = match r.match_kind.as_str() {
                    "all" => Match::All,
                    "prefix" => Match::Prefix(normalize_prefix(&r.pattern)),
                    "exact" => Match::Exact(r.pattern.clone()),
                    "regex" => Match::Regex(
                        regex::Regex::new(&r.pattern)
                            .map_err(|e| Error::BadPattern(e.to_string()))?,
                    ),
                    other => {
                        return Err(Error::BadPattern(format!("unknown match kind '{other}'")));
                    }
                };
                let constraint = parse_constraint(r.version_floor.as_deref())?;
                Ok(CompiledRequire {
                    matcher,
                    constraint,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        Ok(Self(compiled))
    }

    /// Whether the subscription has no entries (a composer registry sync refuses
    /// to run on an empty one — it would mirror the whole registry).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether any entry matches this package name (the package-selection gate).
    #[must_use]
    pub fn matches_name(&self, name: &str) -> bool {
        self.0.iter().any(|c| c.matches_name(name))
    }

    /// Whether a version should be mirrored for `name`. Entries matching the name
    /// are OR-ed: keep the version if it satisfies **any** matching entry's
    /// constraint (a `None` constraint always passes). If **no** entry matches
    /// the name, return `true` — the caller mirrored this package explicitly (a
    /// single-package sync), so the subscription has no opinion on its versions.
    ///
    /// `normalized` is a Composer-normalized version string (e.g. `2.4.0.0`).
    #[must_use]
    pub fn version_allowed(&self, name: &str, normalized: &str) -> bool {
        let mut matched = false;
        // Parse the candidate once; reused across every matching constraint.
        let version = Version::parse(normalized);
        for c in self.0.iter().filter(|c| c.matches_name(name)) {
            matched = true;
            match (&c.constraint, &version) {
                // No constraint keeps every version.
                (None, _) => return true,
                (Some(con), Ok(v)) if con.matches(v) => return true,
                // A constraint that doesn't match (or an unparseable version)
                // fails this entry; another matching entry may still pass.
                (Some(_), _) => {}
            }
        }
        !matched
    }
}

/// Normalize a prefix pattern: a trailing `*` (`mage-os/*`) or not (`mage-os/`)
/// both mean "names starting with `mage-os/`".
fn normalize_prefix(pattern: &str) -> String {
    pattern.strip_suffix('*').unwrap_or(pattern).to_owned()
}

/// Parse a stored version constraint. An absent or empty/whitespace string means
/// "no constraint" (every version); anything else must be a valid Composer
/// constraint (`^1.2`, `~2.4`, `>=1.0 <2.0`, `1.2.*`, …).
fn parse_constraint(raw: Option<&str>) -> Result<Option<Constraint>, Error> {
    match raw.map(str::trim) {
        None | Some("") => Ok(None),
        Some(s) => Constraint::parse(s)
            .map(Some)
            .map_err(|e| Error::BadPattern(format!("invalid version constraint '{s}': {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(kind: &str, pattern: &str, constraint: Option<&str>) -> UpstreamRequire {
        UpstreamRequire {
            match_kind: kind.to_owned(),
            pattern: pattern.to_owned(),
            version_floor: constraint.map(ToOwned::to_owned),
        }
    }

    #[test]
    fn prefix_matches_vendor_with_or_without_star() {
        let sub = Subscription::compile(&[req("prefix", "mage-os/*", None)]).unwrap();
        assert!(sub.matches_name("mage-os/composer"));
        assert!(!sub.matches_name("magento/framework"));
        let bare = Subscription::compile(&[req("prefix", "mage-os/", None)]).unwrap();
        assert!(bare.matches_name("mage-os/composer"));
    }

    #[test]
    fn exact_and_all_and_regex() {
        let exact = Subscription::compile(&[req("exact", "psr/log", None)]).unwrap();
        assert!(exact.matches_name("psr/log"));
        assert!(!exact.matches_name("psr/log-extra"));
        let all = Subscription::compile(&[req("all", "", None)]).unwrap();
        assert!(all.matches_name("anything/here"));
        let re = Subscription::compile(&[req("regex", "^magento/module-", None)]).unwrap();
        assert!(re.matches_name("magento/module-catalog"));
        assert!(!re.matches_name("magento/framework"));
    }

    #[test]
    fn union_of_entries() {
        let sub = Subscription::compile(&[
            req("prefix", "symfony/", None),
            req("exact", "monolog/monolog", None),
        ])
        .unwrap();
        assert!(sub.matches_name("symfony/console"));
        assert!(sub.matches_name("monolog/monolog"));
        assert!(!sub.matches_name("guzzlehttp/guzzle"));
    }

    #[test]
    fn bare_version_is_a_wildcard_minor() {
        // Composer treats a bare `2.4` as `2.4.*` (`>=2.4 <2.5`).
        let sub = Subscription::compile(&[req("prefix", "mage-os/", Some("2.4"))]).unwrap();
        assert!(!sub.version_allowed("mage-os/composer", "2.3.7.0"));
        assert!(sub.version_allowed("mage-os/composer", "2.4.0.0"));
        assert!(sub.version_allowed("mage-os/composer", "2.4.1.0"));
        assert!(!sub.version_allowed("mage-os/composer", "2.5.0.0"));
        assert!(!sub.version_allowed("mage-os/composer", "3.0.0.0"));
    }

    #[test]
    fn constraint_operators_are_honored() {
        // `>=` is an open floor.
        let ge = Subscription::compile(&[req("prefix", "x/", Some(">=2.4"))]).unwrap();
        assert!(!ge.version_allowed("x/y", "2.3.0.0"));
        assert!(ge.version_allowed("x/y", "2.4.0.0"));
        assert!(ge.version_allowed("x/y", "4.0.0.0"));

        // `^3.0` caps at `<4.0` — the upper bound the old floor model ignored.
        let caret = Subscription::compile(&[req("prefix", "x/", Some("^3.0"))]).unwrap();
        assert!(!caret.version_allowed("x/y", "2.9.0.0"));
        assert!(caret.version_allowed("x/y", "3.1.0.0"));
        assert!(!caret.version_allowed("x/y", "4.0.0.0"));

        // `~2.4` is `>=2.4 <3.0`.
        let tilde = Subscription::compile(&[req("prefix", "x/", Some("~2.4"))]).unwrap();
        assert!(!tilde.version_allowed("x/y", "2.3.0.0"));
        assert!(tilde.version_allowed("x/y", "2.9.0.0"));
        assert!(!tilde.version_allowed("x/y", "3.0.0.0"));
    }

    #[test]
    fn union_keeps_version_if_any_constraint_passes() {
        // One entry constrains to 2.4.*, another (exact) has no constraint.
        // A 1.0 version fails the first but passes the unconstrained one.
        let sub = Subscription::compile(&[
            req("prefix", "mage-os/", Some("2.4")),
            req("exact", "mage-os/composer", None),
        ])
        .unwrap();
        assert!(sub.version_allowed("mage-os/composer", "1.0.0.0"));
    }

    #[test]
    fn unmatched_name_has_no_version_opinion() {
        // A package matched by no entry (explicit single-package sync) → all versions.
        let sub = Subscription::compile(&[req("prefix", "mage-os/", Some("2.4"))]).unwrap();
        assert!(sub.version_allowed("other/pkg", "1.0.0.0"));
    }

    #[test]
    fn malformed_constraint_is_an_error() {
        assert!(Subscription::compile(&[req("prefix", "x/", Some("not a version"))]).is_err());
    }

    #[test]
    fn empty_constraint_keeps_every_version() {
        let sub = Subscription::compile(&[req("prefix", "x/", Some("  "))]).unwrap();
        assert!(sub.version_allowed("x/y", "0.0.1.0"));
        assert!(sub.version_allowed("x/y", "99.0.0.0"));
    }

    #[test]
    fn empty_subscription_is_empty() {
        assert!(Subscription::compile(&[]).unwrap().is_empty());
    }
}
