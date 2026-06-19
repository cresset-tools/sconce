//! Mirror subscriptions: which packages (and from which version) an upstream
//! mirrors. A subscription is an ordered list of require entries; a package is
//! mirrored iff it matches **any** entry (OR-union), and a version is kept iff it
//! satisfies the floor of at least one matching entry. This replaces the old
//! per-upstream `package_filter` regex — the thing that column expressed is a
//! `composer.json` require list (name → version floor), so it's modelled as one.

use crate::Error;
use crate::version::normalize_tag;
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
    /// Minimum version (4-component), `None` = every version.
    floor: Option<[u64; 4]>,
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
    /// Compile an upstream's stored require-list. Errors only on a malformed
    /// `regex` entry; a malformed floor is treated as "no floor" (lenient).
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
                let floor = r.version_floor.as_deref().and_then(parse_floor);
                Ok(CompiledRequire { matcher, floor })
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
    /// are OR-ed: keep the version if it passes **any** matching entry's floor (a
    /// `None` floor passes). If **no** entry matches the name, return `true` — the
    /// caller mirrored this package explicitly (a single-package sync), so the
    /// subscription has no opinion on its versions.
    #[must_use]
    pub fn version_allowed(&self, name: &str, normalized: &str) -> bool {
        let v = components(normalized);
        let mut matched = false;
        for c in self.0.iter().filter(|c| c.matches_name(name)) {
            matched = true;
            match &c.floor {
                None => return true,
                Some(f) if v >= *f => return true,
                Some(_) => {}
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

/// Parse a floor like `2.4`, `v2.4`, `>=2.4`, `^2.4`, `~2.4` into its 4-component
/// core (the operator/upper-bound is ignored — this is a floor, not a range).
fn parse_floor(s: &str) -> Option<[u64; 4]> {
    let t = s.trim().trim_start_matches(['>', '=', '<', '^', '~', ' ']);
    if t.is_empty() {
        return None;
    }
    Some(components(&normalize_tag(t)?.normalized))
}

/// The 4-component numeric core of a normalized version (`2.4.0.0-beta2` → the
/// `2.4.0.0` part), for ordered comparison. Missing components are zero.
fn components(normalized: &str) -> [u64; 4] {
    let core = normalized.split('-').next().unwrap_or(normalized);
    let mut out = [0u64; 4];
    for (i, p) in core.split('.').take(4).enumerate() {
        out[i] = p.parse().unwrap_or(0);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(kind: &str, pattern: &str, floor: Option<&str>) -> UpstreamRequire {
        UpstreamRequire {
            match_kind: kind.to_owned(),
            pattern: pattern.to_owned(),
            version_floor: floor.map(ToOwned::to_owned),
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
    fn floor_filters_versions() {
        let sub = Subscription::compile(&[req("prefix", "mage-os/", Some("2.4"))]).unwrap();
        // Below the floor is dropped; at/above is kept.
        assert!(!sub.version_allowed("mage-os/composer", "2.3.7.0"));
        assert!(sub.version_allowed("mage-os/composer", "2.4.0.0"));
        assert!(sub.version_allowed("mage-os/composer", "2.4.1.0"));
        assert!(sub.version_allowed("mage-os/composer", "3.0.0.0"));
    }

    #[test]
    fn floor_union_takes_loosest() {
        // Same name matched by two entries: the version passes if EITHER floor lets it.
        let sub = Subscription::compile(&[
            req("prefix", "mage-os/", Some("2.4")),
            req("exact", "mage-os/composer", None),
        ])
        .unwrap();
        assert!(sub.version_allowed("mage-os/composer", "1.0.0.0"));
    }

    #[test]
    fn floor_accepts_constraint_operators() {
        let sub = Subscription::compile(&[req("prefix", "x/", Some(">=2.4"))]).unwrap();
        assert!(!sub.version_allowed("x/y", "2.3.0.0"));
        assert!(sub.version_allowed("x/y", "2.4.0.0"));
        let caret = Subscription::compile(&[req("prefix", "x/", Some("^3.0"))]).unwrap();
        assert!(!caret.version_allowed("x/y", "2.9.0.0"));
        assert!(caret.version_allowed("x/y", "3.1.0.0"));
    }

    #[test]
    fn unmatched_name_has_no_version_opinion() {
        // A package matched by no entry (explicit single-package sync) → all versions.
        let sub = Subscription::compile(&[req("prefix", "mage-os/", Some("2.4"))]).unwrap();
        assert!(sub.version_allowed("other/pkg", "1.0.0.0"));
    }

    #[test]
    fn empty_subscription_is_empty() {
        assert!(Subscription::compile(&[]).unwrap().is_empty());
    }
}
