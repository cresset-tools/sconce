//! Askama view templates for the admin UI — typed, compile-time-checked, and
//! auto-escaping (so `{{ value }}` is HTML-safe without the old hand-rolled
//! `esc()`). Each struct renders one page *body*; the surrounding `AppShell`
//! (sidebar + topbar) is still produced by [`super::shell`] during the
//! migration, so handlers do `shell(&s, &user, title, &View { .. }.render()?)`.

// View-model structs naturally carry several independent display flags
// (active-nav booleans, per-row state); grouping them into enums would just add
// indirection between the handler and the template.
#![allow(clippy::struct_excessive_bools)]

use askama::Template;

/// One row in the org overview repo table.
pub struct RepoRow {
    pub slug: String,
    /// Private packages allowed (vs public-only).
    pub private: bool,
    /// Count of broken packages (renders an amber badge when > 0).
    pub broken: i64,
    pub packages: i64,
    /// Pre-formatted "last sync" label, or "never".
    pub last_sync: String,
    pub update_mode: String,
}

/// `/o/{org}` — the organization's repository list.
#[derive(Template)]
#[template(path = "org/overview.html")]
pub struct OrgOverview {
    pub org: String,
    pub can_admin: bool,
    /// Metered storage, pre-formatted (e.g. "1.2 GiB across 340 blobs").
    pub storage: String,
    pub repos: Vec<RepoRow>,
}

/// A simple error page body: title + amber banner + back link.
#[derive(Template)]
#[template(path = "error.html")]
pub struct ErrorCard {
    pub title: String,
    pub msg: String,
    pub back: String,
}

/// `/o/{org}/scim-token` — the one-time SCIM bearer-token reveal.
#[derive(Template)]
#[template(path = "scim_token.html")]
pub struct ScimToken {
    pub org: String,
    pub token: String,
}

/// Current OIDC connection values for the org settings form (empty when unset;
/// the client secret is write-only and never rendered back).
#[derive(Default)]
pub struct OidcView {
    pub issuer: String,
    pub client_id: String,
    pub redirect: String,
    pub scopes: String,
    pub allowed: String,
    pub admin: String,
}

/// `/o/{org}/settings`.
#[derive(Template)]
#[template(path = "org/settings.html")]
pub struct OrgSettings {
    pub org: String,
    pub allow_raw_tokens: bool,
    pub max_ttl: String,
    pub oidc_configured: bool,
    pub oidc: OidcView,
    /// Retired slugs that still redirect here.
    pub former: Vec<String>,
}

/// One row in the package-sets list.
pub struct SetRow {
    pub id: String,
    pub name: String,
    pub count: usize,
}

/// `/o/{org}/sets`.
#[derive(Template)]
#[template(path = "sets/list.html")]
pub struct SetsList {
    pub org: String,
    pub sets: Vec<SetRow>,
}

/// An explicit set member (`{id}` for the remove form, `{name}` shown).
pub struct SetMember {
    pub id: String,
    pub name: String,
}

/// A glob rule on a set.
pub struct SetRule {
    pub id: String,
    pub glob: String,
}

/// `/o/{org}/sets/{id}` — the set editor.
#[derive(Template)]
#[template(path = "sets/editor.html")]
pub struct SetEditor {
    pub org: String,
    pub set_id: String,
    pub name: String,
    pub members: Vec<SetMember>,
    pub rules: Vec<SetRule>,
    /// Resolved membership (explicit ∪ rule matches), shown as badges.
    pub resolved: Vec<String>,
}

/// `/r/{org}/{repo}/settings`.
#[derive(Template)]
#[template(path = "repo/settings.html")]
pub struct RepoSettings {
    pub org: String,
    pub repo: String,
    /// "inherit" | "allow" | "deny" — selected option in the raw-tokens dropdown.
    pub raw_mode: &'static str,
    pub repo_ttl: String,
    pub private: bool,
    pub org_raw: &'static str,
    pub org_ttl: String,
    pub eff_raw: &'static str,
    pub eff_ttl: String,
    pub former: Vec<String>,
}

/// One active login session in the account page.
pub struct SessionRow {
    pub created: String,
    pub expires: String,
    /// Session id (hash hex) for the revoke form.
    pub id: String,
    pub current: bool,
}

/// `/account` — the signed-in user's sessions.
#[derive(Template)]
#[template(path = "account.html")]
pub struct Account {
    pub email: String,
    pub is_superadmin: bool,
    pub sessions: Vec<SessionRow>,
}

/// One org membership chip in the members table.
pub struct TenantChip {
    /// Badge tone class: "held" (deactivated), "violet" (admin), or "slate".
    pub tone: &'static str,
    pub slug: String,
    pub active: bool,
    pub role: String,
}

/// One user row in the members table.
pub struct UserRow {
    pub email: String,
    pub is_superadmin: bool,
    pub tenants: Vec<TenantChip>,
}

/// `/users` — superadmin member management.
#[derive(Template)]
#[template(path = "users.html")]
pub struct UsersPage {
    pub users: Vec<UserRow>,
}

/// One organization row in the instance console.
pub struct ConsoleOrg {
    pub slug: String,
    pub repos: usize,
}

/// `/console` — superadmin instance console.
#[derive(Template)]
#[template(path = "console.html")]
pub struct Console {
    pub orgs: usize,
    pub repos: usize,
    pub users: usize,
    pub oidc_configured: bool,
    pub org_rows: Vec<ConsoleOrg>,
}

/// One background job row in the activity feed.
pub struct JobRow {
    /// Badge tone class for the status.
    pub tone: &'static str,
    /// Status label (e.g. "ready", "retrying · attempt 3").
    pub status: String,
    pub kind: String,
    pub target: String,
    pub repo: String,
    /// Terminal error text, or empty.
    pub err: String,
    pub updated: String,
}

/// `/activity` — recent mirror jobs.
#[derive(Template)]
#[template(path = "activity.html")]
pub struct Activity {
    pub jobs: Vec<JobRow>,
}

/// A repo row inside a home-dashboard org card.
pub struct OrgCardRepo {
    pub slug: String,
    pub private: bool,
    pub packages: i64,
    /// Sync badge tone ("ok" / "held" / "" for never).
    pub sync_tone: &'static str,
    pub sync_label: &'static str,
    pub when: String,
}

/// One org card on the home dashboard.
pub struct OrgCard {
    pub slug: String,
    pub name: String,
    pub can_admin: bool,
    pub repos: Vec<OrgCardRepo>,
}

/// One recent-activity entry on the home dashboard.
pub struct ActItem {
    /// Inline background color for the status glyph chip.
    pub ic_bg: &'static str,
    /// Glyph key: "spinner" | "check" | "x" | "dot".
    pub icon: &'static str,
    pub kind: String,
    /// Job target (mono), unless it's the implicit "dependency closure".
    pub target: Option<String>,
    pub failed: bool,
    /// Owning repo, shown as a "{repo} · " prefix when present.
    pub repo: Option<String>,
    pub err: String,
    pub status: String,
    pub when: String,
}

/// `/` — the home dashboard.
#[derive(Template)]
#[template(path = "home.html")]
pub struct Home {
    pub greeting: String,
    /// Count of packages needing attention (0 hides the pill).
    pub attention: i64,
    pub can_new_org: bool,
    pub can_new_repo: bool,
    pub orgs: Vec<OrgCard>,
    pub activity: Vec<ActItem>,
}

/// One row in the flat repositories table.
pub struct RepoTableRow {
    pub org: String,
    pub slug: String,
    pub private: bool,
    /// Update mode label ("delayed · 3d", "instant", …).
    pub mode: String,
    pub packages: i64,
    pub pending: i64,
    /// True = never synced (renders a plain "never" badge).
    pub never: bool,
    pub sync_tone: &'static str,
    pub sync_label: &'static str,
    pub when: String,
}

/// `/repositories` — the flat, filterable repository table.
#[derive(Template)]
#[template(path = "repositories.html")]
pub struct Repositories {
    pub count: usize,
    pub can_new_repo: bool,
    /// Current name filter (echoed into the input).
    pub q: String,
    /// Current visibility filter ("" | "private" | "public").
    pub vis: String,
    pub repos: Vec<RepoTableRow>,
}

/// `/login` — the two-pane sign-in card (standalone, no app chrome).
#[derive(Template)]
#[template(path = "login.html")]
pub struct Login {
    /// SSO offered at all (an OIDC connection exists somewhere).
    pub sso_enabled: bool,
    /// An instance-default connection exists (shows the direct SSO button).
    pub has_default: bool,
    /// Inline error banner text, or empty.
    pub error: String,
}

/// `/forgot` — request a password-reset link.
#[derive(Template)]
#[template(path = "forgot.html")]
pub struct Forgot {
    /// Inline error banner text, or empty.
    pub error: String,
}

/// `/reset` — set a new password from a valid reset token.
#[derive(Template)]
#[template(path = "reset.html")]
pub struct Reset {
    /// The reset token, round-tripped through the form's hidden field.
    pub token: String,
    /// Inline error banner text, or empty.
    pub error: String,
}

/// A standalone centered status page (404 etc.).
#[derive(Template)]
#[template(path = "status.html")]
pub struct StatusPage {
    pub title: String,
    pub msg: String,
}

/// `/repos/new` — pick an org you administer + a repo name.
#[derive(Template)]
#[template(path = "new_repo.html")]
pub struct NewRepo {
    pub is_superadmin: bool,
    /// Slugs of orgs the user administers (empty → the hint state).
    pub orgs: Vec<String>,
    /// Pre-selected org slug, or empty.
    pub selected: String,
}

/// `/orgs/new` — create an organization (superadmin).
#[derive(Template)]
#[template(path = "new_org.html")]
pub struct NewOrg;

/// A generic repo-scoped notice (title + message + back link).
#[derive(Template)]
#[template(path = "repo_notice.html")]
pub struct RepoNotice {
    pub title: String,
    pub message: String,
    pub org: String,
    pub repo: String,
}

/// "Upstream not added" — a refused-upstream explanation.
#[derive(Template)]
#[template(path = "upstream_notice.html")]
pub struct UpstreamNotice {
    /// "filter" (composer needs a match filter) or "nokey" (no secret key).
    pub reason: &'static str,
    pub org: String,
    pub repo: String,
}

/// `/r/{org}/{repo}/license` success — the one-time license-key reveal.
#[derive(Template)]
#[template(path = "license_created.html")]
pub struct LicenseCreated {
    pub packages: String,
    pub key: String,
    pub org: String,
    pub repo: String,
}

/// `/r/{org}/{repo}/token` success — the one-time token reveal + install snippet.
#[derive(Template)]
#[template(path = "token_created.html")]
pub struct TokenCreated {
    pub tok: String,
    pub base: String,
    pub host: String,
    pub org: String,
    pub repo: String,
}

/// One org option in the device-login org picker.
pub struct DeviceOrg {
    pub slug: String,
    pub name: String,
}

/// `/device` — approve a `bougie login` device flow: confirm the code and pick
/// which org the CLI's read token should cover.
#[derive(Template)]
#[template(path = "device_approve.html")]
pub struct DeviceApprove {
    /// The user code (normalized upper-case); empty if none was supplied.
    pub code: String,
    /// Whether `code` names a pending, unexpired flow (gates the approve form).
    pub pending: bool,
    /// Orgs the approver may scope the token to (member or above).
    pub orgs: Vec<DeviceOrg>,
}

/// `/device` POST result — the "return to your terminal" confirmation.
#[derive(Template)]
#[template(path = "device_approved.html")]
pub struct DeviceApproved {
    /// "approved" or "denied".
    pub outcome: &'static str,
    /// The org the token was scoped to (empty when denied).
    pub org: String,
}

/// One version row in the package detail table.
pub struct VersionRow {
    pub version: String,
    pub badge_tone: &'static str,
    pub badge_label: String,
    pub released: String,
    pub sha: String,
    pub src: String,
    pub normalized: String,
    pub held: bool,
    pub yanked: bool,
}

/// `/r/{org}/{repo}/p/{pkg}` — a package's lifecycle + versions.
#[derive(Template)]
#[template(path = "package_detail.html")]
pub struct PackageDetail {
    pub org: String,
    pub repo: String,
    pub pkg: String,
    /// Lifecycle header badge.
    pub life_tone: &'static str,
    pub life_label: &'static str,
    /// Extra muted detail beside the badge (e.g. the broken reason).
    pub life_reason: Option<String>,
    /// Archive/un-archive button value + label, if an action applies.
    pub action_value: Option<&'static str>,
    pub action_label: &'static str,
    pub visibility: String,
    pub nver: usize,
    pub last: String,
    /// "Last sync error" detail, shown when the package is stale.
    pub sync_error: Option<String>,
    pub versions: Vec<VersionRow>,
}

// ----- the repo page (tabbed) -----

/// A version row in the Packages tab.
pub struct RepoVerRow {
    pub package: String,
    pub version: String,
    pub normalized: String,
    pub stability: String,
    pub badge_tone: &'static str,
    pub badge_label: String,
    pub released: String,
    pub held: bool,
    pub yanked: bool,
}

/// A recent-version line in the Overview card.
pub struct RecentVer {
    pub package: String,
    pub version: String,
    pub badge_tone: &'static str,
    pub badge_label: String,
}

/// One version inside a per-package approval group (Approvals tab).
pub struct ApprovalVer {
    pub package: String,
    pub normalized: String,
    pub version: String,
    pub stability: String,
    /// Badge tone for the stability chip ("ok" for stable, else "slate").
    pub stab_tone: &'static str,
    /// Release date (or "—"), shown in the row's age column.
    pub age: String,
    /// Short dist sha (`a3f9c1b…e7d2`), or "—".
    pub sha: String,
}

/// A package group of pending versions in the Approvals tab — the design's
/// expandable "Approve all N" batch.
pub struct ApprovalGroup {
    pub package: String,
    /// Total pending versions in this package (the "Approve all N").
    pub count: usize,
    /// Every fetched row; the template collapses rows past the first few
    /// behind an inline "Show all N".
    pub rows: Vec<ApprovalVer>,
    /// Rows hidden until "Show all N" (`count - visible rows`).
    pub more: usize,
    /// Render expanded on load (the first / largest batch).
    pub expanded: bool,
    /// Provenance line — "via {upstream} · {visibility}", or empty.
    pub via: String,
}

/// A delayed-cooldown version card in the Approvals tab (countdown + progress).
pub struct CooldownCard {
    pub package: String,
    pub version: String,
    pub normalized: String,
    /// Whole days until it clears cooldown and auto-exposes.
    pub days_left: i64,
    /// Whole days since release (the cooldown window minus what's left).
    pub days_ago: i64,
    /// The repo's full cooldown window in days.
    pub days_total: i64,
    /// Percent of the cooldown window already elapsed (0–100).
    pub pct: i64,
}

/// A held version card in the Approvals tab (the design's "security hold").
pub struct HeldCard {
    pub package: String,
    pub version: String,
    pub normalized: String,
    pub released: String,
}

/// A package-health row in the Approvals tab.
pub struct HealthRow {
    pub pkg: String,
    pub badge_tone: &'static str,
    pub badge_label: &'static str,
    pub reason: Option<String>,
    pub last: String,
    pub action_value: Option<&'static str>,
    pub action_label: &'static str,
}

/// A granted-package row in the Policy tab.
pub struct GrantRow {
    pub package: String,
    pub source_org: String,
    pub source_repo: String,
    /// Current per-grant mode ("" | auto | manual | delayed).
    pub mode: String,
    pub cooldown: String,
}

/// An autogrant (set subscription) row.
pub struct AutograntRow {
    pub rid: String,
    pub set_name: String,
    pub count: usize,
}

/// An option in a package-set `<select>`.
pub struct SetOpt {
    pub id: String,
    pub name: String,
}

/// An upstream row in the Upstreams tab.
pub struct UpstreamRow {
    pub kind: String,
    pub is_composer: bool,
    pub base: String,
    /// The mirror subscription rendered as spec strings (`mage-os/*@2.4`, …);
    /// empty = no require-list (a git source mirrored whole).
    pub requires: Vec<String>,
    /// git monorepo subpaths this upstream mirrors (empty = repo root).
    pub source_paths: Vec<String>,
    pub error: Option<String>,
    pub public: bool,
    pub has_credential: bool,
    pub credential_type: String,
    pub last_tone: &'static str,
    pub last_label: String,
    /// Relative age, appended after the badge for ready/other states.
    pub when: String,
    pub running: bool,
    pub failed: bool,
    pub id: String,
    /// Lowercased base, for the client-side search `data-text`.
    pub text: String,
}

/// A dependency-plan row in the Dependencies tab.
pub struct DepRow {
    /// "missing" | "present" | "other".
    pub status_kind: &'static str,
    pub status_other: String,
    pub name: String,
    pub required_by: String,
    pub resolvable: bool,
}

/// A set entitlement chip inside a license row.
pub struct LicSet {
    pub set_id: String,
    pub name: String,
    /// The edge's own update bound, pre-rendered ("until 2027-07-09", "≤ v2",
    /// or empty when the edge inherits the key bound / is perpetual).
    pub bound: String,
}

/// An edition (SKU) row in the Editions section of the Tokens tab.
pub struct EditionRow {
    pub id: String,
    pub name: String,
    /// Slug (empty if none), shown in parentheses.
    pub slug: String,
    pub set_name: String,
    /// Bound label ("perpetual", "12 months", "≤ v3").
    pub bound: String,
    pub snapshot: bool,
    pub active: bool,
}

/// An option in the "issue against edition" `<select>` (active editions only).
pub struct EditionOpt {
    pub id: String,
    /// "Pro — 12 months" (name + bound), for the picker.
    pub label: String,
}

/// A license-key row in the Tokens tab.
pub struct LicenseRow {
    pub buyer: String,
    pub status: String,
    pub packages: String,
    pub id: String,
    pub sets: Vec<LicSet>,
    pub mode: String,
    pub cooldown: String,
    pub until: String,
    pub major: String,
}

/// An install-token row in the Tokens tab.
pub struct TokenRow {
    /// `None` renders as "unnamed" and a plain "inherit" policy cell.
    pub label: Option<String>,
    pub origin: String,
    pub origin_tone: &'static str,
    pub created: String,
    pub last: String,
    pub expired: bool,
    pub expires: Option<String>,
    pub mode: String,
    pub cooldown: String,
    pub id: String,
}

/// A CI OIDC policy row in the CI tab.
pub struct CiRow {
    pub provider: String,
    pub issuer: String,
    pub audience: String,
    pub claims: String,
    pub ttl: i64,
    pub id: String,
    /// `read` (mint a serving token) or `publish` (mint a publish token).
    pub capability: String,
}

/// "Showing X–Y of N" pager for the Packages tab.
pub struct Pager {
    pub from: i64,
    pub to: i64,
    pub total: i64,
    pub page: i64,
    pub last_page: i64,
    pub base: String,
    /// Pre-encoded extra query (e.g. `q=foo&state=held`), or empty.
    pub extra: String,
}

/// `/r/{org}/{repo}` — the tabbed repository console.
#[derive(Template)]
#[template(path = "repo/page.html")]
pub struct RepoPage {
    pub org: String,
    pub repo: String,
    pub private_packages: bool,
    pub sync_tone: &'static str,
    pub sync_label: &'static str,
    pub pkg_count: usize,
    pub total_versions: i64,
    pub policy_phrase: String,
    pub broken_count: usize,
    pub read_only: bool,
    pub filtering: bool,
    pub approvals_count: i64,
    // Overview
    pub base: String,
    pub host: String,
    pub example_pkg: String,
    pub pending_count: i64,
    pub held_count: i64,
    pub recent: Vec<RecentVer>,
    // Packages
    pub search_q: String,
    pub q_enc: String,
    pub state: String,
    pub filtered: bool,
    pub versions: Vec<RepoVerRow>,
    pub pager: Option<Pager>,
    // Approvals
    /// Versions awaiting a decision (pending + cooldown + held).
    pub ap_total: usize,
    pub ap_pending: usize,
    pub ap_cooldown: usize,
    pub ap_held: usize,
    /// "synced 2m ago" pill text from the freshest upstream, or empty.
    pub ap_synced: String,
    /// Upstreams that completed a sync within the last hour — drives the
    /// "N upstreams synced" banner (0 = no banner).
    pub ap_fresh_ups: usize,
    /// True when the queue exceeds the per-bucket display cap (lists truncated).
    pub ap_capped: bool,
    pub ap_groups: Vec<ApprovalGroup>,
    pub ap_cooldowns: Vec<CooldownCard>,
    pub ap_helds: Vec<HeldCard>,
    pub health: Vec<HealthRow>,
    // Policy
    pub update_mode: String,
    pub cooldown_days: i32,
    pub grants: Vec<GrantRow>,
    pub org_sets_empty: bool,
    pub autogrant_rules: Vec<AutograntRow>,
    pub set_opts: Vec<SetOpt>,
    // Upstreams
    pub upstreams: Vec<UpstreamRow>,
    pub up_total: usize,
    pub git_count: usize,
    pub composer_count: usize,
    pub failing_count: usize,
    pub has_secret_key: bool,
    // Deps
    pub deps: Vec<DepRow>,
    // Tokens + licenses
    pub licenses: Vec<LicenseRow>,
    pub org_set_opts: Vec<SetOpt>,
    /// Editions (SKUs) defined on this repo.
    pub editions: Vec<EditionRow>,
    /// Active editions, for the "issue against edition" picker.
    pub edition_opts: Vec<EditionOpt>,
    pub tokens: Vec<TokenRow>,
    // CI
    pub ci: Vec<CiRow>,
}

// ----- shared chrome (outer scaffold) -----

/// The full HTML document scaffold. `body` and the page are pre-rendered (trusted
/// markup); `title` is escaped into `<title>`.
#[derive(Template)]
#[template(path = "chrome/doc.html")]
pub struct Doc {
    pub title: String,
    pub body: String,
    /// `/assets/*.js` URL for a page script, or empty.
    pub script_src: String,
}

/// The authenticated app shell (left nav + breadcrumb + content). `sidebar` and
/// `body` are pre-rendered; `here` (the breadcrumb) is escaped.
#[derive(Template)]
#[template(path = "chrome/shell.html")]
pub struct Shell {
    pub sidebar: String,
    pub here: String,
    pub body: String,
}

/// The left navigation sidebar (active state derived from the current page).
#[derive(Template)]
#[template(path = "chrome/sidebar.html")]
pub struct Sidebar {
    pub single_tenant: bool,
    pub is_superadmin: bool,
    pub show_members: bool,
    pub show_account: bool,
    pub on_home: bool,
    pub on_repos: bool,
    pub on_members: bool,
    pub on_activity: bool,
    pub on_console: bool,
    pub role: &'static str,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole reason for the migration: interpolated values are HTML-escaped
    /// automatically, so a hostile slug can't inject markup (no manual `esc()`).
    #[test]
    fn org_overview_escapes_interpolated_values() {
        let html = OrgOverview {
            org: "<script>alert(1)</script>".to_owned(),
            can_admin: true,
            storage: "0 B across 0 blobs".to_owned(),
            repos: vec![RepoRow {
                slug: "a\"<b>".to_owned(),
                private: true,
                broken: 2,
                packages: 7,
                last_sync: "just now".to_owned(),
                update_mode: "pinned".to_owned(),
            }],
        }
        .render()
        .unwrap();
        // No raw markup survives; the hostile slug is rendered as entities
        // (Askama's HTML escaper emits numeric entities, e.g. `&#60;` for `<`).
        assert!(!html.contains("<script>alert(1)"));
        assert!(html.contains("&#60;script&#62;alert(1)&#60;/script&#62;"));
        assert!(!html.contains("a\"<b>"));
        assert!(html.contains("a&#34;&#60;b&#62;"));
        // Real content still renders.
        assert!(html.contains("badge amber"));
        assert!(html.contains("badge slate")); // private repo
    }

    /// A `RepoPage` with everything but the approval queue left empty — used to
    /// render just the Approvals tab in isolation.
    fn repo_page_with_approvals(
        ap_groups: Vec<ApprovalGroup>,
        ap_cooldowns: Vec<CooldownCard>,
        ap_helds: Vec<HeldCard>,
    ) -> RepoPage {
        let ap_pending: usize = ap_groups.iter().map(|g| g.count).sum();
        let ap_cooldown = ap_cooldowns.len();
        let ap_held = ap_helds.len();
        RepoPage {
            org: "cresset".to_owned(),
            repo: "acme-storefront".to_owned(),
            private_packages: true,
            sync_tone: "ok",
            sync_label: "synced",
            pkg_count: 0,
            total_versions: 0,
            policy_phrase: "manual approval required".to_owned(),
            broken_count: 0,
            read_only: false,
            filtering: false,
            approvals_count: 0,
            base: "https://x".to_owned(),
            host: "x".to_owned(),
            example_pkg: "acme/widget".to_owned(),
            pending_count: 0,
            held_count: 0,
            recent: vec![],
            search_q: String::new(),
            q_enc: String::new(),
            state: String::new(),
            filtered: false,
            versions: vec![],
            pager: None,
            ap_total: ap_pending + ap_cooldown + ap_held,
            ap_pending,
            ap_cooldown,
            ap_held,
            ap_synced: "2m".to_owned(),
            ap_fresh_ups: 0,
            ap_capped: false,
            ap_groups,
            ap_cooldowns,
            ap_helds,
            health: vec![],
            update_mode: "manual".to_owned(),
            cooldown_days: 0,
            grants: vec![],
            org_sets_empty: true,
            autogrant_rules: vec![],
            set_opts: vec![],
            upstreams: vec![],
            up_total: 0,
            git_count: 0,
            composer_count: 0,
            failing_count: 0,
            has_secret_key: false,
            deps: vec![],
            licenses: vec![],
            org_set_opts: vec![],
            editions: vec![],
            edition_opts: vec![],
            tokens: vec![],
            ci: vec![],
        }
    }

    /// The Approvals tab renders the queue: a per-package group with a bulk
    /// "Approve all", a cooldown card with a progress bar, and a held card —
    /// each wired to the right action endpoint.
    #[test]
    fn approvals_tab_renders_the_queue() {
        let html = repo_page_with_approvals(
            vec![ApprovalGroup {
                package: "acme/widget".to_owned(),
                count: 3,
                rows: vec![ApprovalVer {
                    package: "acme/widget".to_owned(),
                    normalized: "1.2.0.0".to_owned(),
                    version: "v1.2.0".to_owned(),
                    stability: "stable".to_owned(),
                    stab_tone: "ok",
                    age: "2024-06-01".to_owned(),
                    sha: "a3f9c1b…e7d2".to_owned(),
                }],
                more: 2,
                expanded: true,
                via: "via mage-os · public".to_owned(),
            }],
            vec![CooldownCard {
                package: "acme/blocks".to_owned(),
                version: "v3.3.0".to_owned(),
                normalized: "3.3.0.0".to_owned(),
                days_left: 2,
                days_ago: 1,
                days_total: 3,
                pct: 33,
            }],
            vec![HeldCard {
                package: "acme/loyalty".to_owned(),
                version: "v0.8.0".to_owned(),
                normalized: "0.8.0.0".to_owned(),
                released: "2024-05-20".to_owned(),
            }],
        )
        .render()
        .unwrap();

        // Queue chrome + header counts (1 group of 3 + 1 cooldown + 1 held = 5).
        assert!(html.contains("Approval queue"));
        assert!(html.contains("<strong>5</strong> version(s) awaiting a decision"));
        // The package group with its bulk action, expanded by default.
        assert!(html.contains("acme/widget"));
        assert!(html.contains(r#"class="apgroup open""#));
        assert!(html.contains("Approve all 3"));
        assert!(html.contains("/r/cresset/acme-storefront/approve-bulk"));
        assert!(html.contains("a3f9c1b…e7d2"));
        assert!(html.contains("+ 2 more version(s)"));
        // Cooldown card with its progress bar + countdown.
        assert!(html.contains("in cooldown"));
        assert!(html.contains("width:33%"));
        assert!(html.contains("Approve early"));
        // Held card.
        assert!(html.contains("acme/loyalty"));
        assert!(html.contains("HELD"));
        // The selection bulk bar posts the picked versions.
        assert!(html.contains(r"name=versions"));
    }

    /// With nothing pending, the Approvals tab shows the friendly empty state and
    /// no queue panel.
    #[test]
    fn approvals_tab_empty_state() {
        let html = repo_page_with_approvals(vec![], vec![], vec![])
            .render()
            .unwrap();
        assert!(html.contains("Nothing awaiting a decision"));
        // No queue panel and no bulk-approve action when the queue is empty.
        assert!(!html.contains("id=ap-queue"));
        assert!(!html.contains("approve-bulk"));
    }
}
