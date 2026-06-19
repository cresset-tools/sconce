# Design TODO — Bougie Repo screen inventory vs. implementation

What's still missing between the Claude Design handoff (the "Bougie Repo" screen
inventory + the standalone `Login.dc.html`) and the live admin UI in
`crates/sconce-server/src/ui.rs`.

The visual language is already a faithful build of the **Slate** direction —
Geist / Geist Mono, accent `#5a4ff0`, the light surface palette, the full status
badge vocabulary, the tabbed repository view, and the two-pane sign-in. This file
tracks the screens and behaviours that are **not yet** implemented, or that
diverge from the design.

Legend: ✅ done · 🟡 partial / diverges · ❌ not implemented

---

## A — Entry & account

- ✅ **Sign in** — two-pane card, SSO + org-email routing, password form,
  Show/Hide toggle, inline error banner (matches `Login.dc.html`).
- 🟡 **Forgot password** — the link exists (per design) but there is **no
  password-reset flow** behind it; currently points at `/login`.
  - [ ] Decide: build a reset flow (email token → set new password) or remove the link.
- 🟡 **SSO redirect/callback transient states** — "Signing you in…",
  "Completing SSO with your provider". Errors render in the login card, but there
  is **no styled in-progress/spinner screen** during the IdP round-trip.
  - [ ] Add a lightweight interstitial for the callback while the flow resolves.
- ❌ **Sign-up / onboarding wizard** — design shows a guided 4-step stepper
  (account → org → first repo → install). Implemented as separate plain forms
  (`/orgs/new`, `/repos/new`) with no stepper, progress, or "first repo" policy
  presets (Auto / Delayed / Manual cards).
  - [ ] Build a multi-step onboarding flow with the policy-preset cards and a
        final "Install" step showing the composer snippet.
- ✅ **Account menu & sessions** — `/account` (active sessions, revoke, sign out).

## B — App shell & home

- ✅ **Global shell** — sidebar (logo + "Hosted", Repositories / Members /
  Activity / Instance console, role badge + Log out).
- ❌ **⌘K command palette / global search** — present in the design's shell,
  not implemented.
  - [ ] Add a command palette (jump to org/repo/package, quick actions).
- ✅ **Home / dashboard** — "Welcome back" greeting, "N packages need attention"
  pill, two-column layout: per-org cards (visibility / packages / last-sync,
  aligned columns), centered empty-org state, and the **Recent activity** panel
  with per-status icons. Matches the design's B2.
- 🟡 **Org switcher** — the design shows a switcher dropdown in the shell header;
  the current header is a static "Bougie Repo / Hosted" brand block.
  - [ ] Add an org switcher control for multi-org users.

## C — Organization

- ✅ **Org overview** — repos table, Package sets / Settings / New repo.
- ✅ **Org settings** — allow-raw-tokens, max token expiry, OIDC, SCIM, rename.
- ✅ **Members & roles** — role + status badges, grant access.
- ✅ **SSO connection (OIDC)** — in org settings.
- ✅ **SCIM provisioning** — in org settings.
- ❌ **Billing & plan** — entire screen absent (Team plan card, usage, invoices).
  Hosted-only; expected to be out of the open tree, but listed here for completeness.
  - [ ] Out of scope for OSS unless hosted "Bougie Repo" is built.

## D — Repository (the core)

- ✅ **Repo overview + tabs** — Overview / Packages / Approvals / Upstreams /
  Dependencies / Policy / Tokens / CI access, install hero, supply-chain summary.
- 🟡 **Packages & versions** — search + state chips (all / pending / held /
  yanked / approved) + per-version actions + badge vocabulary are done. Diverges:
  - [ ] Design groups versions under **expandable per-package rows**; impl is a
        flat package+version table (package name repeats per row).
  - [ ] Design has a **lifecycle filter row** (All / Healthy / Broken / Archived
        / Renamed) and a **Visibility + Lifecycle column**; impl has Stability +
        State only.
  - [ ] Design state pills show **counts** (Pending 2, Cooldown 3); impl chips
        have no counts.
- ✅ **Approval queue** — approvals tab + inline approve/hold in Packages.
- ✅ **Upstreams** — search, kind/failing filters, table, sync/sync-all, add form.
- ✅ **Dependency plan** — resolve closure, add resolvable.
- ✅ **Update policy** — mode + cooldown (Policy tab).
- ✅ **Tokens** — list + create; **License keys** section present.
- ✅ **Token shown once** — rendered as a "Token created" page (shown once).
      (Design framed it as a modal; page is functionally equivalent.)
- ✅ **CI access / OIDC policies** — zero-secret CI, claim matchers, snippet.
- ✅ **Repo settings** — tighten-only, effective values, rename, danger zone.
- ✅ **Install instructions panel** — Overview tab hero.

## E — Agency mode

- 🟡 **Agency overview** — no dedicated dashboard (house repo + client grid +
  bulk actions). Agency features surface inline instead.
  - [ ] Build an agency overview: house repo, client grid, bulk grant actions.
- 🟡 **Client curation (allow / deny)** — partial via grants; no dedicated
  public-package allow/deny screen.
  - [ ] Build the client-curation allow/deny UI.
- ✅ **Grants & autogrant** — Policy tab (grant from repo, autogrant from set).
- ✅ **Shared / house repo** — Package sets cover the house-bundle concept.

## F — Vendor / seller mode

- 🟡 **Vendor overview** — no dedicated dashboard (commercial packages, recent
  sales, custom hostname).
  - [ ] Build a vendor overview dashboard.
- 🟡 **Commercial packages** — partial; no dedicated view.
- ❌ **Recent sales** — not implemented.
  - [ ] Add a sales/usage view for issued licenses.
- ✅ **License keys** — Tokens tab → License keys (issue, entitled packages, sets).
- ✅ **License key shown once** — "License created" page (shown once).
- 🟡 **Buyers** — buyer appears on the license row; no per-buyer entitlements view.
  - [ ] Build a Buyers screen with per-buyer entitlements.
- ❌ **Custom hostnames** — not implemented in the UI.
  - [ ] Add custom-hostname management (CNAME/verification).
- ❌ **Buyer portal (Cresset Market)** — buyer-facing "activate your license"
  install page; not in the admin UI.
  - [ ] Build the buyer-facing portal (likely a separate surface from admin UI).

## G — Cross-cutting & system

- ✅ **Activity / jobs** — queued → running → ready/failed, error detail.
  - [ ] Minor: design mentions a **retry** action on failed jobs — add retry buttons.
- ✅ **Superadmin instance console** — org/user/repo counts, instance OIDC, org list.
  - [ ] Design lists **Global settings** beyond OIDC — confirm scope and add if needed.
- ❌ **Audit log & vulnerability findings** — not implemented.
  - [ ] Build an audit-log view and a vulnerability-findings surface.
- 🟡 **Reusable components** — e.g. "Revoke this token?" is a plain form button,
  not the design's confirmation modal.
  - [ ] Add a shared confirm-modal component for destructive actions.
- 🟡 **Global states** — empty states exist; **404 / no-access / generic error**
  pages return bare HTTP status codes, not the styled screens in the design.
  - [ ] Add styled 404, no-access, and error pages.

## H — Addendum: package lifecycle & sets

- ✅ **Package lifecycle states** — badges: live / cooldown / held / yanked /
  archived · frozen / broken.
- ✅ **Package detail · lifecycle panel** — lifecycle header + version provenance
  + archive/unarchive.
- ❌ **Renamed · redirect & abandoned** — no package **rename / alias** control
  on the package detail (repo & org rename + slug redirects do exist).
  - [ ] Add a package rename/alias control with chain-aware redirect display.
- ✅ **Package-set editor** — explicit members, glob rules, resolved membership.

---

## Suggested priority

High-value, self-contained, in-scope for the open tree:

1. **Styled global states** — 404 / no-access / error pages (G).
2. **Onboarding wizard** — guided account → org → repo → install (A).
3. **Grouped Packages view** — expandable per-package rows + lifecycle filter +
   counts (D).
4. **Confirm-modal component** — reuse for token revoke, repo/org delete, etc. (G).
5. **Recent-activity card on the dashboard** + **failed-job retry** (B, G).
6. **Package rename/alias control** (H).
7. **⌘K command palette** (B).

Larger / commercial surfaces (scope first):

- Agency overview + client curation (E).
- Vendor overview, Buyers, Custom hostnames, Recent sales, Buyer portal (F).
- Audit log & vulnerability findings (G).
- Billing & plan (C) — hosted-only.

## Notes on method

- Design source: the Claude Design handoff bundle for "Bougie Repo" (screen
  inventory, sections A–H) plus the standalone `Login.dc.html`.
- Implementation audited by running `sconce ui` and screenshotting every
  reachable screen (headless Chromium), cross-checked against the routes in
  `crates/sconce-server/src/ui.rs::router`.
