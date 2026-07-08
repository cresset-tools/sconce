-- OAuth 2.0 device authorization grant (RFC 8628) for `bougie login`: a CLI gets
-- a repo **read** token by having the user approve in the dashboard. Two parts:
-- (1) generalize read `tokens` to allow an org-scoped token, and (2) a
-- short-lived pending-state table (modeled on oidc_flows).

-- (1) Org-scoped read tokens. Until now a token was strictly per-repository
-- (repo_id NOT NULL). A device login mints one token that authenticates every
-- repo in an org (Composer keys auth by host, so one stored credential must
-- cover all of a team's repos under that host). Model it as: exactly one of
-- repo_id / org_id is set — repo_id = the existing per-repo token, org_id = the
-- new org-wide token. The serving path (token_valid) matches either.
alter table tokens alter column repo_id drop not null;
alter table tokens add column org_id uuid references organizations (id) on delete cascade;
alter table tokens add constraint tokens_repo_xor_org
    check ((repo_id is null) <> (org_id is null));

-- (2) Per-device pending-state, mirroring oidc_flows. The `device_code` (polled
-- by the CLI) is stored only as its sha256, like every other token; the
-- `user_code` is the short human string shown in the terminal and typed into the
-- approval page. `org_id` + `approved_by` are filled in when a signed-in member
-- approves. The minted token is NOT stored here — the poll endpoint mints it
-- on-demand from `org_id` once `status = 'approved'`, so no plaintext is retained.
create table if not exists device_flows (
    device_code_hash bytea primary key,
    user_code        text not null unique,
    status           text not null default 'pending'
                     check (status in ('pending', 'approved', 'denied')),
    org_id           uuid references organizations (id) on delete cascade,
    approved_by      uuid references users (id) on delete set null,
    expires_at       timestamptz not null,
    created_at       timestamptz not null default now()
);
