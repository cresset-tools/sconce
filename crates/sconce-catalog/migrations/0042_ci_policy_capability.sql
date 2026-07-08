-- CI OIDC policies now declare a **capability**: what the minted token can do.
-- 'read' (the default, back-compatible with every existing policy) mints a repo
-- serving token into `tokens`; 'publish' mints a short-lived *publish* token into
-- `publish_tokens`, letting a zero-secret CI workflow upload package versions. The
-- two exchange endpoints filter by this column so a serving policy can never mint a
-- publish token and vice versa.
alter table ci_oidc_policies
    add column capability text not null default 'read'
        check (capability in ('read', 'publish'));
