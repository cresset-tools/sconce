-- Org-wide policy. One row per organization; absence means "all defaults"
-- (every getter coalesces to the permissive default, so existing orgs are
-- unaffected until an admin sets something). Add a future setting = add a
-- nullable/defaulted column here + a field on OrgSettings.
create table if not exists org_settings (
    org_id             uuid primary key references organizations (id) on delete cascade,
    -- When false, manually-created raw repo tokens are refused org-wide (the org
    -- mandates SSO/CI-derived credentials, which can be deprovisioned).
    allow_raw_tokens   boolean not null default true,
    -- When set, a created token must carry an expiry of at most this many days
    -- (and may not be non-expiring). NULL = no cap. bigint to match the i64 the
    -- catalog binds/reads (avoids int4/i64 friction).
    max_token_ttl_days bigint,
    updated_at         timestamptz not null default now()
);
