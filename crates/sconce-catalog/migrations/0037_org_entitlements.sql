-- Per-org entitlements: a neutral resource throttle the hosted control plane
-- writes to constrain a tenant. The engine itself has no notion of plans or
-- billing (those live in the closed control plane); it only reads this row and
-- enforces it at mutation points.
--
-- **Absent row ⇒ unlimited/all-on.** A self-hoster never writes one and is
-- entirely unaffected. Feature columns therefore default TRUE and caps are
-- nullable (null = no cap), so even an explicitly-inserted-then-reset row is
-- permissive. Gates fail open (see BILLING_PLAN P2): a missing/partial row
-- grants access rather than wrongly blocking a paying customer.

create table if not exists org_entitlements (
    org_id                uuid primary key references organizations(id) on delete cascade,
    -- Soft: advisory only (billing meters the real number via org_storage; this
    -- never blocks a write, it only drives a "you're near your limit" banner).
    storage_soft_bytes    bigint,          -- null = no advisory limit
    -- Hard caps: block the mutation past the cap. null = unlimited.
    max_skus              integer,
    -- Feature switches. Default true so an absent/partial row is permissive.
    feat_agency           boolean not null default true,
    feat_sso              boolean not null default true,
    feat_multi_oidc       boolean not null default true,
    feat_repo_access      boolean not null default true,
    feat_scim             boolean not null default true,
    feat_audit_log        boolean not null default true,
    feat_custom_hostname  boolean not null default true,
    feat_white_label      boolean not null default true,
    updated_at            timestamptz not null default now()
);
