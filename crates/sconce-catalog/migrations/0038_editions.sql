-- Editions (SKUs): a named, reusable **issuance template** for seller mode. An
-- edition bundles the sellable content (a package set) with an update-bound
-- template and an optional policy override; license keys are issued *against* an
-- edition, which resolves the template into the existing per-key columns/tables
-- (entitlements, update_until / version_cap_major, update_mode). Serving is
-- unchanged — it still reads everything off the key. See SKU_PLAN.md.
--
-- This is also the countable entity the vendor billing track meters:
-- org_entitlements.max_skus caps active editions per org (control plane writes
-- the cap; the engine only counts + enforces).
create table if not exists editions (
    id            uuid primary key default gen_random_uuid(),
    repo_id       uuid not null references repositories (id) on delete cascade,
    name          text not null,
    -- Stable external id for the Magento product mapping / management API.
    slug          text,
    -- The sellable content, always modeled as a package set (a single-package
    -- edition uses a singleton set). Restrict-delete so an in-use set can't
    -- vanish out from under an edition.
    set_id        uuid not null references package_sets (id) on delete restrict,
    -- Bound TEMPLATE, resolved onto the key at issue:
    --   perpetual -> (until=null, major=null)
    --   time      -> until = issue_date + bound_period_months  (absolute)
    --   version   -> version_cap_major = bound_major
    bound_kind          text not null default 'perpetual',
    bound_period_months integer,
    bound_major         integer,
    -- By-reference (auto-grow, default) vs frozen set membership at purchase.
    snapshot_at_issue   boolean not null default false,
    -- Optional supply-chain policy override stamped onto issued keys (tighten-only
    -- at serve time). null = inherit the repo default.
    update_mode   text,
    cooldown_days integer,
    -- Sellable? Deactivated editions stop new sales and free a max_skus slot
    -- without touching already-issued keys.
    active        boolean not null default true,
    created_at    timestamptz not null default now(),
    unique (repo_id, name),
    constraint edition_bound_kind check (bound_kind in ('perpetual', 'time', 'version'))
);

-- Which edition a key was minted from (null = legacy / ad-hoc key). Enables
-- renewal (re-resolve the time bound from the edition), "My Licenses" inspection,
-- and the Magento order -> edition mapping.
alter table license_keys add column if not exists edition_id uuid references editions (id) on delete set null;

-- Forward-compat for idempotent provisioning (Magento order id). Unused until the
-- commerce webhook lands (SKU_PLAN step 5); the partial unique index makes a
-- retried checkout a no-op rather than a second key.
alter table license_keys add column if not exists idempotency_key text;
create unique index if not exists license_keys_idem
    on license_keys (repo_id, idempotency_key)
    where idempotency_key is not null;
