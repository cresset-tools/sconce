-- Integrity guardrails and idempotency fixes for editions/SKUs, backing the
-- correctness fixes in the catalog layer so invalid state is impossible
-- regardless of the entry path (CLI / UI / management API).

-- (1) An edition's policy columns must be as constrained as the license-key
-- columns they get copied into at issue time. Without this, a bad `update_mode`
-- was accepted at edition-create but then failed license_keys_update_mode_chk on
-- every issuance (an opaque 500), and a negative cooldown silently skewed the
-- delayed-update window on every key. Mirror the license_keys constraints here.
alter table editions drop constraint if exists editions_update_mode_chk;
alter table editions add constraint editions_update_mode_chk
    check (update_mode is null or update_mode in ('auto', 'manual', 'delayed'));

alter table editions drop constraint if exists editions_cooldown_chk;
alter table editions add constraint editions_cooldown_chk
    check (cooldown_days is null or cooldown_days >= 0);

-- (2) `slug` is the stable external id the management API / Magento module resolve
-- an edition by (find_edition). It must be unique within a repo, or find_edition
-- silently issues against an arbitrary one of several slug matches. Partial so
-- multiple slug-less editions remain allowed.
create unique index if not exists editions_repo_slug
    on editions (repo_id, slug)
    where slug is not null;

-- (3) Scope issue idempotency to the edition, not just (repo, order-id). The
-- documented key is the commerce order id, and a real order has several line
-- items (several editions); keyed on (repo, key) only, the 2nd line item replayed
-- the 1st's license and its SKU was never minted. Including edition_id lets one
-- order id provision one key per edition while still deduping retries per SKU.
-- (edition_id is always non-null when idempotency_key is — both are set together
-- by issue_from_edition — so the partial index stays fully enforcing.)
drop index if exists license_keys_idem;
create unique index if not exists license_keys_idem
    on license_keys (repo_id, edition_id, idempotency_key)
    where idempotency_key is not null;

-- (4) Make renewal idempotent. renew_license extends `update_until` by the
-- edition's period; a retried at-least-once "subscription renewed" webhook would
-- otherwise double-extend the bound (free updates the buyer never paid for). A
-- renewal records its idempotency key here; a repeat is a no-op that returns the
-- current bound instead of extending again.
create table if not exists license_renewals (
    id              uuid primary key default gen_random_uuid(),
    license_key_id  uuid not null references license_keys (id) on delete cascade,
    idempotency_key text not null,
    created_at      timestamptz not null default now(),
    unique (license_key_id, idempotency_key)
);
