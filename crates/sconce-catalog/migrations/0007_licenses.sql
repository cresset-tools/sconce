-- Seller mode: a seller's repository issues license keys to buyers. Unlike a
-- read token (which unlocks the whole repo), a license key is entitled to only
-- the specific packages the buyer purchased. Buyers authenticate with the key
-- as the http-basic password (the Magento Marketplace model).

create table if not exists license_keys (
    id          uuid primary key default gen_random_uuid(),
    repo_id     uuid not null references repositories (id) on delete cascade,
    key_hash    bytea not null unique,
    buyer_ref   text,                              -- email / order id / company
    status      text not null default 'active',    -- active | revoked
    expires_at  timestamptz,
    created_at  timestamptz not null default now(),
    constraint license_valid_status check (status in ('active', 'revoked'))
);

create table if not exists entitlements (
    license_key_id uuid not null references license_keys (id) on delete cascade,
    package_id     uuid not null references packages (id) on delete cascade,
    primary key (license_key_id, package_id)
);
