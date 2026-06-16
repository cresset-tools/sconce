-- Package sets — a named, org-scoped group of packages, the shared primitive
-- reused by seller entitlements (license a SKU/edition), agency autogrant (a
-- house bundle), and public allowlists. Membership is **explicit members** plus
-- **glob rules** (`vendor/*`, auto-including matching packages added later), so a
-- set defined by a rule auto-grows. Resolution unions both (see resolve_set).
create table if not exists package_sets (
    id         uuid primary key default gen_random_uuid(),
    org_id     uuid not null references organizations (id) on delete cascade,
    name       text not null,
    created_at timestamptz not null default now(),
    unique (org_id, name)
);

-- Explicit members: specific packages (in this org's repos).
create table if not exists package_set_members (
    set_id     uuid not null references package_sets (id) on delete cascade,
    package_id uuid not null references packages (id) on delete cascade,
    primary key (set_id, package_id)
);

-- Glob rules: a package-name pattern (`*` wildcard) matched against the org's
-- packages, including ones added later.
create table if not exists package_set_rules (
    id     uuid primary key default gen_random_uuid(),
    set_id uuid not null references package_sets (id) on delete cascade,
    glob   text not null
);
