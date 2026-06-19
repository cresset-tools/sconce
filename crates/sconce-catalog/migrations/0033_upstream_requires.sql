-- Mirror subscriptions: an ordered require-list scoping which packages (and from
-- which version) an upstream mirrors. Replaces the single `upstreams.package_filter`
-- regex — the thing that column expressed is really a `composer.json` require list
-- (name → version floor), so model it as one. Each row is one OR-ed entry; a
-- package is mirrored iff it matches ANY entry, and a version is kept iff it
-- satisfies the floor of at least one matching entry.
create table if not exists upstream_requires (
    id            uuid primary key default gen_random_uuid(),
    upstream_id   uuid not null references upstreams (id) on delete cascade,
    -- Ordering within an upstream (stable display + deterministic union).
    position      integer not null default 0,
    -- How `pattern` matches a package name:
    --   prefix - the name starts with `pattern` (a vendor: 'mage-os/', or any prefix)
    --   exact  - the name equals `pattern` (a single package)
    --   all    - matches every package (explicit require-all opt-in; `pattern` ignored)
    --   regex  - advanced escape hatch: `pattern` is a regex over the name
    match_kind    text not null default 'prefix'
                  check (match_kind in ('prefix', 'exact', 'all', 'regex')),
    pattern       text not null default '',
    -- Optional version floor: mirror only versions >= this (a bare version like
    -- '2.4', normalized like a tag). NULL = every version.
    version_floor text,
    created_at    timestamptz not null default now()
);
create index if not exists upstream_requires_idx
    on upstream_requires (upstream_id, position);

-- Clean break: the regex package_filter is superseded by upstream_requires.
alter table upstreams drop column if exists package_filter;
