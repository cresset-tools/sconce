-- Versions whose upstream changed after they were mirrored: a git tag moved
-- to another commit, or a composer upstream serves different dist bytes.
-- The stored version is kept (lock files pin it); this records the change so
-- the admin UI can warn about it. A row goes away when the upstream matches
-- the stored version again.
--
-- A new table only: the previous release never names it.

create table if not exists version_conflicts (
    package_id         uuid        not null references packages(id) on delete cascade,
    normalized_version text        not null,
    upstream_id        uuid        references upstreams(id) on delete cascade,
    reason             text        not null,
    detected_at        timestamptz not null default now(),
    last_seen_at       timestamptz not null default now(),
    primary key (package_id, normalized_version)
);
