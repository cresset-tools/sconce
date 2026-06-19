-- Monorepo / multi-package sources: a single git upstream can publish several
-- Composer packages, each defined by a composer.json at a subdirectory. The
-- catalog already binds every package to the upstream it came from
-- (packages.upstream_id), so this is a 1→N relationship on one upstream — each
-- package records the subdirectory it was archived from.
alter table packages add column if not exists source_path text not null default '';

-- The explicit subpaths a git upstream mirrors (one Composer package each). An
-- upstream with no rows mirrors the repo root as a single package (source_path
-- '', the common single-package case).
create table if not exists upstream_source_paths (
    id          uuid primary key default gen_random_uuid(),
    upstream_id uuid not null references upstreams (id) on delete cascade,
    -- Subdirectory holding the package's composer.json ('' = repo root).
    source_path text not null,
    created_at  timestamptz not null default now(),
    unique (upstream_id, source_path)
);
create index if not exists upstream_source_paths_idx
    on upstream_source_paths (upstream_id);
