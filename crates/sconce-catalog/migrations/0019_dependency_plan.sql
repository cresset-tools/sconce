-- The computed dependency closure for a repo, awaiting the operator's review.
-- Read-only proposal: resolving recomputes it; the operator picks which entries
-- to actually add (mirror). One row per package in the closure.
create table if not exists dependency_plan (
    repo_id      uuid not null references repositories (id) on delete cascade,
    name         text not null,                 -- "vendor/package"
    -- present | resolvable-private | resolvable-public | missing
    status       text not null,
    -- the upstream that resolves it (for resolvable-* rows), else NULL
    resolver_upstream_id uuid references upstreams (id) on delete set null,
    -- a sample package in the repo that requires it (for context)
    required_by  text,
    computed_at  timestamptz not null default now(),
    primary key (repo_id, name)
);
