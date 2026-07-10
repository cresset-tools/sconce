-- Team-manifest lookup: map a consuming project's git remote to the org that
-- owns it, so a client can fetch a project's team config (its Composer repo
-- URLs, and later pinned service versions / policy) keyed purely by
-- `git remote get-url origin` — nothing committed to the repo.
--
-- Distinct from `upstreams.base` (a per-repo *package mirror source* clone URL):
-- this is the identity of the team's own application repository. The remote is
-- stored **normalized** (host/path with scheme, user, `:` scp-separator, `.git`
-- suffix and case folded away; see `sconce_catalog::normalize_git_remote`), so
-- every clone-URL form for the same repo — `git@github.com:acme/shop.git`,
-- `https://github.com/acme/shop` — collapses to one row. One org owns many app
-- remotes; each remote belongs to exactly one org (the UNIQUE below), and
-- re-registering it reassigns ownership.
create table if not exists org_remotes (
    id          uuid primary key default gen_random_uuid(),
    org_id      uuid not null references organizations (id) on delete cascade,
    remote      text not null unique,
    created_at  timestamptz not null default now()
);

create index if not exists org_remotes_by_org on org_remotes (org_id);
