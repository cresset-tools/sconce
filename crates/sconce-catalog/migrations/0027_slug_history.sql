-- Slug history for org/repo renames.
--
-- The Composer wire URL is org/repo-scoped, and a composer.lock pins absolute
-- dist URLs + the configured repository URL — all embedding the slug. So a
-- rename must not break existing locks/CI: we keep the old slug here and the
-- wire router 301-redirects it to the canonical path.
--
-- SECURITY: a retired slug is **never re-assignable** to a different org/repo —
-- otherwise old locks + host-scoped tokens would silently resolve to a
-- stranger's content. Creation and rename both reject retired slugs.
create table if not exists slug_history (
    id          uuid primary key default gen_random_uuid(),
    entity_type text not null check (entity_type in ('org', 'repo')),
    old_slug    text not null,
    -- For a repo, its owning org (the old slug is unique within the org). NULL
    -- for an org (org slugs are global).
    org_id      uuid references organizations (id) on delete cascade,
    -- The current entity the old slug points at (organizations.id / repositories.id).
    entity_id   uuid not null,
    retired_at  timestamptz not null default now()
);
-- An old ORG slug is globally unique; an old REPO slug is unique within its org.
create unique index if not exists slug_history_org_uniq
    on slug_history (old_slug) where entity_type = 'org';
create unique index if not exists slug_history_repo_uniq
    on slug_history (org_id, old_slug) where entity_type = 'repo';
