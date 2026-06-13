-- Multi-tenancy: organizations own repositories; packages and tokens are scoped
-- to a repository, and the update policy moves from the global singleton onto
-- each repository. (Cross-repo package/grant sharing is a later slice; for now a
-- package belongs to one repo, while CAS blobs still dedupe globally.)

create table if not exists organizations (
    id          uuid primary key default gen_random_uuid(),
    slug        text not null unique,
    name        text,
    created_at  timestamptz not null default now()
);

create table if not exists repositories (
    id            uuid primary key default gen_random_uuid(),
    org_id        uuid not null references organizations (id) on delete cascade,
    slug          text not null,
    update_mode   text not null default 'auto',
    cooldown_days int  not null default 0,
    created_at    timestamptz not null default now(),
    unique (org_id, slug),
    constraint repo_valid_mode check (update_mode in ('auto', 'manual', 'delayed'))
);

alter table packages add column if not exists repo_id uuid references repositories (id) on delete cascade;
alter table tokens   add column if not exists repo_id uuid references repositories (id) on delete cascade;

-- Attach any pre-existing rows to a default/default repo so the NOT NULL +
-- per-repo uniqueness constraints below can be added safely.
insert into organizations (slug, name) values ('default', 'Default') on conflict (slug) do nothing;
insert into repositories (org_id, slug)
    select o.id, 'default' from organizations o where o.slug = 'default'
    on conflict (org_id, slug) do nothing;

update packages
    set repo_id = (select r.id from repositories r join organizations o on o.id = r.org_id
                   where o.slug = 'default' and r.slug = 'default')
    where repo_id is null;
update tokens
    set repo_id = (select r.id from repositories r join organizations o on o.id = r.org_id
                   where o.slug = 'default' and r.slug = 'default')
    where repo_id is null;

alter table packages alter column repo_id set not null;
alter table tokens   alter column repo_id set not null;

-- Package names are unique per repository now, not globally.
alter table packages drop constraint if exists packages_name_key;
alter table packages add constraint packages_repo_name_key unique (repo_id, name);

-- Policy lives on the repository; the global singleton is gone.
drop table if exists repo_settings;
