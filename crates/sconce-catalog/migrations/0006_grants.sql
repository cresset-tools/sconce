-- Agency curation: a repository can expose packages it doesn't own by being
-- *granted* them from another repository. The agency mirrors public/purchased
-- packages once into a shared repo, then grants a curated subset into each
-- client repo. A repo's visible set = its own packages ∪ its granted packages.
create table if not exists repository_grants (
    repo_id    uuid not null references repositories (id) on delete cascade,
    package_id uuid not null references packages (id) on delete cascade,
    granted_at timestamptz not null default now(),
    primary key (repo_id, package_id)
);

create index if not exists idx_grants_repo on repository_grants (repo_id);
