-- Member repositories: a repository can serve everything other repositories in
-- its org own, as one Composer repository. A Mage-OS registry can then be one
-- repository built from a repository its releases are published to and a
-- mirror of Hyvä's registry, each accepting only its own kind of package.
--
-- Members are ordered. When two members own a package with the same name, the
-- first one serves it and the later ones' copies are hidden, the way Composer
-- treats an ordered list of repositories, so one package's versions never mix
-- two sources. One level only: a repository with members owns no packages
-- itself and is never a member of another (enforced by the catalog).
create table if not exists repository_members (
    repo_id        uuid not null references repositories (id) on delete cascade,
    member_repo_id uuid not null references repositories (id) on delete cascade,
    position       integer not null,
    created_at     timestamptz not null default now(),
    primary key (repo_id, member_repo_id),
    unique (repo_id, position),
    check (repo_id <> member_repo_id)
);

create index if not exists idx_repository_members_member on repository_members (member_repo_id);
