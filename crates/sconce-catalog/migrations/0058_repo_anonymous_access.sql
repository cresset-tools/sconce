-- Anonymous access: when on, the repository's Composer read routes
-- (packages.json, p2 metadata, dists) answer requests that carry no credential
-- at all. Such requests see only **public** packages — those that may be
-- redistributed — under the repository's own update policy. Private packages,
-- and everything else the repository serves (publishing, uploads, snapshots, the
-- management API), still need a credential. Off by default: a repository that
-- mirrors public packages for internal work stays closed.
alter table repositories add column if not exists anonymous_access boolean not null default false;
