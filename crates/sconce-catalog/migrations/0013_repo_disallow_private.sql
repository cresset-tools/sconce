-- Per-repo policy: may this repo contain/serve PRIVATE packages? Default true
-- (existing behavior). When false, the repo is public-only — private packages
-- can't be added, and any already present are not served.
alter table repositories add column if not exists allow_private_packages boolean not null default true;

-- A package's visibility, driven by the upstream it was mirrored from. Today
-- everything is git-mirrored from operator-controlled sources, so 'private' is
-- the default; public-upstream mirroring (Packagist, …) will set 'public'.
alter table packages add column if not exists visibility text not null default 'private';
alter table packages add constraint packages_visibility_chk
    check (visibility in ('private', 'public'));
