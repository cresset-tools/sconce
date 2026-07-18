-- Data **profiles**: named variants of a repo+environment's snapshot — a tiny
-- `small` slice for quick work, the default `full` set, a `perf` dump for load
-- testing. jibs loads a dump as a fixed artifact (no load-time parameters), so
-- each profile is a separately produced and separately published `.jibsdump`;
-- the profile becomes a third addressing dimension beside (repo, environment).
-- `bougie db pull --profile <name>` picks the variant; existing rows and the
-- profile-less routes mean `full`.
alter table snapshots
    add column if not exists profile text not null default 'full';

-- One moving "latest" per (repo, environment, profile) now.
alter table snapshot_latest
    add column if not exists profile text not null default 'full';
alter table snapshot_latest
    drop constraint if exists snapshot_latest_pkey;
alter table snapshot_latest
    add primary key (repo_id, environment, profile);

-- Newest-first per (environment, profile): drives list, retention, and digest
-- resolution (rebuilt from migration 0050's shape).
drop index if exists snapshots_repo_env;
create index if not exists snapshots_repo_env
    on snapshots (repo_id, environment, profile, created_at desc, seq desc);

-- A chunked snapshot upload session carries its target profile (null = full).
alter table upload_sessions add column if not exists profile text;

-- The team default a remote's manifest advertises beside snapshot_env — what
-- `bougie db pull` seeds when the dev names no `--profile`. Null = full.
alter table org_remotes add column if not exists snapshot_profile text;
