-- Database **snapshots** (datasets): a `.jibsdump` produced by the scheduled dump
-- job, uploaded through the same OIDC-authenticated chunked-upload machinery as a
-- package (a publish token, staged parts in the CAS, assembled server-side), then
-- registered here instead of as a `package_versions` row. Each repo+environment has
-- a moving **latest** pointer, so `org/repo/env/latest` resolves to a short-lived
-- presigned download exactly like a dist URL. Unlike a package the bytes are stored
-- verbatim (no re-archive) — a dump is opaque.
--
-- Reuses CAS + refcount + GC verbatim: a snapshot references a blob by its sha256,
-- and a trigger (mirroring `package_versions`' `trg_blob_refcount`) keeps the blob's
-- refcount in step so retention deletes flow into the existing orphan GC.

create table if not exists snapshots (
    id           uuid primary key default gen_random_uuid(),
    repo_id      uuid not null references repositories (id) on delete cascade,
    environment  text not null,
    blob_sha256  bytea not null references blobs (sha256),
    size_bytes   bigint not null,
    source_ref   text,
    created_at   timestamptz not null default now()
);

-- Newest-first per environment: drives `list`, retention, and resolving "latest".
create index if not exists snapshots_repo_env
    on snapshots (repo_id, environment, created_at desc);

-- The moving "latest" pointer, one row per (repo, environment). Advanced on every
-- successful upload. `on delete cascade` from the snapshot keeps it consistent, so
-- retention must never prune the row a pointer still references (see the catalog's
-- prune query).
create table if not exists snapshot_latest (
    repo_id      uuid not null references repositories (id) on delete cascade,
    environment  text not null,
    snapshot_id  uuid not null references snapshots (id) on delete cascade,
    updated_at   timestamptz not null default now(),
    primary key (repo_id, environment)
);

-- Refcount the snapshot's blob, mirroring `blob_refcount_adjust` on package_versions
-- (migration 0036). Without this a snapshot blob would sit at refcount 0 and the
-- orphan GC would reclaim bytes still referenced by a live snapshot.
create or replace function snapshot_blob_refcount_adjust()
returns trigger language plpgsql as $$
begin
    if tg_op = 'INSERT' then
        perform blob_refcount_bump(new.blob_sha256, 1);
    elsif tg_op = 'DELETE' then
        perform blob_refcount_bump(old.blob_sha256, -1);
    elsif tg_op = 'UPDATE' and new.blob_sha256 is distinct from old.blob_sha256 then
        perform blob_refcount_bump(old.blob_sha256, -1);
        perform blob_refcount_bump(new.blob_sha256, 1);
    end if;
    return null;
end;
$$;

drop trigger if exists trg_snapshot_blob_refcount on snapshots;
create trigger trg_snapshot_blob_refcount
    after insert or update or delete on snapshots
    for each row execute function snapshot_blob_refcount_adjust();

-- Generalize the chunked-upload session (migration 0044) to carry snapshots too, so
-- the part-staging + assemble routes are shared. `kind` discriminates; a package
-- session keeps vendor/name/version, a snapshot session carries an environment.
alter table upload_sessions
    add column if not exists kind text not null default 'package'
        check (kind in ('package', 'snapshot'));
alter table upload_sessions add column if not exists environment text;
alter table upload_sessions alter column vendor drop not null;
alter table upload_sessions alter column name drop not null;
alter table upload_sessions alter column version drop not null;
alter table upload_sessions
    add constraint upload_sessions_kind_fields check (
        (kind = 'package' and vendor is not null and name is not null and version is not null)
        or (kind = 'snapshot' and environment is not null)
    );
