-- Blob reference counting + GC support.
--
-- Blobs are content-addressed and globally deduplicated: one blob can back
-- many package_versions across many repos/tenants. To reclaim a blob safely we
-- must know it is referenced by *nothing* — so we maintain an exact reference
-- count on `blobs`, driven by triggers on `package_versions` (the only table
-- that references a blob, via `dist_blob_sha256`). Triggers, not application
-- code, so the count can never drift: it moves atomically with the row that
-- changes it, including the `on delete cascade` from repositories → packages →
-- package_versions (so deleting a repo decrements its blobs' refcounts for
-- free, with no change to delete_repo).
--
-- `last_seen_at` is bumped every time the mirror worker upserts a blob (even a
-- dedup hit, just before it references it). GC uses it as a grace window: a
-- blob about to be referenced has a fresh `last_seen_at`, so the sweep won't
-- race a mirror job that is mid-flight.

alter table blobs add column if not exists refcount integer not null default 0;
alter table blobs add column if not exists last_seen_at timestamptz not null default now();

-- Backfill the count from existing references before the triggers take over.
update blobs b
set refcount = (
    select count(*) from package_versions pv where pv.dist_blob_sha256 = b.sha256
);

-- Adjust a blob's refcount by ±1 (NULL sha = no dist blob, e.g. metapackages).
create or replace function blob_refcount_bump(sha bytea, delta integer)
returns void language sql as $$
    update blobs set refcount = refcount + delta where sha256 = sha;
$$;

create or replace function blob_refcount_adjust()
returns trigger language plpgsql as $$
begin
    if tg_op = 'INSERT' then
        if new.dist_blob_sha256 is not null then
            perform blob_refcount_bump(new.dist_blob_sha256, 1);
        end if;
    elsif tg_op = 'DELETE' then
        if old.dist_blob_sha256 is not null then
            perform blob_refcount_bump(old.dist_blob_sha256, -1);
        end if;
    elsif tg_op = 'UPDATE' and new.dist_blob_sha256 is distinct from old.dist_blob_sha256 then
        -- Re-mirror can repoint a version at different bytes (new sha): the old
        -- blob loses a reference, the new one gains it.
        if old.dist_blob_sha256 is not null then
            perform blob_refcount_bump(old.dist_blob_sha256, -1);
        end if;
        if new.dist_blob_sha256 is not null then
            perform blob_refcount_bump(new.dist_blob_sha256, 1);
        end if;
    end if;
    return null; -- AFTER trigger, result ignored
end;
$$;

drop trigger if exists trg_blob_refcount on package_versions;
create trigger trg_blob_refcount
    after insert or update or delete on package_versions
    for each row execute function blob_refcount_adjust();

-- GC scans for orphans; a partial index keeps that scan cheap as the blob
-- table grows (the vast majority of blobs are referenced, refcount > 0).
create index if not exists idx_blobs_orphan on blobs (last_seen_at) where refcount = 0;
