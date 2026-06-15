-- Package lifecycle: distinguish "can't sync anymore" from "still serving".
--
-- Mirrored dists live in the CAS, so a package keeps serving its already-
-- mirrored versions even after its upstream breaks or yanks it. These columns
-- govern only the *discovery of new versions* and the operator's view — they do
-- NOT remove the package from packages.json/p2 (serving is unchanged).
--
--   sync_health     'ok' | 'broken'  — worker-set; 'broken' = a *terminal* sync
--                   failure (source gone / access refused / deterministically
--                   bad content). Transient failures never set this.
--   broken_reason   why it broke (bad_content | auth_failed | source_gone | …).
--   broken_at       when it was first flagged broken.
--   last_success_at last time a sync succeeded (drives the "stale" indicator).
--   archived_at     operator froze it: acknowledges a broken package or
--                   deliberately freezes a healthy one. Masks the broken flag
--                   and stops scheduling syncs. NULL = active.
alter table packages add column if not exists sync_health     text not null default 'ok';
alter table packages add column if not exists broken_reason   text;
alter table packages add column if not exists broken_at       timestamptz;
alter table packages add column if not exists last_success_at timestamptz;
alter table packages add column if not exists archived_at     timestamptz;

alter table packages drop constraint if exists valid_sync_health;
alter table packages add  constraint valid_sync_health check (sync_health in ('ok', 'broken'));
