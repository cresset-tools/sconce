-- Background job queue: one row per "mirror this upstream" request. The worker
-- claims jobs with SELECT ... FOR UPDATE SKIP LOCKED and is woken by NOTIFY on
-- the 'mirror_jobs' channel (with a poll backstop). Idempotent: re-running a
-- mirror re-derives the same blobs and upserts the same rows.
create table if not exists mirror_jobs (
    id          uuid primary key default gen_random_uuid(),
    upstream_id uuid not null references upstreams (id) on delete cascade,
    status      text not null default 'pending'
                check (status in ('pending', 'running', 'ready', 'failed')),
    attempts    integer not null default 0,
    -- Not eligible to claim until this time (used for retry backoff).
    run_after   timestamptz not null default now(),
    claimed_at  timestamptz,
    last_error  text,
    created_at  timestamptz not null default now(),
    updated_at  timestamptz not null default now()
);

-- At most one PENDING job per upstream — enqueue is a no-op if one's waiting.
-- (A running job does NOT block a new pending one, so a sync requested mid-run
-- still triggers a fresh pass afterward.)
create unique index if not exists mirror_jobs_pending_uniq
    on mirror_jobs (upstream_id) where status = 'pending';

-- Claim path: cheap lookup of the next eligible pending job.
create index if not exists mirror_jobs_claim_idx
    on mirror_jobs (run_after) where status = 'pending';
