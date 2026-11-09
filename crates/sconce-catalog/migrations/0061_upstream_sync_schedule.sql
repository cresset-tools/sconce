-- Automatic upstream syncs. The worker checks each upstream when its
-- next_check_at passes: a git upstream's tags are compared with the set it
-- last mirrored (synced_refs), and a mirror job is queued only when they
-- differ; a composer upstream is re-synced, with conditional requests so an
-- unchanged package costs a 304.
--
-- Only new columns with defaults and a new table: the previous release never
-- names them, so it keeps working against this schema.

alter table upstreams add column if not exists next_check_at timestamptz not null default now();
alter table upstreams add column if not exists last_checked_at timestamptz;
-- Consecutive failed checks; spaces the next check out while an upstream is down.
alter table upstreams add column if not exists check_failures integer not null default 0;
alter table upstreams add column if not exists last_check_error text;
-- git: digest of the tag set (name → peeled commit) the last successful
-- mirror saw. Null = never mirrored, so the next check queues a mirror.
alter table upstreams add column if not exists synced_refs text;

create index if not exists upstreams_next_check_idx on upstreams (next_check_at);

-- HTTP validators of the last successfully processed response per URL, for
-- conditional requests (If-None-Match / If-Modified-Since).
create table if not exists upstream_validators (
    upstream_id   uuid        not null references upstreams(id) on delete cascade,
    url           text        not null,
    etag          text,
    last_modified text,
    updated_at    timestamptz not null default now(),
    primary key (upstream_id, url)
);
