-- Deterministic "newest first" ordering for snapshots. `list_snapshots`,
-- `resolve_snapshot_by_digest`, and retention (`prune_snapshots`) all order by
-- `created_at desc`, but two snapshots created in the same microsecond tie — the
-- `id` is a random uuid, so there's no monotonic tiebreak and the order is
-- unstable (flaky on fast hardware; usually masked on slower CI where the
-- timestamps differ). Add a monotonic sequence so ties break by insertion order,
-- and extend the ordering index to match so the new order-by stays index-served.
alter table snapshots add column if not exists seq bigserial;

drop index if exists snapshots_repo_env;
create index if not exists snapshots_repo_env
    on snapshots (repo_id, environment, created_at desc, seq desc);
