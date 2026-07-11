-- Per-remote snapshot (dataset) config for the team manifest: which sconce
-- repository + environment holds the production-shaped database dump a team
-- project seeds from. `bougie db pull` reads this out of the served manifest
-- (`GET /api/v1/manifest`), so a dev on a registered project needs no `--repo`
-- — the dump source is centrally configured, like the Composer repositories.
--
-- Columns live on `org_remotes` (one dataset source per app remote). A NULL
-- `snapshot_repo_id` means "no dump configured" and the manifest omits the
-- snapshot block. `on delete set null` so retiring the dataset repo just clears
-- the pointer rather than dropping the remote registration itself.
alter table org_remotes
    add column if not exists snapshot_repo_id uuid
        references repositories (id) on delete set null,
    add column if not exists snapshot_env text;
