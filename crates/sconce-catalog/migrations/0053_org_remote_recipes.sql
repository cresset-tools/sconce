-- Team-shared recipe tasks for the manifest: standard `bougie make` tasks
-- (`test`, `lint`, `deploy-check`, project flows) a team distributes so every
-- clone runs identical commands, and a task can change centrally without a
-- commit. `bougie make` folds them between the framework built-in and the
-- project's own `bougie.toml` tasks — built-in < team < local — so a team task
-- overrides the framework default but a project's own same-named task wins.
--
-- One row per (remote, task name), cascade-deleted with the `org_remotes`
-- registration. Mirrors a `bougie-recipe` TaskDef: `run` is the shell script,
-- `check` a skip-if-exit-0 probe, `deps`/`creates` the dependency + freshness
-- arrays (served as JSON arrays so bougie parses them straight into a TaskDef).
create table if not exists org_remote_recipes (
    org_remote_id  uuid        not null references org_remotes (id) on delete cascade,
    name           text        not null,
    run            text,
    check_cmd      text,
    deps           text[]      not null default '{}',
    creates        text[]      not null default '{}',
    created_at     timestamptz not null default now(),
    primary key (org_remote_id, name)
);
