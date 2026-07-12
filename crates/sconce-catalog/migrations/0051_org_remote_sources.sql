-- Named database sources for the team manifest: the production / staging hosts
-- `bougie db get --source <name>` reproduces a row-graph from. Each source is a
-- jibs SSH target a dev with access already holds (some developers have prod or
-- staging credentials); the manifest advertises the *connection* so the dev
-- picks `--source staging` instead of retyping `--host`. This carries
-- connection metadata only — never a secret. A hosted no-credentials gateway is
-- future work.
--
-- One row per (remote, name), cascade-deleted with the `org_remotes`
-- registration so unregistering a remote drops its sources too. `remote_mysql`,
-- `identity`, and `port` are optional refinements passed through to jibs.
create table if not exists org_remote_sources (
    org_remote_id  uuid        not null references org_remotes (id) on delete cascade,
    name           text        not null,
    host           text        not null,
    remote_mysql   text,
    identity       text,
    port           integer,
    created_at     timestamptz not null default now(),
    primary key (org_remote_id, name)
);
