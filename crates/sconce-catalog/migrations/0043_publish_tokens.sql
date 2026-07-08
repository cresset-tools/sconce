-- Publish tokens: a short-lived, repo-scoped **bearer** credential that authorizes
-- *uploading* package versions via the publish API. Deliberately a separate table
-- from read `tokens` (which only unlock Composer serving) and `service_tokens`
-- (which provision license keys) — the codebase keeps one table per privilege so
-- isolation can't depend on every query carrying the right `kind` filter; one slip
-- would be a privilege escalation.
--
-- These are minted only by the OIDC publish exchange (`/oauth/ci-publish`), never
-- shown in the admin UI as a raw operator secret. Only the sha256 is stored.
create table if not exists publish_tokens (
    id           uuid primary key default gen_random_uuid(),
    repo_id      uuid not null references repositories (id) on delete cascade,
    token_hash   bytea not null unique,
    label        text,
    created_at   timestamptz not null default now(),
    last_used_at timestamptz,
    expires_at   timestamptz
);

create index if not exists publish_tokens_repo on publish_tokens (repo_id);
