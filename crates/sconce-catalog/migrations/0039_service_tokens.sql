-- Management-API service tokens: a privileged, repo-scoped **bearer** credential
-- that a seller's commerce front-end (e.g. the Magento module) uses to provision
-- and manage license keys via `/api/v1`. Distinct from read `tokens` (which only
-- unlock Composer serving) — a service token can issue / renew / revoke keys, so
-- it is a separate, more privileged credential type. Only the sha256 is stored;
-- the plaintext is shown once at creation.
create table if not exists service_tokens (
    id           uuid primary key default gen_random_uuid(),
    repo_id      uuid not null references repositories (id) on delete cascade,
    token_hash   bytea not null unique,
    label        text,
    created_at   timestamptz not null default now(),
    last_used_at timestamptz,
    expires_at   timestamptz
);

create index if not exists service_tokens_repo on service_tokens (repo_id);
