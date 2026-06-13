-- Read tokens for the (single-tenant) repository. Only the sha256 of the token
-- is stored; the plaintext is shown once at creation and never persisted.
create table if not exists tokens (
    id            uuid primary key default gen_random_uuid(),
    token_hash    bytea not null unique,
    label         text,
    created_at    timestamptz not null default now(),
    last_used_at  timestamptz
);
