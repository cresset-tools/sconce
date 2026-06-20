-- Password-reset tokens for the admin UI's "forgot password" flow. Only the
-- token's sha256 is stored (like sessions); a token is single-use (consumed by
-- stamping used_at) and short-lived (expires_at). Rows are best-effort GC'd by
-- being deleted when superseded or consumed.
create table if not exists password_resets (
    token_hash bytea primary key,
    user_id    uuid not null references users (id) on delete cascade,
    created_at timestamptz not null default now(),
    expires_at timestamptz not null,
    used_at    timestamptz
);

create index if not exists idx_password_resets_user on password_resets (user_id);
