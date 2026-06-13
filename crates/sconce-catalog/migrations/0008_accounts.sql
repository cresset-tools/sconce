-- Account system for the admin UI. A "tenant" is an organization; users can
-- belong to several, and a superadmin sees all of them. (The public Composer
-- wire API stays token/license-gated and is unaffected.)

create table if not exists users (
    id            uuid primary key default gen_random_uuid(),
    email         text not null unique,
    password_hash text not null,                  -- argon2 PHC string
    is_superadmin boolean not null default false,
    created_at    timestamptz not null default now()
);

-- Membership: which tenants (organizations) a user may administer.
create table if not exists user_tenants (
    user_id uuid not null references users (id) on delete cascade,
    org_id  uuid not null references organizations (id) on delete cascade,
    primary key (user_id, org_id)
);

-- Admin-UI login sessions (only the token's sha256 is stored).
create table if not exists sessions (
    token_hash bytea primary key,
    user_id    uuid not null references users (id) on delete cascade,
    created_at timestamptz not null default now(),
    expires_at timestamptz not null
);

create index if not exists idx_sessions_user on sessions (user_id);
