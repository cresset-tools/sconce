-- Dashboard SSO (OIDC Auth Code + PKCE). A connection is the IdP config; a flow
-- is the short-lived per-login transaction state. For now there is a single
-- instance-wide connection (org_id NULL = default); per-org BYO-OIDC is a later
-- extension that reuses these tables with org_id set.
create table if not exists oidc_connections (
    id             uuid primary key default gen_random_uuid(),
    org_id         uuid references organizations (id) on delete cascade, -- NULL = instance default
    issuer_url     text not null,
    client_id      text not null,
    -- Encrypted (nonce||ciphertext); NULL for a public client (PKCE only).
    client_secret  bytea,
    redirect_url   text not null,
    scopes         text not null default 'openid email profile',
    -- If set, only these email domains may sign in; NULL/empty = any verified email.
    allowed_domains text[],
    -- Email domains whose users are provisioned as superadmins; NULL/empty = none.
    admin_domains  text[],
    created_at     timestamptz not null default now()
);
-- At most one instance-default connection.
create unique index if not exists oidc_conn_instance_uniq
    on oidc_connections ((true)) where org_id is null;

-- Per-login transaction state, keyed by the opaque `state` we send to the IdP.
create table if not exists oidc_flows (
    state          text primary key,
    nonce          text not null,
    pkce_verifier  text not null,
    redirect_to    text not null default '/',
    expires_at     timestamptz not null
);
