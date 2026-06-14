-- SCIM provisioning (the offboarding mechanism). Each org has a bearer token its
-- IdP uses to provision/deprovision into that org. Deactivation flips a
-- membership to inactive (and the app revokes the user's sessions), so access
-- stops immediately — what OIDC login alone can't signal.
alter table user_tenants add column if not exists active boolean not null default true;

create table if not exists scim_tokens (
    org_id     uuid primary key references organizations (id) on delete cascade,
    token_hash bytea not null unique,
    created_at timestamptz not null default now()
);
