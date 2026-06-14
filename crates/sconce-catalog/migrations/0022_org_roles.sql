-- Per-tenant role: 'member' (read-only in the dashboard) or 'admin' (manage the
-- org's repos/upstreams/tokens/settings). New memberships default to 'member';
-- existing ones are backfilled to 'admin' to preserve current behavior (every
-- member could manage everything before this).
alter table user_tenants add column if not exists role text not null default 'member'
    check (role in ('member', 'admin'));
update user_tenants set role = 'admin' where role = 'member';
