-- Per-org BYO-OIDC: a connection may be scoped to an org (org_id set), and a
-- login flow remembers which connection it belongs to so the callback uses the
-- right one (and grants that org's membership).
alter table oidc_flows add column if not exists conn_id uuid references oidc_connections (id) on delete cascade;

-- At most one connection per org (the instance default already has its own
-- partial unique index from 0020).
create unique index if not exists oidc_conn_org_uniq
    on oidc_connections (org_id) where org_id is not null;
