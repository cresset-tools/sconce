-- CI OIDC token exchange: a policy lets a CI workflow trade its platform OIDC
-- JWT for a short-lived repo token (zero stored secret). A request is granted if
-- its JWT validates against `issuer`/`audience` AND every claim in `claims`
-- matches (e.g. {"repository":"acme/app","ref":"refs/heads/main"}).
create table if not exists ci_oidc_policies (
    id              uuid primary key default gen_random_uuid(),
    repo_id         uuid not null references repositories (id) on delete cascade,
    provider        text not null,             -- 'github' | 'gitlab' | label
    issuer          text not null,             -- OIDC issuer (JWKS discovered from it)
    audience        text not null,             -- expected `aud`
    claims          jsonb not null default '{}',
    token_ttl_secs  bigint not null default 900,
    created_at      timestamptz not null default now()
);
create index if not exists ci_oidc_policies_repo_idx on ci_oidc_policies (repo_id);
