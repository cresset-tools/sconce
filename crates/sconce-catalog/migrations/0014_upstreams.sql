-- Per-repo upstreams: where packages are mirrored from. A repo owns a list of
-- these, each with its own visibility and (encrypted) credential. Upstreams are
-- bound to packages explicitly (packages.upstream_id) rather than resolved by
-- host, so two upstreams may share a host with different credentials.
create table if not exists upstreams (
    id          uuid primary key default gen_random_uuid(),
    repo_id     uuid not null references repositories (id) on delete cascade,
    kind        text not null check (kind in ('git', 'composer')),
    -- git: the clone URL. composer: the repository base URL (Packagist, …).
    base        text not null,
    -- Drives dependency classification + the package visibility of what it
    -- mirrors: 'public' (open registry / public repo) or 'private'.
    visibility  text not null check (visibility in ('public', 'private')),
    label       text,
    -- Encrypted userinfo for cloning (XChaCha20Poly1305; nonce||ciphertext).
    -- NULL for public/unauthenticated upstreams.
    credential  bytea,
    created_at  timestamptz not null default now()
);
create index if not exists upstreams_repo_idx on upstreams (repo_id);

-- Which upstream a package was mirrored from (NULL for pre-upstream/local rows).
alter table packages add column if not exists upstream_id uuid references upstreams (id) on delete set null;
