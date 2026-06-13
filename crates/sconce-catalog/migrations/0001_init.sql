-- Catalog schema, initial.
--
-- Three concerns kept separate (see ROADMAP): the content layer (blobs), the
-- logical packages, and their versions. Multi-tenancy (org ownership) is added
-- in a later migration; for now a package name is globally unique.

create table if not exists blobs (
    sha256      bytea primary key,
    size_bytes  bigint not null,
    created_at  timestamptz not null default now()
);

create table if not exists packages (
    id          uuid primary key default gen_random_uuid(),
    name        text not null unique,          -- "vendor/name"
    kind        text not null,                 -- 'git' | 'mirror' | 'upload'
    source      jsonb,                         -- where it comes from (git url, etc.)
    created_at  timestamptz not null default now()
);

create table if not exists package_versions (
    id                  uuid primary key default gen_random_uuid(),
    package_id          uuid not null references packages (id) on delete cascade,
    version             text not null,         -- "v1.2.0", "dev-main"
    normalized_version  text not null,         -- composer-normalized
    stability           text not null,         -- stable|RC|beta|alpha|dev
    composer_json       jsonb not null,        -- canonical, without our injected dist
    dist_blob_sha256    bytea references blobs (sha256),
    source_reference    text,                  -- git commit sha
    released_at         timestamptz,           -- upstream release time (drives cooldown)
    yanked_at           timestamptz,
    unique (package_id, normalized_version)
);

create index if not exists idx_pv_package on package_versions (package_id);
