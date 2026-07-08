-- Chunked / resumable publish uploads. A large package is split by the client into
-- ordered parts, each uploaded in its own bounded request, so a single request body
-- limit (e.g. a proxy's 100 MB cap) is not the ceiling on package size. The part
-- *bytes* are staged in the shared CAS (content-addressed, works across fs/S3 and
-- multiple server instances); this table tracks the session and part manifest so any
-- instance can assemble the parts in order on `complete`.
--
-- Staged chunk blobs are never referenced by a `package_versions` row, so they stay
-- at refcount 0 and the existing orphan GC reclaims them automatically — abandoned or
-- completed sessions self-clean with no eager delete (and thus no cross-session race).
create table if not exists upload_sessions (
    id         uuid primary key default gen_random_uuid(),
    repo_id    uuid not null references repositories (id) on delete cascade,
    vendor     text not null,
    name       text not null,
    version    text not null,
    status     text not null default 'open'
        check (status in ('open', 'completed', 'aborted')),
    created_at timestamptz not null default now(),
    expires_at timestamptz not null
);

create index if not exists upload_sessions_repo on upload_sessions (repo_id);
-- Drives the worker sweep that aborts sessions past their deadline.
create index if not exists upload_sessions_expiry
    on upload_sessions (expires_at) where status = 'open';

-- One row per uploaded part; `chunk_sha256` is the CAS key of that part's bytes.
-- Re-uploading a part number overwrites (idempotent retry / resume).
create table if not exists upload_parts (
    session_id   uuid not null references upload_sessions (id) on delete cascade,
    part_number  integer not null,
    chunk_sha256 bytea not null,
    size_bytes   bigint not null,
    created_at   timestamptz not null default now(),
    primary key (session_id, part_number)
);
