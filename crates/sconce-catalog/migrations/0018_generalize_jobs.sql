-- Generalize the job queue beyond "mirror a whole upstream" so it can also
-- resolve a repo's dependency closure and mirror a single package. A job now
-- carries a `kind` and the columns relevant to it (the others are NULL):
--   mirror_upstream  -> upstream_id
--   mirror_package   -> upstream_id + package
--   resolve_closure  -> repo_id
alter table mirror_jobs add column if not exists kind text not null default 'mirror_upstream'
    check (kind in ('mirror_upstream', 'mirror_package', 'resolve_closure'));
alter table mirror_jobs alter column upstream_id drop not null;
alter table mirror_jobs add column if not exists package text;
alter table mirror_jobs add column if not exists repo_id uuid references repositories (id) on delete cascade;

-- Dedup pending jobs across all kinds: at most one pending job per
-- (kind, upstream, package, repo). NULLs are coalesced so identical pending
-- jobs actually collide (a plain unique index treats NULLs as distinct).
drop index if exists mirror_jobs_pending_uniq;
create unique index if not exists mirror_jobs_pending_uniq on mirror_jobs (
    kind,
    coalesce(upstream_id::text, ''),
    coalesce(package, ''),
    coalesce(repo_id::text, '')
) where status = 'pending';
