-- Autogrant from a shared package set (the agency "house bundle"): a standing
-- rule that grants **every** package in a set into a target repo, including ones
-- added to the set later. Resolution is virtual (serving unions rule-granted
-- packages), so the target auto-grows as the set grows; removing the rule
-- removes the inherited access. Honors the set's own org scoping.
create table if not exists repository_grant_rules (
    id             uuid primary key default gen_random_uuid(),
    target_repo_id uuid not null references repositories (id) on delete cascade,
    set_id         uuid not null references package_sets (id) on delete cascade,
    created_at     timestamptz not null default now(),
    unique (target_repo_id, set_id)
);
