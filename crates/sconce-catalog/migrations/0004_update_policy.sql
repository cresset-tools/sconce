-- Supply-chain controls: gate which versions a client may see.
--
-- Per-version deviations from the global policy.
alter table package_versions add column if not exists held_at timestamptz;     -- security hold / yank
alter table package_versions add column if not exists approved_at timestamptz; -- manual approval / early release

-- Global update policy (singleton row, enforced by a boolean PK = true).
create table if not exists repo_settings (
    id            boolean primary key default true,
    update_mode   text not null default 'auto',  -- auto | manual | delayed
    cooldown_days int  not null default 0,
    constraint singleton check (id),
    constraint valid_mode check (update_mode in ('auto', 'manual', 'delayed'))
);
insert into repo_settings (id) values (true) on conflict (id) do nothing;
