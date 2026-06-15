-- Per-credential supply-chain policy (license-based policy).
--
-- A repo read token or a seller license key may carry its own update policy
-- override, so one repo can serve a conservative buyer "delayed, >=30-day-old
-- versions only" while another credential on the same repo sees the repo
-- default. NULL = inherit the repo. The override can only *tighten* the repo
-- policy at serve time (it never weakens a hold / security posture) — see
-- PolicyOverride::effective.
alter table tokens add column if not exists update_mode  text;
alter table tokens add column if not exists cooldown_days int;
alter table tokens drop constraint if exists tokens_update_mode_chk;
alter table tokens add constraint tokens_update_mode_chk
    check (update_mode is null or update_mode in ('auto', 'manual', 'delayed'));

alter table license_keys add column if not exists update_mode  text;
alter table license_keys add column if not exists cooldown_days int;
alter table license_keys drop constraint if exists license_keys_update_mode_chk;
alter table license_keys add constraint license_keys_update_mode_chk
    check (update_mode is null or update_mode in ('auto', 'manual', 'delayed'));
