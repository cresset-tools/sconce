-- Grant-scoped supply-chain policy: a package **granted** into a repo can be
-- served under a tighter policy than the repo default. Resolution order at serve
-- time is credential override → grant override → repo default, all tighten-only
-- (a grant can make the gate stricter, never weaker). NULL = inherit.
alter table repository_grants add column if not exists update_mode  text;
alter table repository_grants add column if not exists cooldown_days int;
