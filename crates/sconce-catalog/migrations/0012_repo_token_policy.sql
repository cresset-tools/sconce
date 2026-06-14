-- Per-repo token-policy overrides. NULL = inherit from the org (the common
-- case). The effective policy combines org + repo so a repo can only *tighten*,
-- never loosen: raw tokens are allowed only if BOTH levels allow; the max TTL is
-- the smaller of the two caps. Columns live on `repositories` alongside the
-- existing per-repo policy (update_mode, cooldown_days).
alter table repositories add column if not exists allow_raw_tokens boolean;
alter table repositories add column if not exists max_token_ttl_days bigint;
