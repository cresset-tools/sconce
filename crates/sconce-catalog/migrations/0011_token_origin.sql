-- How a token was minted. 'manual' = a raw token created by an operator/user
-- (the only path today); 'session' = derived from an SSO login; 'ci' = from a
-- CI OIDC exchange. The org-wide `allow_raw_tokens` policy gates ONLY 'manual'
-- tokens — SSO/CI-derived tokens are exempt (they carry an identity that can be
-- deprovisioned, which is the whole point of disabling raw tokens). Existing
-- rows are manual.
alter table tokens add column if not exists origin text not null default 'manual';
alter table tokens add constraint tokens_origin_chk
    check (origin in ('manual', 'session', 'ci'));
