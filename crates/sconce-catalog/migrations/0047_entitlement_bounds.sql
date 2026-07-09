-- Per-entitlement update bounds: move the perpetual-fallback ceiling from the
-- key onto the entitlement **edges**, so one key can carry differently-bounded
-- purchases (a perpetual tool + an annual subscription) and the buyer keeps a
-- single Composer auth entry. Composer http-basic auth is keyed by hostname —
-- one password per repo host — so "one key per customer" is the only shape
-- that lets a mixed portfolio install everything in one project.
--
-- Semantics (per axis, applied at serve time):
--   edge value NULL  -> inherit the key's value (0029) on that axis, so every
--                       existing key/edge keeps its exact behavior.
--   edge value set   -> this entitlement's own ceiling.
-- A package covered by several edges gets the most permissive result: any
-- unbounded covering edge wins, else the latest/highest ceiling.
--
-- Note the deliberate asymmetry: "explicitly perpetual edge on a bounded key"
-- is not expressible (NULL means inherit). Merge targets are therefore always
-- unbounded (perpetual) keys — the account key — and every bound on them lives
-- on an edge. Legacy standalone keys keep their key-level bound with NULL edges.
alter table license_set_entitlements add column if not exists update_until      timestamptz;
alter table license_set_entitlements add column if not exists version_cap_major int;
alter table entitlements             add column if not exists update_until      timestamptz;
alter table entitlements             add column if not exists version_cap_major int;
