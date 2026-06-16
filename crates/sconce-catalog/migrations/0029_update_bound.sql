-- Perpetual-fallback licensing (the JetBrains "updates for a year" model). A
-- license installs versions up to a ceiling and keeps them forever; past the
-- ceiling it stops getting new releases until renewed.
--
-- The ceiling is one of two kinds (both NULL = perpetual / unbounded):
--   update_until      time bound: a version is in-window if its (graced)
--                     entitlement date is <= this.
--   version_cap_major version bound: a version is allowed if its major
--                     (normalized_version's first component) is <= this — i.e.
--                     "this major and below". A new major needs a new license.
alter table license_keys add column if not exists update_until      timestamptz;
alter table license_keys add column if not exists version_cap_major  int;

-- Per-release seller "generosity" knobs (time axis), used by the serving clause:
--   grace_days        shift a release's effective entitlement date earlier, so a
--                     license that lapsed up to N days before it still gets it.
--   entitlement_date  override the date used for the time bound (backport: treat
--                     a patch as part of an older line). Defaults to released_at.
alter table package_versions add column if not exists grace_days       int not null default 0;
alter table package_versions add column if not exists entitlement_date timestamptz;
