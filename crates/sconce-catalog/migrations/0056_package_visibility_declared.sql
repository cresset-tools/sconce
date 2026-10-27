-- A package's visibility says whether it may be redistributed (licensing), not
-- whether it needs a credential: `private` means you may not share it publicly.
-- It starts out derived from where the package comes from (a public registry →
-- public; your own sources, paid and credentialed upstreams → private) and is
-- refreshed from that source on every sync.
--
-- An operator can instead *declare* it — "this is my own code and I may share
-- it". A declared visibility is a deliberate licensing statement, so a later
-- sync must not undo it; this records when it was made.
alter table packages add column if not exists visibility_declared_at timestamptz;
