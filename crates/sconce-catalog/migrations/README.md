# Migrations

Every `sconce serve` applies these on startup (`Catalog::migrate`, serialized
by an advisory lock), and a deploy restarts one instance at a time. So for a
while **the previous release runs against the new schema**: the first new
instance migrates, and the old one keeps serving until it is replaced. A
release can also be rolled back to the previous image without undoing its
migrations.

Every migration therefore has to work with the code of the release before it.

## Safe in one release

- Create a table, index or function.
- Add a column that is nullable or has a default. The old code never names
  it, so it reads and writes the table as before.
- Add a check or foreign key that the old code's writes already satisfy.
- Backfill data, if the old code ignores or tolerates the new values.

Keep each migration idempotent (`if not exists`, `if exists`), like the rest:
a failed startup re-runs it.

## Takes two releases

Anything the previous release still reads or writes: dropping or renaming a
column or table, making a column `not null` without a default, narrowing a
type or a check.

1. **Release N** stops using the old shape: it reads the new one, writes
   both if both exist, and adds the new column or table in a migration.
2. **Release N+1**, once N is the oldest version running anywhere, removes
   the old shape in its migration.

For example, `0033_upstream_requires.sql` moved `upstreams.package_filter` into
a new table and dropped the column in the same migration; an instance still on
the previous release would fail every query naming `package_filter` until it
was replaced. Under this rule the drop belongs to the next release.

## Checking a migration

Ask: if the previous release's binary ran against this schema, would any
query it makes fail or return something it misreads? If yes, split it.
