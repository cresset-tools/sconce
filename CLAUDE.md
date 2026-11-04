# Rules when implementing javascript frontend functionality

- Always put page scripts in one <script> block at the bottom of <body>
- Always write vanilla readable javascript
- Write in a modern style. No need to support older browsers or older styles.

# Rules when writing CSS

- Write readable CSS

# Rules when writing database migrations

- The previous release keeps running against the new schema during a rolling deploy (and after a rollback), so every migration must work with the code of the release before it. Read `crates/sconce-catalog/migrations/README.md` before adding one.
- Dropping, renaming or tightening anything the previous release uses takes two releases: stop using it first, remove it in the next.
