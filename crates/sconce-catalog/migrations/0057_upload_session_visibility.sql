-- A chunked package upload may ask for the visibility (licensing) of the package
-- it creates, like a single-shot publish's `?visibility=`. The request names it
-- when the session opens, so it is carried on the session until `complete`.
-- Null = the repository's default.
alter table upload_sessions add column if not exists visibility text;
alter table upload_sessions drop constraint if exists upload_sessions_visibility_chk;
alter table upload_sessions add constraint upload_sessions_visibility_chk
    check (visibility is null or visibility in ('public', 'private'));
