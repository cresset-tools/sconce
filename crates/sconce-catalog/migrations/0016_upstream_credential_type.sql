-- How an upstream's credential should be presented when cloning:
--   basic  - the secret is full userinfo (e.g. 'oauth2:TOKEN' or 'user:pass'),
--            injected as 'scheme://<secret>@host' (the prior behavior).
--   github - the secret is a token, injected as 'x-access-token:<token>'.
--   gitlab - the secret is a token, injected as 'oauth2:<token>'.
--   bearer - the secret is a token, sent as 'Authorization: Bearer <token>'.
-- Ignored for public upstreams (which have no credential).
alter table upstreams add column if not exists credential_type text not null default 'basic';
alter table upstreams add constraint upstreams_credential_type_chk
    check (credential_type in ('basic', 'github', 'gitlab', 'bearer'));
