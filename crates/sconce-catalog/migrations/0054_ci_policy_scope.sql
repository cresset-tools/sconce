-- A 'read' CI OIDC policy can now mint an ORG-scoped serving token — valid for
-- every repo in the org, like a device login — instead of only the policy's own
-- repo. This is what a team's CI needs: `bougie login --ci` then `bougie sync`
-- of an app that depends on many private package repos, all under one org.
--
-- `token_scope` = 'repo' (default, unchanged: the exchange mints a repo-scoped
-- serving token) or 'org' (mints an org-scoped one). Only meaningful for
-- capability='read'; publish tokens stay repo-targeted regardless.
alter table ci_oidc_policies
    add column token_scope text not null default 'repo'
        check (token_scope in ('repo', 'org'));
