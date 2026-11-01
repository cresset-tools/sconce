-- OAuth 2.0 authorization-code grant with PKCE (RFC 6749 §4.1, RFC 7636) for
-- `bougie login`: the CLI opens the dashboard's /authorize page, a signed-in
-- member picks an org, and the browser hands a one-time code back to the CLI
-- (a loopback redirect, or pasted from the dashboard's callback page). The CLI
-- trades the code plus its PKCE verifier for the same org-scoped session token
-- the device flow mints.
--
-- A row is the approved, not-yet-redeemed code. It is stored only as its
-- sha256, bound to everything the token request must repeat: the client, the
-- exact redirect_uri, and the PKCE challenge. Redeeming deletes the row, so a
-- code works once.
create table if not exists authorization_codes (
    code_hash      bytea primary key,
    org_id         uuid not null references organizations (id) on delete cascade,
    approved_by    uuid references users (id) on delete set null,
    client_id      text not null,
    redirect_uri   text not null,
    code_challenge text not null,
    expires_at     timestamptz not null,
    created_at     timestamptz not null default now()
);
