-- Optional expiration for read tokens. NULL = never expires (the prior
-- behavior). An expired token fails validation but is kept for the audit trail
-- until explicitly revoked.
alter table tokens add column if not exists expires_at timestamptz;
