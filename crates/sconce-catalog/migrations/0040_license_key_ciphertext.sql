-- Store the license key **encrypted at rest** (in addition to its hash), so it
-- can be recovered and shown again — e.g. an idempotent re-issue returns the
-- same key, and the management API's inspect endpoint returns it for a buyer
-- portal / the Magento module. Auth still uses key_hash; this column is only for
-- recovery.
--
-- Encrypted with XChaCha20Poly1305 under SCONCE_SECRET_KEY (nonce||ciphertext),
-- the same scheme as upstream credentials. Null when no secret key is configured
-- (then keys stay hash-only / unrecoverable) or for keys issued before this.
alter table license_keys add column if not exists key_ciphertext bytea;
