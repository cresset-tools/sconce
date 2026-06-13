-- Composer verifies a dist by its sha1 (the `dist.shasum` field), while our CAS
-- key is the sha256. Store the sha1 hex alongside so metadata serving never has
-- to read the blob back to compute it.
alter table package_versions add column if not exists dist_shasum text;
