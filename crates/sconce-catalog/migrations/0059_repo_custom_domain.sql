-- Custom domain: a hostname whose root serves this repository's Composer read
-- routes, so `https://repo.example.org/packages.json` is the repository with no
-- `/<org>/<repo>` prefix, and every URL in its metadata stays on that host. Lets
-- an existing registry (e.g. repo.mage-os.org) move here without its users
-- changing their composer.json or lock files.
--
-- Stored lowercase, without scheme or port. One repository per hostname.
alter table repositories add column if not exists custom_domain text;
create unique index if not exists repositories_custom_domain_key
    on repositories (custom_domain) where custom_domain is not null;
