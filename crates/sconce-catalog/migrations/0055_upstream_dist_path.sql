-- Where a mirrored version's dist lived on its upstream, relative to the
-- upstream's base URL (e.g. `packages/mage-os/module-catalog-1.0.0.zip` for a
-- version mirrored from https://repo.mage-os.org).
--
-- composer.lock records each package's full dist URL and installs from it
-- without consulting repository metadata. When a registry is imported into
-- sconce and its domain is pointed at the sconce repository, every existing lock
-- file still asks for these paths; recording them lets the repository serve the
-- same verbatim bytes under them. Null for versions whose dist was hosted
-- elsewhere (e.g. GitHub zipballs behind Packagist) and for non-mirrored ones.
alter table package_versions add column if not exists upstream_dist_path text;

create index if not exists package_versions_upstream_dist_path
    on package_versions (upstream_dist_path)
    where upstream_dist_path is not null;
