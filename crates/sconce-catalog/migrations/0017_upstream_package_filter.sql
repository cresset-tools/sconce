-- Optional regex scoping which packages a *composer* upstream mirrors on sync
-- (e.g. '^mage-os/' or '^magento/module-'). NULL = every package the registry
-- lists in available-packages (potentially huge — set a filter for big repos).
-- Ignored for git upstreams (which are a single source).
alter table upstreams add column if not exists package_filter text;
