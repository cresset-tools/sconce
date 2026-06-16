-- Entitle a license to a whole **package set** (a SKU/edition), not just
-- individual packages. The license unlocks every package the set resolves to,
-- by reference (auto-grows as the set grows). Coexists with per-package
-- entitlements (a license can have both).
create table if not exists license_set_entitlements (
    license_key_id uuid not null references license_keys (id) on delete cascade,
    set_id         uuid not null references package_sets (id) on delete cascade,
    primary key (license_key_id, set_id)
);
