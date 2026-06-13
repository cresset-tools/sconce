# sconce

_A fast, Composer-compatible static repository generator — a Satis in Rust._

sconce builds [Composer](https://getcomposer.org/) package repositories from
git/VCS sources and other Composer repos, emitting static metadata compatible
with **both** Composer v1 (`provider-includes`) and v2 (`metadata-url`) clients.
It re-archives every package version into a **deterministic, content-addressed**
artifact, so identical packages dedupe and download URLs stay stable.

sconce is the open-source engine behind **Bougie Repo**, the hosted product.
It's a member of the [cresset-tools](https://github.com/cresset-tools) family
alongside [bougie](https://github.com/cresset-tools/bougie) and
[wick](https://github.com/cresset-tools/wick).

## Status

Early. The first landed primitive is the **deterministic archiver**
(`sconce-archive`): the same file tree always serializes to byte-identical ZIP
bytes, which is what makes content-addressed dedup and stable `dist.shasum`
possible.

```bash
# Archive a directory into a reproducible zip — run it twice, compare:
cargo run -p sconce -- archive ./my-package out.zip
```

## Workspace

| Crate | Role |
| --- | --- |
| `sconce` | CLI binary |
| `sconce-archive` | deterministic, content-addressable archive writer |

## License

Proprietary — all rights reserved. See [LICENSE](./LICENSE).
