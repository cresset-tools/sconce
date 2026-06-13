# sconce

_The modern, self-hostable private Composer repository — a Satis in Rust._

sconce is a **single-binary, open-source private [Composer](https://getcomposer.org/)
repository**: the easy, self-hosted middle ground between Satis (free but clunky)
and Private Packagist (great but hosted/paid). It mirrors packages from git/VCS
sources and other Composer repos, serves metadata compatible with **both**
Composer v1 (`provider-includes`) and v2 (`metadata-url`) clients, and re-archives
every version into a **deterministic, content-addressed** artifact, so identical
packages dedupe and download URLs stay stable.

sconce is open-core (EUPL-1.2): the engine here is the open-source core, and
**Bougie Repo** is the hosted product + commercial agency/seller features built
on it. It's a member of the [cresset-tools](https://github.com/cresset-tools)
family alongside [bougie](https://github.com/cresset-tools/bougie) and
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

[EUPL-1.2](./LICENSE). The EUPL's copyleft covers network use ("providing
access to its essential functionalities"), giving an AGPL-style trigger for
anyone running a hosted service off it.
