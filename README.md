# sconce

_The modern, self-hostable private Composer repository — a Satis in Rust._

sconce is a **single-binary, open-source private [Composer](https://getcomposer.org/)
repository**: the easy, self-hosted middle ground between Satis (free but clunky)
and Private Packagist (great but hosted/paid). It mirrors packages from git/VCS
sources and other Composer repos, serves metadata compatible with **both**
Composer v1 (`provider-includes`) and v2 (`metadata-url`) clients, and re-archives
every version into a **deterministic, content-addressed** artifact, so identical
packages dedupe and download URLs stay stable.

Its headline feature is **preventive supply-chain control**: per-repo version
**cooldown** (only expose releases older than N days), **manual approval queues**,
**allowlists**, and **security holds** — so a compromised upstream release can't
reach your builds before a human vets it. (Notably *not* a speed play — Private
Packagist already mirrors dist; sconce competes on self-hosting, ownership, and
control.)

sconce is fully open source (EUPL-1.2) — all features, including agency and
seller modes, are in the open tree. A hosted deployment ("**Bougie Repo**") and
support are possible later, but nothing is gated today. It's a member of the
[cresset-tools](https://github.com/cresset-tools) family alongside
[bougie](https://github.com/cresset-tools/bougie) and
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

## Run it (Docker)

A single `sconce serve` process runs the Composer wire API, the admin UI, **and**
the in-process mirror worker; Postgres is the only dependency. With Docker:

```bash
SCONCE_ADMIN_PASSWORD=change-me docker compose up --build
# wire API → http://localhost:8080      (composer repositories.<x> composer …)
# admin UI → http://localhost:8081      (single-tenant; password above)
```

Then in the UI: create an org + repo, add an upstream (a git URL or a Composer
registry like `https://repo.mage-os.org` with a `^vendor/` match), hit **Sync**,
and add a read token — the install snippet is shown on the token page.

Config is environment-based (12-factor): `DATABASE_URL`, `SCONCE_ADMIN_PASSWORD`,
and `SCONCE_SECRET_KEY` (base64 of 32 bytes; needed only to store *private*
upstream credentials). Run a dedicated worker instead of the in-process one with
`sconce serve --no-worker` + `sconce worker --cas …`.

## Workspace

| Crate | Role |
| --- | --- |
| `sconce` | CLI + `serve`/`worker`/`ui` binary |
| `sconce-archive` | deterministic, content-addressable archive writer |
| `sconce-cas` | content-addressed blob store (sha256, fanout) |
| `sconce-catalog` | Postgres catalog: packages, versions, upstreams, jobs, deps |
| `sconce-git` | git-tree reader (canonical modes, `export-ignore`) |
| `sconce-metadata` | Composer v1/v2 metadata rendering |
| `sconce-mirror` | mirror worker: git clone + composer-registry, dependency closure |
| `sconce-server` | Composer wire API + admin UI |

## License

[EUPL-1.2](./LICENSE). The EUPL's copyleft covers network use ("providing
access to its essential functionalities"), giving an AGPL-style trigger for
anyone running a hosted service off it.
