# Scheduled database snapshots → sconce

A nightly GitHub Actions job that produces an **anonymized** database dump from
production (with [jibs](https://github.com/cresset-tools/jibs)) and uploads it to
sconce as the `<env>/latest` **snapshot**. Developers and CI then pull a
production-shaped database from a single URL — no one but this job ever touches
prod credentials.

```
prod DB ──ssh──▶ jibs import (anonymize) ──▶ nightly.jibsdump ──▶ sconce snapshot
                                                                     │
                              GET /<org>/<repo>/snapshots/<env>/latest ◀── devs / CI
```

This directory has one file — the workflow. Copy it into your app repo:

| file | copy it to (in your app repo) |
| --- | --- |
| `dump-and-upload.yml` | `.github/workflows/db-snapshot.yml` |

The upload itself is the
[`cresset-tools/sconce-upload`](https://github.com/cresset-tools/sconce-upload)
action (it runs `sconce snapshot push` from the sconce container image), so
there's no script to vendor.

## How auth works (no stored secret)

The job never holds a sconce token. It requests a per-run **OIDC JWT** from the
CI platform (`permissions: id-token: write`) and exchanges it at
`POST /oauth/ci-publish` for a short-lived **publish** token. sconce validates
the JWT against the issuer's JWKS and your policy's claim matchers before minting
it, so only the workflow you authorized can publish. The publish token authorizes
the snapshot upload and nothing else, and expires in minutes.

## One-time setup

### 1. In sconce — authorize the workflow to publish

Create a CI-OIDC policy with the **`publish`** capability, scoped to the exact
workflow repository by a claim so no other workflow can mint a publish token:

```sh
sconce ci-policy add \
  --repo acme/backend \
  --provider github \
  --issuer https://token.actions.githubusercontent.com \
  --audience sconce \
  --claim repository=acme/backend \
  --capability publish
```

- `--audience` must equal the action's `audience` input (default: `sconce`).
- `--claim` is repeatable; tighten it further (e.g.
  `--claim ref=refs/heads/main`, `--claim workflow_ref=...`) to pin the exact
  workflow. See GitHub's OIDC token claims for the full set.
- GitLab: `--provider gitlab --issuer https://gitlab.com` and the corresponding
  `id_tokens` audience.

### 2. In your app repo — secrets and the workflow

- Add the `PROD_SSH_KEY` secret (a deploy key with **read-only** database access
  on the host jibs dumps from).
- Commit your `shop.jibs` config (the tables + anonymization rules jibs runs
  server-side).
- Copy the workflow file above; edit its `env:` block
  (`SCONCE_URL`, `SCONCE_REPO`, `SNAPSHOT_ENV`, `PROD_SSH_HOST`).

That's it — the job runs nightly (and on demand via **Run workflow**).

## Consuming the snapshot

- **Latest:** `GET /<org>/<repo>/snapshots/<env>/latest` → 302 to a short-lived
  presigned download. Requires a repo **read** token.
- **Pinned (reproducible):** `GET /<org>/<repo>/snapshots/<env>/<digest>` — pull
  the exact bytes a given run produced (the `digest` the upload prints), for
  lockfile pinning or CI-parity so every environment loads the same data.

## Retention

Nightly uploads accumulate; dedup means an unchanged dataset re-stores for ~free,
but prune old ones to bound storage. The `latest` pointer is never pruned:

```sh
sconce snapshot list  --repo acme/backend --env production        # inspect (* = latest)
sconce snapshot prune --repo acme/backend --env production --keep 7
sconce gc                                                          # reclaim freed blobs
```

Run the prune on its own schedule (a second scheduled job, or a step after the
upload).

## Scaling notes

- The `sconce-upload` action **chunks** the dump (`sconce snapshot push` splits it
  into `part_size_limit` pieces and completes with the whole-file sha256), so
  multi-GB dumps aren't bounded by a single request body limit. sconce assembles
  the parts and verifies the sha before registering the snapshot.
- Server-side ceilings: `SCONCE_MAX_UPLOAD_BYTES` (per request/part) and
  `SCONCE_MAX_SNAPSHOT_BYTES` (assembled total).
