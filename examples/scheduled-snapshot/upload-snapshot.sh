#!/usr/bin/env bash
#
# Upload a database dump to sconce as the latest snapshot for an environment,
# using a zero-secret CI-OIDC **publish** token and the chunked upload API (so an
# arbitrarily large dump is never bounded by a single request body limit).
#
# Flow: request the platform OIDC JWT -> exchange it at /oauth/ci-publish for a
# short-lived publish token -> open an upload session -> split the dump into parts
# and upload each -> complete with the whole-file sha256. sconce assembles the
# parts, stores the dump verbatim, and advances `<env>/latest`.
#
# Required environment (set in the workflow):
#   SCONCE_URL     base URL of your sconce instance, e.g. https://repo.example.com
#   SCONCE_REPO    org/repo in sconce, e.g. acme/backend
#   SNAPSHOT_ENV   environment label, e.g. production
# Optional:
#   SCONCE_OIDC_AUDIENCE   the `aud` your CI policy expects (default: $SCONCE_URL)
# Provided automatically by GitHub Actions when `permissions: id-token: write`:
#   ACTIONS_ID_TOKEN_REQUEST_URL, ACTIONS_ID_TOKEN_REQUEST_TOKEN
#
# Usage: upload-snapshot.sh <dump-file>
# Deps: curl, jq, split, sha256sum (all present on ubuntu-latest runners).

set -euo pipefail

DUMP="${1:?usage: upload-snapshot.sh <dump-file>}"
: "${SCONCE_URL:?set SCONCE_URL}" "${SCONCE_REPO:?set SCONCE_REPO}" "${SNAPSHOT_ENV:?set SNAPSHOT_ENV}"
: "${ACTIONS_ID_TOKEN_REQUEST_URL:?missing OIDC request URL — set 'permissions: id-token: write'}"
[ -f "$DUMP" ] || { echo "no such dump file: $DUMP" >&2; exit 1; }

base="${SCONCE_URL%/}/${SCONCE_REPO}"
audience="${SCONCE_OIDC_AUDIENCE:-$SCONCE_URL}"

echo "==> requesting OIDC token (audience: $audience)"
jwt="$(curl -fsSL -H "authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
    "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=${audience}" | jq -r '.value')"

echo "==> exchanging for a short-lived publish token"
token="$(curl -fsSL -X POST "${SCONCE_URL%/}/oauth/ci-publish" \
    -H 'content-type: application/json' \
    -d "$(jq -nc --arg r "$SCONCE_REPO" --arg j "$jwt" '{repository:$r, jwt:$j}')" \
    | jq -r '.access_token')"
[ -n "$token" ] && [ "$token" != "null" ] || { echo "publish-token exchange failed (no matching CI policy?)" >&2; exit 1; }
auth=(-H "authorization: Bearer $token")

echo "==> opening upload session for $SCONCE_REPO [$SNAPSHOT_ENV]"
init="$(curl -fsSL -X POST "${auth[@]}" "$base/snapshots/$SNAPSHOT_ENV/uploads")"
upload_id="$(jq -r '.upload_id' <<<"$init")"
part_size="$(jq -r '.part_size_limit' <<<"$init")"

work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
split -b "$part_size" -d -a 6 "$DUMP" "$work/part."

n=0
for part in "$work"/part.*; do
    n=$((n + 1))
    echo "==> uploading part $n ($(wc -c <"$part") bytes)"
    curl -fsSL -o /dev/null -X PUT "${auth[@]}" --data-binary @"$part" \
        "$base/uploads/$upload_id/parts/$n"
done

echo "==> completing ($n part(s))"
sha="$(sha256sum "$DUMP" | cut -d' ' -f1)"
resp="$(curl -fsSL -X POST "${auth[@]}" -H 'content-type: application/json' \
    -d "$(jq -nc --argjson p "$n" --arg s "$sha" '{parts:$p, sha256:$s}')" \
    "$base/uploads/$upload_id/complete")"

digest="$(jq -r '.digest' <<<"$resp")"
echo "==> done: $SCONCE_REPO [$SNAPSHOT_ENV] latest is now $digest"
