#!/usr/bin/env bash
# Downloads country flag PNGs from flagcdn.com and uploads them to the private R2 bucket
# under flags/<lowercase-iso-code>.png with Content-Type image/png.
set -euo pipefail

BUCKET="${1:-country-flags}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

codes=$(curl -fsS https://flagcdn.com/en/codes.json \
  | python3 -c 'import json,sys; print("\n".join(json.load(sys.stdin).keys()))' \
  | grep -E '^[a-z]{2}$')

for c in $codes; do
  curl -fsS "https://flagcdn.com/w320/${c}.png" -o "$TMP/${c}.png"
  npx wrangler r2 object put "${BUCKET}/flags/${c}.png" \
    --file "$TMP/${c}.png" --content-type image/png --remote
done
echo "Uploaded flags to bucket: ${BUCKET}"
