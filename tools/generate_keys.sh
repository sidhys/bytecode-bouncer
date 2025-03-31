#!/usr/bin/env bash
set -euo pipefail

seed="${1:-$(date +%s)}"
secret="$(openssl rand -hex 32)"
key_id="$(printf '%s' "key-id|${secret}" | shasum -a 256 | awk '{print $1}')"

printf 'seed=%s\n' "$seed"
printf 'key_id=%s\n' "$key_id"
printf 'secret=%s\n' "$secret"
