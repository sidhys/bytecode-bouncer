#!/usr/bin/env bash
set -euo pipefail

seed="${1:-$(date +%s)}"
secret="$(openssl rand -hex 32)"

printf 'seed=%s\n' "$seed"
printf 'secret=%s\n' "$secret"