#!/usr/bin/env bash
# Track B VPS setup. Idempotent-ish; review before running on a fresh box.
set -euo pipefail

cd "$(dirname "$0")"

if ! command -v docker >/dev/null 2>&1; then
  echo "[setup] docker not found. Install docker + compose plugin first." >&2
  exit 1
fi

echo "[setup] pulling pinned Juice Shop image..."
docker compose pull

echo "[setup] starting target..."
docker compose up -d

echo "[setup] waiting for healthcheck..."
for i in $(seq 1 30); do
  if docker compose ps juice-shop | grep -q healthy; then
    echo "[setup] target healthy"
    break
  fi
  sleep 2
done

echo "[setup] local smoke test:"
curl -sf -o /dev/null -w "  local: %{http_code}\n" http://127.0.0.1:8080/rest/admin/application-version || true

if [ -n "${PUBLIC_URL:-}" ]; then
  echo "[setup] public smoke test against $PUBLIC_URL:"
  curl -s -o /dev/null -w "  public: %{http_code}\n" -I "$PUBLIC_URL" || true
else
  echo "[setup] set PUBLIC_URL=https://juice.example.com to test through Cloudflare"
fi

echo "[setup] done. See cloudflare.md before running any tool."