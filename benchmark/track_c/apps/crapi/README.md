# OWASP crAPI

| | |
|---|---|
| Base URL | http://127.0.0.1:8888 |
| Images | 10 containers pinned via `apps.json["crapi"].image_digests` (gateway, identity, community, workshop, web, chatbot, mailhog, postgres, mongo, chromadb) |
| Auth | JWT via `/identity/api/auth/login` after `pre_register` at `/identity/api/auth/signup` |
| Port | 8888 (host) |

## Status

**Active, passing.** First run 2026-10-30 (`20261030T110245Z-crapi`:
TP=2, FP=0, FN=0, TN=3, F1=1.0). Fresh validation run under ADR-025
(M43) on 2026-11-05.

## What it tests

- `ssrf` — `/workshop/api/merchant/contact_mechanic` (POST, JSON body)
- `sqli_blind` — `/workshop/api/shop/apply_coupon` (POST, JSON body)

Safe endpoints: `/`, `/workshop/api/shop/products`,
`/identity/api/v2/user/dashboard`.

## Multi-container pinning

crAPI's trial behavior depends on 10 running containers, not just one.
`apps.json["crapi"].image_digests` is an array, not a scalar. SCHEMA.md
v2.1 ("Multi-container apps") explicitly permits and requires this form.

Any single digest pin would falsely claim reproducibility of behavior
driven by the other 9 containers.

## Start

    cd ../crapi/deploy/docker && docker compose up -d

Healthcheck: `GET http://127.0.0.1:8888/` returns 200.

Wait for all 10 services healthy (~30-120s cold start) before running.
`docker compose ps` should show 10 healthy.

## Prior runs

- `20261030T110245Z-crapi` — F1=1.0 (initial validation)
- `2026-11-05T*-crapi` — M43 validation run (see ADR-025)

## Trial data

`cases.csv` rows for `app=crapi`. Templates in `../templates/crapi_*.json`.
