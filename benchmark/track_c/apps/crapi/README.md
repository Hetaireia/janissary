# OWASP crAPI

| | |
|---|---|
| Base URL | http://127.0.0.1:8888 |
| Images | 10 containers pinned via `apps.json["crapi"].image_digests` (gateway, identity, community, workshop, web, chatbot, mailhog, postgres, mongo, chromadb) |
| Auth | JWT via `/identity/api/auth/login` after `pre_register` at `/identity/api/auth/signup` |
| Port | 8888 (host) |

## Status

**Active, passing.** M43 validation completed 2026-11-05 with two clean runs:

- `20261030T110245Z-crapi` — TP=2, FP=0, FN=0, TN=3, F1=1.0 (initial)
- `20261105T055315Z-crapi` — TP=2, FP=0, FN=0, TN=3, F1=1.0 (ADR-025 validation)

Both runs match exactly. See ADR-025 for the scope decision (M43 ships
single-session validation; tri-session-vs-crAPI deferred to M43.5).

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

## Tri-session validation (M43.5, ADR-026)

M43 validated crAPI end-to-end with single-session auth (F1=1.0).
M43.5 adds tri-session validation: prove M41's 401-triggered rotation
works against crAPI by running with a multi-session file and confirming
`aborts: 0`.

### What gets proven

- **Run 1 (both-valid)**: sessions file has two valid JWTs. Scanner uses
  first for all trials. Rotation never fires. Proves: multi-session
  config is accepted without breaking the scan.
- **Run 2 (invalid-then-valid)**: sessions file has one invalid JWT
  followed by a valid one. Scanner tries invalid, gets 401, rotates to
  valid, succeeds. Proves: rotation fires on 401 and recovers.

Both runs must produce `aborts: 0` and F1=1.0 (matching the M43
baseline of TP=2/FP=0/FN=0/TN=3).

### Workflow

1. Start crAPI (10 containers, see "Start" above).
2. Login as `login.data.email` -> capture `jwt_primary`.
3. Login as `login_alt.data.email` -> capture `jwt_alt`.
4. Write two sessions files:

   `sessions-both-valid.json`:
   ```json
   [{"cookie": null, "bearer": "<jwt_primary>"},
    {"cookie": null, "bearer": "<jwt_alt>"}]
   ```

   `sessions-rotation.json`:
   ```json
   [{"cookie": null, "bearer": "invalid.jwt.value"},
    {"cookie": null, "bearer": "<jwt_alt>"}]
   ```

5. Run each pair:

   ```
   python -m benchmark.track_c.runner --app crapi --sessions-file sessions-both-valid.json
   python -m benchmark.track_c.score --app crapi

   python -m benchmark.track_c.runner --app crapi --sessions-file sessions-rotation.json
   python -m benchmark.track_c.score --app crapi
   ```

6. Verify both run dirs' `score.json` show `aborts: 0` and `f1: 1.0`,
   and `exit_codes.json` records include `sessions_used: 2`.

### Identity blocks

Two identity blocks live in `apps.json["crapi"]`:

- `login` -- primary (`jns-trackc@example.com`)
- `login_alt` -- alternate (`jns-trackc-alt@example.com`)

Both use `capture_jwt_from_json` + `pre_register`. Distinct emails
ensure the JWTs are for different users (rotation tests a real
identity change, not a token refresh).
