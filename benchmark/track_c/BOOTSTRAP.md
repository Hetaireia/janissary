# Track C - Bootstrap

How to start the 7 track_c apps. Pinned image digests live in
`apps.json` (source of truth). See `SCHEMA.md` for lock rules.

## Start commands

- dvwa, juice-shop: `cd benchmark/track_c && docker compose up -d`
- bwapp: `cd benchmark/track_c && docker compose -f docker-compose.bwapp.yml up -d`
- crAPI (10 containers): `cd ../crapi/deploy/docker && docker compose up -d`

gitea, nextcloud, vampi: started via `docker run` in a prior
session. Reconstructed below from `docker inspect`.
| App | Image | Port | Volume | Key env |
|---|---|---|---|---|
| gitea | gitea/gitea:1.22 | 3001:3000 | /data | GITEA__security__INSTALL_LOCK=true, GITEA__server__ROOT_URL=http://127.0.0.1:3001/, GITEA_CUSTOM=/data/gitea |
| nextcloud | nextcloud:stable-apache | 8082:80 | /var/www/html | SQLITE_DATABASE=nextcloud, NEXTCLOUD_ADMIN_USER=admin, NEXTCLOUD_ADMIN_PASSWORD=admin, NEXTCLOUD_TRUSTED_DOMAINS=127.0.0.1 localhost |
| vampi | erev0s/vampi:latest | 5000:5000 | none | DB_HOST=janissary-trackc-vampi-db, DB_USER=vampi, DB_PASSWORD=vampi, DB_NAME=vampi, vulnerable=1 |

## The state gap

The locked corpus numbers in `corpus-score.json` were scored
against the *current* volume state on this host. A fresh
`docker run` with pinned digests produces app data that may
differ:

- gitea: `INSTALL_LOCK=true` on a fresh volume = broken (setup
  never ran). Run setup once or export the current volume.
- nextcloud: env vars trigger unattended install; fresh works.
- vampi: self-contained SQLite inside container; data state may differ between fresh deploys.

**To reproduce exact numbers**: export and import the current
See `scripts/export-volumes.ps1` (run while containers are healthy) and `scripts/import-volumes.ps1` (run after fresh deploy).
**To run on a fresh install**: expect login-flow variance; app
scores may differ from `corpus-score.json`.

## What "locked" means

Image identity - same digests = same binary behavior. Not volume
identity - same digests + different data may produce different
detector results. `apps.json` is authoritative for digests;
`corpus-score.json` is authoritative for numbers.

vampi is self-contained: erev0s/vampi:latest bundles SQLite by default.
Verified: docker start janissary-trackc-vampi alone brings /users/v1/_debug to 200.

## Vampi reseed: `/createdb` is non-idempotent (FN-11)

If a fresh `erev0s/vampi:latest` container returns 500 on `/users/v1/*` with
`no such table: users`, the SQLite DB exists but was never populated. Seed it:

    curl.exe http://127.0.0.1:5000/createdb

**If `/createdb` returns 500** with `UNIQUE constraint failed: books.book_title`,
retry once. Vampi's `populate_db()` does `drop_all()` + `create_all()` + row
inserts; the random `bookTitle<N>` suffix can collide mid-insert, leaving the
DB half-seeded with one or two users present and `admin` missing. A second
`/createdb` call usually lands clean.

**Detect half-seed:** after `/createdb` returns 200, verify:

    curl.exe -s -o NUL -w "%{http_code}`n" http://127.0.0.1:5000/users/v1/admin
    curl.exe -s -o NUL -w "%{http_code}`n" http://127.0.0.1:5000/users/v1/_debug

Both must be 200. If either is 404, the seed is partial — run `/createdb`
again.

**Do not `docker rm` a working container.** `docker stop` / `start` / `restart`
preserve the seeded SQLite. `docker rm` destroys it and reseeding is the only
recovery path. This container was destroyed twice in the 2026-11-01 session,
costing ~90 minutes of FN-6 investigation time.
