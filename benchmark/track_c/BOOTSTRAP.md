
vampi is self-contained: erev0s/vampi:latest bundles SQLite by default.
Verified: docker start janissary-trackc-vampi alone brings /users/v1/_debug to 200.


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
- vampi: requires the DB container; data state may differ.

**To reproduce exact numbers**: export and import the current
named volumes. Procedure not automated.
**To run on a fresh install**: expect login-flow variance; app
scores may differ from `corpus-score.json`.

## What "locked" means

Image identity - same digests = same binary behavior. Not volume
identity - same digests + different data may produce different
detector results. `apps.json` is authoritative for digests;
`corpus-score.json` is authoritative for numbers.

vampi is self-contained: erev0s/vampi:latest bundles SQLite by default.
Verified: docker start janissary-trackc-vampi alone brings /users/v1/_debug to 200.
