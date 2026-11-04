# OWASP Juice Shop

| | |
|---|---|
| Base URL | http://127.0.0.1:3000 |
| Image | bkimminich/juice-shop:v17.1.1 |
| Auth | none for the RETAIL SQLi / XSS surface |
| Port | 3000 |

## Classes exercised

- `sqli` - /rest/products/search?q=test (the classic q parameter)
- `xss` (reflected) - same endpoint, DOM/echo surface

## Start

    docker compose -f benchmark/track_c/docker-compose.yml up -d juice-shop

Healthcheck polls /rest/admin/application-version (returns a JSON object
with the current version) so the container is not marked ready until
Express is serving.

## Runner configuration

Authoritative entry: ../apps.json["juice-shop"]. No login required - the
two known-vulnerable endpoints are reachable anonymously.

## Notes

Juice Shop's SPA catch-all routing is a known false-positive source
(documented in the top-level README under "Known Limitations, Issue #1"):
the scanner's admin-panel probe used to report false positives on catch-all
routes. Regression tracked; not addressed in Track C.