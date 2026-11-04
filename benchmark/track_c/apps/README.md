# Track C - per-app corpus

This directory holds one subdirectory per **documented** Track C target.
The executable configuration lives in `../apps.json`; `../cases.csv` holds
the per-case scan targets; `../runner.py` reads both.

The subdirectories here are documentation + Docker helpers. They do not
change how the runner executes - that continues to be driven by apps.json.

## Structure

    apps/
      README.md           <- this file
      <app>/
        README.md         <- what it tests, auth flow, how to start, apps.json excerpt
        docker-compose.yml <- only when the app is not already in ../docker-compose.yml

## Targets

| App | Status | Compose |
|-----|--------|---------|
| DVWA | active | ../docker-compose.yml (service `dvwa`) |
| OWASP Juice Shop | active | ../docker-compose.yml (service `juice-shop`) |
| OWASP WebGoat | documented, activation pending | ./webgoat/docker-compose.yml |

Activation status mirrors `apps.json[name].excluded`. A documented-but-excluded
target is honest bookkeeping: we have the image, the auth flow and the entry,
but the trial cases have not been validated end-to-end and are therefore not
scored. See `../AMENDMENT-24.md` for the schema.