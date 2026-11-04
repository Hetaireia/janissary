# OWASP WebGoat

| | |
|---|---|
| Base URL | http://127.0.0.1:8889 (host) -> :8080 (container) |
| Image | webgoat/webgoat |
| Auth | user1 / user1 (lesson accounts; guest works for some lessons) |
| Port | 8889 (host), chosen to avoid the ModSecurity CRS container on :8080 |

## Status

**Documented, activation pending.** apps.json["webgoat"] is present with
"excluded": true and "trial_class": []. The Docker image, auth flow and
endpoint shape are recorded below; trial cases have not been validated
end-to-end, so WebGoat is intentionally not scored.

The top-level Track C README lists this under "Known gaps":
> Multi-step auth flows beyond simple cookie set (e.g. WebGoat).

The auth flow is the blocker. WebGoat gates most lessons behind a JS-driven
registration handshake that also establishes a per-session JSESSIONID +
WEBGOAT_SESSION pair. That can likely be reproduced by cases.csv's existing
cookie-set mechanism once the exact request pair is captured, but it has
not been validated.

## Classes to exercise (once activated)

- `sqli` - /SqlInjection.lesson and /SqlInjectionAdvanced.lesson family,
  exposed as POST forms with a `query` or `name` parameter.
- `xss` - /CrossSiteScripting.lesson.
- `traversal` - /PathTraversal.lesson.

## Start

    docker compose -f benchmark/track_c/apps/webgoat/docker-compose.yml up -d

Healthcheck: curl -sf http://localhost:8080/WebGoat/login.

## Activation checklist

1. Pull webgoat/webgoat:latest and record its image_digest in apps.json
   (mirror the DVWA and Juice Shop entries).
2. Capture the registration flow with curl -v and translate to
   apps.json["webgoat"]["login"] (the pre_register + capture_* fields used
   by vampi and crapi are the working precedents).
3. Add per-class rows to cases.csv.
4. Flip "excluded": false and set "trial_class" to the validated list.
5. Run `python -m benchmark.track_c.runner --app webgoat` and score.