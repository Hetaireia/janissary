# Track C — real-target precision

Proves JANISSARY's precision on **real applications**, not just OWASP Benchmark.

## Targets

- **DVWA** — Damn Vulnerable Web Application (SQLi, XSS, traversal)
- **OWASP Juice Shop** — modern Node.js target (SQLi, XSS)

## How it works

1. `docker compose up -d <app>` starts the target locally.
2. `python -m benchmark.track_c.runner --app <app>` logs in (if needed),
   scans each case from `cases.csv`, writes `runs/<timestamp>-<app>/<class>.jsonl`.
3. `python -m benchmark.track_c.score --app <app>` classifies findings against
   `cases.csv`, writes `runs/<timestamp>-<app>/score.json` with TP / FP / FN
   and precision / recall / F1.

## Why this matters

OWASP Benchmark reports F1 0.921 with 0 FP. Real targets expose things the
benchmark doesn't: SPAs that return 200 for everything, WAFs, auth gating.
Track C is the honest second number.

## Known gaps (deferred to later iterations)

- POST-only endpoints (e.g. DVWA `/vulnerabilities/exec/`) — scanner's
  POST-body construction needs validation before we add them.
- Multi-step auth flows beyond simple cookie set (e.g. WebGoat).
