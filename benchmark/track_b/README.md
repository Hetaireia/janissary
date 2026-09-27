# Track B — Juice Shop + Cloudflare

Harness placeholder. See `../BENCHMARK.md` for the pre-registered
methodology.

Planned files:

- `runner.py`     — drives JANISSARY / ZAP / Nuclei against the target,
                    records timing, WAF-block events, and IP-ban status.
- `cloudflare.md` — DNS/TLS setup notes, exact Cloudflare free-tier
                   settings used (defaults only, no tuned rules).
- `tools.env.example` — same shape as track_a's, plus the target hostname.

Target reset between tools: container rebuild + fresh database so state
from an earlier tool cannot influence a later one.