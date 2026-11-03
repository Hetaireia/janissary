# ADR-015 -- Native Interactsh OOB client (M14)

**Status:** Accepted (2026-11-04). Session 0.4.x.
**Supersedes:** None. Extends ADR-012 D1. **Blocks:** Nothing.

## Context

ADR-012 D1 shipped SSRF detection via a user-supplied Burp-compatible
collaborator URL (`--collaborator`). ADR-012 D10 deferred a
"project-hosted collaborator (7.6.x option, evidence-driven)".

Ascension milestone **M14** (`OOB channel (interactsh) integration`,
proposed 22-NOV-2026) is that follow-up. The goal is to remove the
manual step of running `interactsh-client` out-of-band and copying
its URL, so a scan can obtain an OOB channel with a single flag.

The `ascension_state.json` probe for M14 expects a file matching
`src/**/oob*.py`, `src/**/interactsh*.py`, or `tests/**/*oob*.py`.

## Decisions

### D1. Native Python client, not a subprocess wrapper

Implement `src/janissary/integrations/interactsh.py` speaking the
Interactsh registration + poll protocol directly, mirroring
`collaborator.py` (pure Python, `requests`-based, no external binary).

Rejected: subprocess wrapper around `interactsh-client` (adds a Go
binary dependency and PATH handling); vendored copy of justinsteven
`interactsh-client-python` (license + maintenance surface).

### D2. Interface parity with `CollaboratorClient`

`InteractshClient` implements the three methods `Scanner._ssrf_phase`
already calls:

- `new_unique_id(payload_name) -> str`
- `payload_for(payload, uniq) -> str`
- `poll(uniq) -> list[SsrfHit]`

It raises `CollaboratorError` on transport/protocol failure so
`_ssrf_phase` catch-sites need no change.

### D3. `cryptography` as an optional `[oob]` extra

Interactsh requires RSA-OAEP key exchange and AES-CFB payload
decryption. Add `cryptography>=42` under
`[project.optional-dependencies] oob`, matching the existing
`yaml` / `browser` / `ml` pattern. Core install stays unchanged.

### D4. Default to public Interactsh servers, allow self-hosted

Default server list: `oast.pro`, `oast.live`, `oast.site`,
`oast.online`, `oast.fun`, `oast.me` (the ProjectDiscovery public
rotation). `--interactsh-server URL` overrides (self-hosted), with
`--interactsh-token` for authenticated servers.

### D5. CLI surface

- `--interactsh` (flag, boolean): enable OOB via Interactsh.
- `--interactsh-server URL` (optional): override default servers.
- `--interactsh-token TOKEN` (optional): auth for self-hosted.

`--interactsh` and `--collaborator` are mutually exclusive; the
parser rejects both being set.

### D6. Payload corpus reuse

`SSRF_PAYLOADS` from `collaborator.py` is reused verbatim. The
Interactsh client only changes the transport (the `{collab}` host
comes from the registered correlation domain), not the payload
templates.

### D7. Test strategy

- Unit tests (`tests/unit/test_interactsh.py`): mock `requests`
  session; cover registration, RSA-OAEP decrypt, AES-CFB decrypt of
  a canned poll response, uniq attribution, and `CollaboratorError`
  on transport failure. No network.
- Live integration test (opt-in, gated on
  `JANISSARY_INTERACTSH_LIVE=1`): spins a self-hosted
  `projectdiscovery/interactsh-server` via Docker, runs a scan of a
  local SSRF-vulnerable target, asserts a hit is recorded.

### D8. Scope: SSRF only (no new finding types)

Same SSRF use case as ADR-012. No new `finding_type` values. M14
adds a transport, not a detection class.

## Consequences

Positive: single-flag OOB; no external binary; public servers work
out of the box; self-hosted path for closed environments.

Negative: `cryptography` is a non-trivial optional dependency
(3.8 MB wheel + cffi); Interactsh protocol drift (server-side
changes) is our maintenance burden.

Neutral: `--collaborator URL` remains for Burp Pro users. Benchmarks
(`--no-waf`, no `--interactsh`) are unaffected.

## Alternatives rejected

Subprocess wrapper (binary dependency, PATH, Go runtime).
Vendored justinsteven client (license review + merge surface).
Reusing `CollaboratorClient` with a hosted proxy (violates
zero-hosting directive from ADR-012 D1).

## References

- docs/decisions/ADR-012-ssrf-via-collaborator.md -- D1, D10
- src/janissary/integrations/collaborator.py -- interface, payloads
- src/janissary/engine/scanner.py -- `_ssrf_phase` call sites
- src/janissary/cli.py -- `--collaborator` definition (line ~1446)
- ProjectDiscovery interactsh: registration (`/register`),
  poll (`/poll?id=&secret=`), RSA-OAEP + AES-CFB transport.