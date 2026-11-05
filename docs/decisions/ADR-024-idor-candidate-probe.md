# ADR-024 -- IDOR candidate probe (M42)

**Status:** Accepted (2026-11-05). Phase 2 implementation.
**Supersedes:** None.
**Amends:** FUTURE-STATE-PLAN.md Phase 2 (ADR-023 → ADR-024 renumber; CLI flags reconciled).
**Extends:** ADR-016 (vocabulary), ADR-017/022 (Track B candidates), ADR-019 (SARIF discovery routing), ADR-023 (sessions input).

## Context

README line 417 currently says: "No IDOR detection yet. Insecure Direct
Object Reference is an open gap. It is planned for Phase 2 (M42, proposed
May 2027)". That is the state M42 must change.

FUTURE-STATE-PLAN.md line 151-152 pre-specified M42's mechanism:

    detection/idor.py -- candidate-only IDOR probe (A vs B differential; C blocked)
    CLI --cookie-alt, --bearer-alt, --idor (candidates go to triage stream)

FUTURE-STATE-PLAN.md line 235 additionally named the future ADR as
"ADR-023 | IDOR candidate generation rules | 2". Between that draft and
today, ADR-023 was consumed by M41 (tri-session auth rotation). This ADR
is therefore ADR-024, and the plan table row must be renumbered. That is a
documentation fixup included in M42's delivery, not a separate concern.

M41 shipped tri-session auth with `--sessions PATH` and `SessionSpec`. That
creates a design conflict with the plan's `--cookie-alt`/`--bearer-alt`:
three different ways to express two identities is redundant. This ADR
resolves it in favor of *both* — M41's flag for users with a JSON file,
the plan's flags for users who want a one-line command. Both routes funnel
into the same `SessionSpec` pairs internally.

## Current state (evidence)

Probe 2026-11-05:

1. **Zero IDOR code exists.** Grep for `IDOR|idor|access.control` across
   `src/**/*.py` returns nothing. M42 is greenfield.

2. **`recon/admin.py` (379 lines) is unrelated.** It has `AdminHit`,
   `AdminProfile`, `AdminProbe`, `probe_admin` — admin panel discovery.
   Not reusable for cross-identity comparison (different threat model,
   different evidence shape).

3. **`recon/admin_struct.py` (74 lines) may be reusable.** It does
   structural DOM hashing (ADR-002). IDOR candidates benefit from the same
   "compare structure not bytes" primitive. M42 will reuse it if the API
   fits; else fall back to simple length comparison for v1.

4. **M41 supplies the identity mechanism.** `SessionSpec(cookie, bearer)`
   plus `--sessions PATH` file loader (`load_sessions_file`). M42 does not
   need its own credential store.

5. **M38 supplies the observation mechanism.** `Scanner.collect_observations=True`
   populates `_observations` during the payload loop. `Observation` has
   `url, body, headers, method, response_status, payload_name, payload_value,
   param`. It does NOT carry identity — M42's after-scan B refetches are
   keyed by URL, not by observation identity.

6. **M40 supplies the SARIF discovery routing.** Any `unproven` finding
   automatically routes to `runs[1]` with `properties.track="discovery"`.
   M42 does not touch SARIF; it produces `CandidateFinding` and lets the
   pipeline route.

7. **`HeuristicConfirmer` matches only `heuristic:*` discovery_reason.**
   IDOR candidates need their own `IdorConfirmer` (or broaden the check).
   This ADR chooses a separate confirmer (D2).

## Decisions

### D1. Module at `src/janissary/detection/idor.py`

Follows the plan. `detection/` is where vulnerability primitives live
(`sqli_union.py`, `pathtraver_oracle.py`, `blind_sqli_oracle.py`, ...).
IDOR is a vulnerability primitive, not a signature match. The `heuristic/`
package was created specifically for Track B *signature matching* (M37/M38);
extending it with a non-signature probe would muddy the boundary.

`heuristic/` and `detection/idor.py` both emit `CandidateFinding` and both
route through `_ENGINE.verify()` → `_to_scan_finding()`. The difference is
mechanism, not output shape.

### D2. New `IdorConfirmer` in `verification/confirmers.py`

```python
class IdorConfirmer:
    name = "idor"

    def confirm(self, candidate):
        reason = candidate.discovery_reason or ""
        if reason.startswith("idor:"):
            return Confirmation(confirmed=True, reason=reason, unproven=True)
        return None
```

Registered in `_ENGINE` before `AnalyzerImplicitConfirmer` (same position
constraint as `HeuristicConfirmer`, per ADR-023's discovery).

Why not extend `HeuristicConfirmer` to match both prefixes? Because the
two probes have independent reasons, evidence shapes, and eventual
verification rules. Combining them couples the IDOR admission criteria to
heuristic signature logic. Two small confirmers is cleaner than one
dual-purpose one.

### D3. CLI surface: `--idor` + (`--sessions` OR `--cookie-alt`/`--bearer-alt`)

Three paths to express identity pairs, all converging on
`(SessionSpec_A, SessionSpec_B)` internally:

- `--sessions file.json` (M41): file has >=2 entries; A=[0], B=[1]
- `--cookie X --cookie-alt Y --idor`: A=cookie X, B=cookie Y
- `--bearer X --bearer-alt Y --idor`: A=bearer X, B=bearer Y

Mutual exclusion: `--sessions` cannot combine with `--cookie-alt`/`--bearer-alt`
(which source wins is ambiguous). Exit 64 with a clear message.

If `--idor` given without any two-identity source, exit 64:
    "--idor requires --sessions with 2+ entries, or --cookie-alt/--bearer-alt"

Why accept the plan's `--cookie-alt`/`--bearer-alt` when M41's `--sessions`
already exists? Convenience for one-off scans. Writing a JSON file for a
two-cookie probe is friction. Both routes are tested; neither is preferred
over the other in help text.

### D4. Probe mechanism: single A pass + targeted B refetches

The plan says "A vs B differential". Two possible implementations:

**(a) Full double-scan** — run entire payload loop as A, then as B, diff
    observations. Cost: 2× total requests.

**(b) After-scan B refetches** — run normal scan as A (as today), then
    iterate `scanner._observations`, for each URL with an ID-like param,
    refetch as B. Compare A's body to B's body. Cost: 1 extra request per
    interesting URL.

This ADR picks **(b)**. Rationale: bounded cost, no changes to the payload
loop (M41's rotation logic already lives there — do not touch again), and
the probe naturally benefits from M38's `Observation` collection.

Flow inside `Scanner.run_idor(alt_sessions)` called from `cmd_scan`
after the normal scan completes:

```python
def run_idor(self, alt_session_spec):
    # Requires self._observations populated (collect_observations=True)
    # Requires alt_session_spec (B identity)
    idor_urls = _extract_idor_candidate_urls(self._observations)
    candidates = []
    for url, a_observation in idor_urls:
        b_response = _fetch_as(url, alt_session_spec, timeout=self.timeout)
        if _is_idor_candidate(a_observation, b_response):
            candidates.append(CandidateFinding(...))
    return candidates
```

### D5. ID-like parameter detection

A URL is treated as IDOR-testable if it matches *any* of:

1. Path segment is numeric: `/orders/42` — `\\d+`
2. Path segment is UUID-ish: `/users/a1b2c3d4-...` — `\\w{8,}` with hyphens
3. Query param name in a fixed set: `{id, uid, user_id, account_id,
   order_id, resource_id, object_id, doc_id, file_id, invoice_id,
   customer_id, tenant_id}` (case-insensitive)

Rationale: refetching every URL the scan visited would double request
volume for no gain. IDOR is fundamentally about object references; if
there is no object reference in the URL, no cross-identity comparison
makes sense.

### D6. Comparison predicate (v1: deliberately simple)

A candidate fires when ALL of:

1. `a_observation.response_status` is 2xx
2. `b_response.status_code` is 2xx
3. Body similarity between A's and B's response is above a threshold

"Body similarity" v1: exact string match OR length within 5% AND structural
skeleton match (via `recon.admin_struct` if its API fits; otherwise simple
length comparison as fallback, flagged in code comment as v1-limitation).

Deliberately excluded from v1:
- Semantic diffing (B sees A's PII replaced with B's PII) — needs entity
  recognition, out of scope
- Time-based inference (A's response appears in B's response) — false
  positives from common templates
- Blind IDOR (B gets 404 for A's resource but 403 for C's) — needs
  three identities, "C blocked" per plan

### D7. CandidateFinding shape

```python
CandidateFinding(
    param=a_observation.param,
    payload_name="idor",
    payload_value=url,
    category="idor",
    severity="medium",
    finding_type="idor_candidate",
    detail="A and B both received 2xx with similar body on <url>",
    response_status=b_response.status_code,
    response_length=len(b_response.text or ""),
    url=url,
    method=a_observation.method,
    discovery_reason="idor:cross_identity_match",
)
```

`discovery_reason="idor:cross_identity_match"` — parsed by `IdorConfirmer`
(D2) and by `_parse_signals` extension (D8).

### D8. `_parse_signals` extension for `idor:` prefix

Current `_parse_signals` in `cli.py` handles only `heuristic:` prefix.
Extend to also recognize `idor:` and return signals like
`["idor_cross_identity_match"]` (prefix stripped, colon replaced with underscore).

Preserves ADR-019 D3 contract: `properties.signals` carries the
signature/reason IDs, regardless of which Track B variant emitted them.

### D9. Both identities must be non-empty

`--cookie-alt` with no `--cookie` produces A="" B="cookie". That is a
valid probe in theory (anonymous vs authenticated) but not a common IDOR
case. v1 requires both A and B to be authenticated:

```python
if spec_a.cookie is None and spec_a.bearer is None:
    exit 64 "--idor: primary identity is empty"
if spec_b.cookie is None and spec_b.bearer is None:
    exit 64 "--idor: alternate identity is empty"
```

Documented limitation: anonymous-vs-auth IDOR deferred.

### D10. Third identity (C) blocked per plan

If `--sessions` file has 3+ entries, M42 uses `[0]` and `[1]` only.
Third identity is out of scope for M42. This matches FUTURE-STATE-PLAN
line 151 ("C blocked").

### D11. Test scope: ~18 tests across 4 files

- `tests/unit/test_idor_detection.py` — 6 tests: ID-like URL detection,
  comparison predicate, candidate construction
- `tests/unit/test_idor_confirmer.py` — 4 tests: prefix match, registration
  order, unproven emission
- `tests/unit/test_cli_idor.py` — 5 tests: flag combinations, mutual
  exclusion, empty identity rejection
- `tests/integration/test_scanner_idor.py` — 3 tests: end-to-end flow with
  mock sessions, SARIF discovery routing

### D12. README + plan update as M42 delivery

Three doc changes committed with M42 code (not deferred):

1. README line 401: remove "IDOR" from "not implemented" list
2. README line 417: replace with "ships IDOR candidate detection (M42);
   candidates are unproven and require manual triage"
3. FUTURE-STATE-PLAN line 235: `| ADR-023 |` → `| ADR-024 |`

## Consequences

**Positive:**
- README's "not implemented" claim becomes accurate (it ships)
- Reuses M38 (observations), M40 (SARIF discovery), M41 (sessions)
- No changes to scanner's payload loop (M41 already touched it once)
- Additive: `--idor` off = zero behavior change, all 945 unit tests
  and 63 scanner/SARIF integration tests pass byte-for-byte

**Negative:**
- Body-similarity v1 catches obvious IDORs, misses semantic-diff cases
- After-scan B refetches add ~1 request per interesting URL to each
  `--idor` scan. Cost is proportional to how many IDs the target exposes
- The `--cookie-alt`/`--bearer-alt` route duplicates `--sessions`
  functionally. Could be deprecated in a future ADR if unused

**Neutral:**
- M42 scope ~200 lines code + ~250 lines tests + doc updates
- M43 (crAPI validation) can use `--sessions` + `--idor` against crAPI's
  known IDOR endpoints

## Alternatives rejected

**Option A: `heuristic/idor.py`** — rejected. `heuristic/` was created
for signature matching (M37/M38). IDOR is a differential, not a pattern
match. Keeping the packages separate preserves the mental model.

**Option B: reuse `HeuristicConfirmer` for `idor:` prefix** — rejected
(D2). Dual-purpose confirmer couples admission rules.

**Option C: full double-scan (both A and B run the entire payload loop)**
— rejected (D4). 2× requests for marginal additional coverage; after-scan
B refetches are cheaper and simpler.

**Option D: `--cookie-alt`/`--bearer-alt` deprecated in favor of `--sessions`**
— rejected. Plan specified the flags; one-line commands are convenient
for one-off tests. Both routes live.

**Option E: require 3 identities (A/B/C) from the start** — rejected per
plan ("C blocked"). Tri-session is for rotation during a scan; IDOR is
for cross-identity comparison. Different mechanisms, different ADRs.

**Option F: candidate-only, never verified** — this is not rejected,
it is adopted. D7 sets `verification_status="unproven"` via `IdorConfirmer`.
Some IDORs are semantically verifiable but v1 has no semantics.

## References

- FUTURE-STATE-PLAN.md lines 151-152, 235, 249
- README.md lines 401, 417
- ADR-002 — structural DOM hashing (may be reused by D6)
- ADR-007 — finding identity scheme (fingerprint flows through)
- ADR-016 — Verified vs Discovery vocabulary
- ADR-017 / ADR-022 — Track B candidate emission contract
- ADR-019 — SARIF discovery routing (M42 findings appear in runs[1])
- ADR-023 — tri-session auth (`--sessions`, `SessionSpec`)
- src/janissary/detection/ — existing primitives (path for `idor.py`)
- src/janissary/recon/admin_struct.py — structural hashing helper
- src/janissary/engine/scanner.py — `_observations`, `run_heuristic()` as pattern
- src/janissary/verification/confirmers.py — `HeuristicConfirmer` as pattern
