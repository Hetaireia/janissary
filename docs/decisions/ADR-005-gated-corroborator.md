# ADR-005 — Gated corroborator (Phase 1.3c)

**Status:** Accepted (2026-10-25). Amended 2026-10-25 post-G2.
**Depends on:** ADR-002, ADR-004
**Blocks:** 1.3c, 1.3d, 1.3e

## Context

1.3c targets Issue #1 (39 SPA catch-all FPs). G2 (2026-10-25) established
they originate in `recon/admin.py:probe_admin`, not `scanner.py`'s payload
loop. D1 and D3 re-scope accordingly. `baseline_struct` (1.3b) is not
consumed by 1.3c; its payload-loop application is deferred to 1.3d.

## Decisions

### D1. Scope
The FPs are admin-path hits emitted when a registered admin path returns
`200` with HTML whose structure matches the target root. Discard when ALL
of: status 200; content type `text/html`;
`hamming(fingerprint(body), fingerprint(root_body)) <= 3`;
`sha256(normalize_body(body)[:4096]) == sha256(normalize_body(root_body)[:4096])`.
Root = first successful 200 response to the target itself. If root fetch
fails or is non-HTML, the filter is disabled (pass-through). Payload-loop
FPs are out of 1.3c scope; `scanner.py` and `CORROBORATOR_ONLY_TYPES` are
untouched.

### D2. Root signature
Exact SHA-256 equality. No tolerance.

### D3. Integration
In `recon/admin.py:probe_admin`, after candidate hit classification and
before appending to the profile's hits list. Helper
`should_discard_admin_hit` (pure) takes the candidate response plus root
fingerprint and signature. Suppression: excluded from hits, DEBUG per D6,
counts per D4. `DifferentialAnalyzer`, `Baseline`, `Scanner.scan`
unmodified.

### D4. Observability schema
The profile object returned by `probe_admin` gains an additive `arming`
attribute: `{enabled, reason, discarded_count, discarded_by_reason}`.
Reason is `disabled_no_root` | `disabled_no_html_root` | `enabled`.
Existing `to_dict()` keys unchanged. `ScanSummary.baselines[param]`
unchanged by 1.3c.

### D5. Disabled filter = pass-through
When disabled, output field-equal to pre-1.3c except for the additive
`arming` attribute with `enabled: False`: same hits list (order and
fields), same paths_probed, same requests issued. Enforced by a diff test
against a pre-1.3c reference profile minus `arming`.

### D6. Discard observability
DEBUG per suppressed hit (path, platform, hamming, signature match).
Aggregate `discarded_count` and `discarded_by_reason`. One reason tag:
`spa_catchall_admin`. At most one INFO end-of-probe when verbose.

### D7. Reproducing the 39 — RESOLVED
G2 confirmed origin: `test_custom_paths_override_defaults` fires a hit on
`200 + GENERIC_HTML`. The 39 are admin-path hits on an SPA target.
Synthetic fixture in `tests/unit/test_admin.py` (fake SPA returns 200 +
index HTML on every admin path) and in `tests/integration/` (suppression
on fake routes; emission on real vulnerable pages). Manual 39-to-0 stays
deferred — no in-repo artifact for the original target.

### D8. Emit-path
Discard only. No distance>20, no traversal/WAF-collapse, no pathtraver
oracle changes. 1.3d owns emit.

### D9. Acceptance
Primary: `--min-f1 0.92 --max-fp 0` on r1+rec. Additionally: fresh 3-run
before merge; fresh mean F1 at least 0.903; no TP loss vs pre-1.3c;
synthetic SPA tests mandatory; manual 39-to-0 deferred per D7. Precision
wins ties.

## Consequences
1.3c modifies `recon/admin.py`, adds `should_discard_admin_hit` (inline or
a new `recon/admin_struct.py`), extends the profile with `arming`. Tests:
unit truth table, synthetic SPA, D5 pass-through. `baseline_struct` (1.3b)
is not consumed by 1.3c; deferred to 1.3d where the payload-loop emit
path needs it. Fresh 3-run before merge — first phase where the F1 rule
is active.

## References
ADR-002 §Integration point / §Combined signal / §Success criteria;
ADR-004 D1-D6; handover §11.1-§11.8; `tests/unit/test_admin.py`;
`tests/unit/test_scanner_baseline.py`; `tests/integration/test_scanner.py`.
