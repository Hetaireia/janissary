# Detection Backlog — 2026-11-09

Origin: external bug-bounty feed review (XSS/SSRF payloads, Dalfox v3.3.0 feature comparison). Each candidate was assessed against current Janissary coverage; the items below are the ones that survived. Tier 1/2 are scheduled work. Tier 3 is out-of-scope documentation with revisit triggers.

Not a replacement for docs/ROADMAP.md (strategic) or docs/PHASE-6-PLAN.md (FN registry). This is a concrete, verification-first backlog for detection coverage expansion, which maps to Phase 3 "Discovery Expansion" in docs/FUTURE-STATE-PLAN.md.

## Tier 1 — ready to implement

Differential-provable. Reuses an existing oracle or payload path. No new architecture.

### BL-1 — Redirect-chain SSRF probe

Gap: _ssrf_phase in engine/scanner.py fires on direct SSRF. Does not test whether the target follows a redirect to an internal host. Classic bypass: url= to allowlisted host that 302s to http://169.254.169.254/latest/meta-data/.

Needs: new payload family pointing at a USER-SUPPLIED redirector. CLI flag --ssrf-redirector URL. Payload becomes <redirector>?to=<metadata-endpoint>. Fires when (a) metadata markers appear in the response body, or (b) OOB callback arrives at the Interactsh unique URL. Design constraint: JANISSARY does not host the redirector; the user supplies it. Bug bounty hunters already have this infrastructure. Test cases: benign redirect -> silent; redirect to metadata endpoint -> fires; redirect to Interactsh -> fires (OOB).

Verification: fires on the first, silent on the second.

Refs: ADR-012, ADR-015, scanner.py::_ssrf_phase

### BL-2 — CSTI payload expansion

Gap: XSS oracle fires on reflection. Payload dictionary lacks template syntax.

Needs: add the four standard CSTI families to the XSS payload list in detection/analyzer.py: double-brace, hash-brace, dollar-brace, ERB angle form.

Verification: against a page that evaluates the double-brace form to its numeric answer, oracle fires. Against verbatim reflection, silent.

Refs: existing XSS oracle, detection/analyzer.py

### BL-3 — Path-traversal encoding audit — CLOSED 2026-11-10 (no additions)

Audit complete. Six encoding families checked against scanner.py DEFAULT_PAYLOADS:

| Family | Present | Payload name |
|---|---|---|
| standard | yes | traversal_passwd |
| URL-encoded | yes | traversal_encoded |
| double-encoded | yes | traversal_passwd_dot |
| backslash-encoded | yes | traversal_win_encoded |
| overlong UTF-8 | no | — |
| mixed-slash | no | — |

Decision: do not add the two missing families.

Overlong UTF-8 (%c0%af) is rejected by every modern parser (Tomcat 9+, Jetty, Undertow, ASP.NET Core, Node/Express, Go net/http). The payload is functionally dead against any target JANISSARY would scan today.

Mixed-slash (..\/..\/) has a real bypass case but cannot improve the benchmark score: pathtraver is target-capped (ADR-003), so new payloads cannot raise F1. ADR-027 lines 1720-1721 record that broadening traversal capture caused a documented -1 TP regression on pathtraver-01. Adding payloads risks the same code path for zero benchmark gain.

Roadmap rule applied: do not compete on payload count. Adding to tick a checklist that the benchmark cannot reward is the exact mindset the roadmap forbids.

Revisit trigger: a named user reports a real target where mixed-slash bypass succeeds. At that point, add mixed-slash with a regression check on pathtraver-01 before/after.



Gap: unknown whether the payload dictionary covers overlong UTF-8, double-encoding, mixed slash.

Needs: audit and add missing encodings from: standard, URL-encoded, double-encoded, overlong UTF-8, mixed-slash, backslash.

Verification: dictionary contains all six forms.

Refs: ADR-003, ADR-027

## Tier 2 — verify first

May already be covered. Verification before implementation.

### BL-4 — DOM-XSS coverage

Question: ADR-002 (DOM structural hashing) — does it catch DOM-XSS (payload in location.hash executing via innerHTML), or only reflected XSS?

Verification: send a hash-based img onerror payload to a page with document.body.innerHTML = location.hash. Fires = covered. Silent = gap.

If gap: new payload family in the DOM-XSS path.

Refs: ADR-002

### BL-5 — OpenAPI / Swagger import

Gap: no integrations/openapi.py. Scanner takes a URL or explicit case list.

Needs: parse OpenAPI 2.0/3.0, emit candidate URLs. CLI flag --openapi PATH. Postman collection import as secondary.

Verification: janissary scan --openapi petstore.json -u http://localhost:8080 fires scans against every operation in the spec.

Refs: ADR-021 (related scope), no current OpenAPI ADR. Largest item in this backlog (3-5 days).

## Tier 3 — considered, not pursued

Each has a revisit trigger. Not scheduled unless the trigger fires.

T3-1 Multi-step auth flow reasoning (2FA/OAuth bypass, cookie tossing). Out: requires modelling intended auth state machine. Revisit: authenticated multi-step scanning mode exists.

T3-2 Business logic. Out: no baseline for intent. Revisit: never in current architecture.

T3-3 Prompt injection / LLM-specific. Out: wrong product surface. Revisit: separate product.

T3-4 Broad auth-vs-authz confusion. Out: IDOR (M42, ADR-024) covers object-level; broad authz needs role model. Revisit: authenticated mode with role declaration.

T3-5 Verbose API error disclosure as named class. Out: weak signal, not differential. Revisit: user requests as candidate-only class.

T3-6 File-upload XSS. Out: requires upload state machine, scope creep. Revisit: named user needs upload testing.

T3-7 JS exec sink detection (Dalfox feature). Out: requires DOM-XSS path. Revisit: BL-4 delivered.

## Cross-references

Strategic roadmap: docs/ROADMAP.md
Finding-gap registry: docs/PHASE-6-PLAN.md
Session tracker: WORKFLOW.md

### BL-1b — SSRF OOB-via-redirect — SHIPPED 2026-11-10

Status: shipped in session, commit pending. Two payloads `ssrf_redirect_oob_http` and `ssrf_redirect_oob_https` added inside `_ssrf_phase`, gated on `--ssrf-redirector`. Four tests in `tests/unit/test_ssrf_redirect_oob.py` verify plumbing. Full suite 1138 passing. Manual end-to-end verification against a live Interactsh and redirecting mock still pending (ADR-028 verification criterion 3).

Original gap text follows.

Gap: ADR-028 described two redirect payload families. `408098d` shipped only metadata-via-redirect (response-body oracle). The OOB family needs the per-probe Interactsh unique ID threaded into the payload value, which the current `(name, value, category, severity)` tuple cannot carry.

Needs: parallel allocation path in `_ssrf_phase`, or tuple change that ripples through `_ssrf_phase` and the body-oracle branch. Three payloads named `ssrf_redirect_oob_http` etc., value = `<redirector>?to=http://{uniq}.{collab}/`. Oracle is the existing collaborator poll.

Verification: mock server 302s to Interactsh unique URL; poll returns a hit; finding emitted.

Refs: ADR-028 (partial implementation note), ADR-012, ADR-015

