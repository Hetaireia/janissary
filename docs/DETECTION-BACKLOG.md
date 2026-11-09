# Detection Backlog — 2026-11-09

Origin: external bug-bounty feed review (XSS/SSRF payloads, Dalfox v3.3.0 feature comparison). Each candidate was assessed against current Janissary coverage; the items below are the ones that survived. Tier 1/2 are scheduled work. Tier 3 is out-of-scope documentation with revisit triggers.

Not a replacement for docs/ROADMAP.md (strategic) or docs/PHASE-6-PLAN.md (FN registry). This is a concrete, verification-first backlog for detection coverage expansion, which maps to Phase 3 "Discovery Expansion" in docs/FUTURE-STATE-PLAN.md.

## Tier 1 — ready to implement

Differential-provable. Reuses an existing oracle or payload path. No new architecture.

### BL-1 — Redirect-chain SSRF probe

Gap: _ssrf_phase in engine/scanner.py fires on direct SSRF. Does not test whether the target follows a redirect to an internal host. Classic bypass: url= to allowlisted host that 302s to http://169.254.169.254/latest/meta-data/.

Needs: second probe that sends a redirecting URL. Two test apps: one 302s to internal IP, one 302s to benign host.

Verification: fires on the first, silent on the second.

Refs: ADR-012, ADR-015, scanner.py::_ssrf_phase

### BL-2 — CSTI payload expansion

Gap: XSS oracle fires on reflection. Payload dictionary lacks template syntax.

Needs: add the four standard CSTI families to the XSS payload list in detection/analyzer.py: double-brace, hash-brace, dollar-brace, ERB angle form.

Verification: against a page that evaluates the double-brace form to its numeric answer, oracle fires. Against verbatim reflection, silent.

Refs: existing XSS oracle, detection/analyzer.py

### BL-3 — Path-traversal encoding audit

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
