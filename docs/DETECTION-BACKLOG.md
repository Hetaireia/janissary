# Detection Backlog — 2026-11-09

Origin: external bug-bounty feed review (XSS/SSRF payloads, Dalfox v3.3.0 feature comparison). Each candidate was assessed against current Janissary coverage; the items below are the ones that survived. Tier 1/2 are scheduled work. Tier 3 is out-of-scope documentation with revisit triggers.

Not a replacement for docs/ROADMAP.md (strategic) or docs/PHASE-6-PLAN.md (FN registry). This is a concrete, verification-first backlog for detection coverage expansion, which maps to Phase 3 "Discovery Expansion" in docs/FUTURE-STATE-PLAN.md.

## Tier 1 — ready to implement

Differential-provable. Reuses an existing oracle or payload path. No new architecture.

### BL-1 — Redirect-chain SSRF probe — SHIPPED 2026-11-10 (metadata path)

Gap: _ssrf_phase in engine/scanner.py fires on direct SSRF. Does not test whether the target follows a redirect to an internal host. Classic bypass: url= to allowlisted host that 302s to http://169.254.169.254/latest/meta-data/.

Needs: new payload family pointing at a USER-SUPPLIED redirector. CLI flag --ssrf-redirector URL. Payload becomes <redirector>?to=<metadata-endpoint>. Fires when (a) metadata markers appear in the response body, or (b) OOB callback arrives at the Interactsh unique URL. Design constraint: JANISSARY does not host the redirector; the user supplies it. Bug bounty hunters already have this infrastructure. Test cases: benign redirect -> silent; redirect to metadata endpoint -> fires; redirect to Interactsh -> fires (OOB).

Verification: fires on the first, silent on the second.

Refs: ADR-012, ADR-015, scanner.py::_ssrf_phase

### BL-2 — CSTI detection (design corrected 2026-11-10)

Status: design corrected, implementation deferred to fresh session.

Original proposal (rejected): add four CSTI families (double-brace, hash-brace, dollar-brace, ERB angle) to the existing XSS payload list in detection/analyzer.py.

Why rejected: the XSS oracle is reflection-based (analyzer.py:566-605, emits reflected_xss when payload appears unescaped in body). CSTI vulnerabilities EVALUATE the payload — a vulnerable endpoint sending {{1337*1337}} responds with 1787569, not with the literal string. The reflection oracle sees no payload in the body, stays silent, produces a false negative on every CSTI-vulnerable endpoint.

Corrected design: new detection oracle, not payload additions.

New module: src/janissary/detection/csti_oracle.py. Payload families share a distinctive evaluated result: double-brace {{1337*1337}}, hash-brace #{1337*1337}, dollar-brace ${1337*1337}, ERB <%= 1337*1337 %>. All evaluate to 1787569 (seven digits, unlikely to appear naturally).

Oracle logic: check whether the expected result string (1787569) appears in the response body AND the literal payload does not. Fires as category=csti severity=high. Silent otherwise. Reuses ResponseSnapshot and baseline comparison from existing oracles.

Estimated effort: ~120 lines (new oracle ~50, scanner wiring ~20, payloads ~10, tests ~40). Requires an ADR before code per project rule.

Deferred because: paste channel corruption rate this session (~50% of commands) makes a four-file write with a new oracle module unsafe. Implementation in a session with a clean paste channel, proper ADR first, full test coverage before commit.

Verification: test against a Jinja2/Twig/Smarty-backed mock that evaluates the payload to 1787569 - oracle fires. Test against verbatim-reflection mock - oracle silent. Test against evaluating engine that escapes the result - oracle silent (not vulnerable).

Refs: analyzer.py (XSS oracle, for contrast), ResponseSnapshot, ADR-016 (verified/discovery vocabulary)


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


## Tier 1b — minted 2026-11-23 (register D-26..D-30; NOT live WORKFLOW queue)

Promotable to WORKFLOW only via Post-launch Tier 1 rule (WORKFLOW rule 3). Item 0 remains D-7. ADR before code for new oracle/shape (rule 4). Corpus/M89 gate before default-on.

### BL-6 — Traversal encode levels 0–3 + depth pad (D-29)

Status: Open. Does **not** reopen BL-3’s closed decision on overlong UTF-8 / mixed-slash.

Gap: pathtraver recall still target-capped and weak; WAF depth models block naive `../` while equal-level `%252e` / depth padding may pass. Same existence, collapse, LFI oracles — matrix only.

Needs: payload matrix levels 0–3; optional probe-evidence field for encode level; regression on pathtraver-01; M89 delta 0.

Refs: D-29, BL-3 (closed), ADR-027, M37/M83, engine/scanner.py DEFAULT_PAYLOADS

### BL-7 — Path-segment URL-join SSRF + same-host retarget (D-26)

Status: Open.

Gap: classic absolute-URL SSRF and BL-1 redirector path do not cover `../` inside path-shaped segments under a fixed API prefix (Vimeo-class URL join).

Needs: path-shaped param heuristic + climb payloads; confirmer for same-host wrong-route body/schema vs baseline; then optional external hop. ADR before code.

Refs: D-26, ADR-034, _ssrf_phase, check_ssrf_response_oracle

### BL-8 — Redirect-chain / final-host SSRF grading residual (D-27)

Status: Open. BL-1 SHIPPED redirector+metadata path; this is evidence grading residual.

Gap: followed 3xx count, final host class, attacker body markers not fully first-class on the finding after ADR-034 DNS-vs-HTTP split.

Needs: grade fields + tests; DNS-only ceiling P4 preserved; M89 delta 0. ADR-034 amend or ADR-036 if emission shape changes.

Refs: D-27, D-6, ADR-033, ADR-034, BL-1

### BL-9 — Post-verify metadata canary pack default-off (D-28)

Status: Open. Complements shipped BL-1/M13; must not spray metadata on every param.

Gap: escalation after verified HTTP SSRF only.

Needs: flag default off; confirmer; 404 ≠ finding. ADR before code.

Refs: D-28, BL-1, ADR-012, ADR-034

### BL-10 — WAF path-depth probe preference (D-30, with D-8)

Status: Open.

Gap: pacer/WAF profile does not yet prefer depth-safe encodings when negative-depth blocks are inferred.

Needs: preference policy only; promotion still requires D-8 parse proof. Not CSPT.

Refs: D-30, D-8, P1.2 pacer, BL-6

## Tier 3 addendum — 2026-11-23 (never queued)

- **CSPT-as-CLI-class:** out of scope without browser/CDP. Encoding theory may inform BL-6/D-30 only.
- **Browser CSPT / client path sink (enterprise):** open-core future engine; not Apache CLI default.
- **CSRF → markdown/javascript: XSS → GraphQL side effects:** session/playbook; stop at verified XSS in core.


## Tier 2 — verify first

May already be covered. Verification before implementation.

### BL-4 — DOM-XSS coverage — CLOSED 2026-11-10 (architecturally out of scope)

Audit result: engine/dom_hash.py is a pure HTML-string hashing primitive with no I/O and no browser. No JS execution anywhere in the src tree. DOM-XSS cannot be detected by this architecture.

Why: DOM-XSS executes client-side. The payload arrives via URL fragment (location.hash), which HTTP does not transmit to the server. A server-side scanner sees only the server response, never the browser DOM after JS runs. The reflection oracle (analyzer.py:566-605) cannot fire because the payload was never reflected by the server.

What DOM-XSS detection would require: a headless browser (Playwright, Selenium, or pyppeteer) that loads the page, sets the URL fragment, waits for JS execution, and inspects the resulting DOM. This is a fundamentally different scanning mode — browser-based, not HTTP-based. Not in the roadmap. Not scheduled. Not a payload gap.

Comparison: Burp Suite Professional detects DOM-XSS via its embedded browser. ZAP has a separate AJAX Spider. JANISSARY does not compete on this axis, consistent with the roadmap rule that it does not compete on protocol or surface count.

Revisit trigger: roadmap opens a Phase 2.x headless-browser workstream. At that point this becomes a scope entry, not a detection-class entry.


Refs: ADR-002

### BL-5 — OpenAPI / Swagger import — IMPLEMENTED WITH LIMITATIONS

Status: OpenAPI 3.0.x and Swagger 2.0 import, operation dispatch, CLI enumeration, and the per-operation live scan loop are implemented. See [ADR-030](decisions/ADR-030-openapi-import.md) for implementation history, tests, and limitations.

Implemented behaviour:

- Imports supported local-file and URL sources and resolves supported `$ref` references.
- `--openapi` imports the specification; `--dry-run` enumerates the version, imported and skipped operations, and scan targets without constructing a Scanner or making target requests.
- The live scan path builds scan targets and runs a Scanner for each target, then merges the resulting summaries.
- Path, query, header, and cookie parameter locations are dispatched according to the importer implementation. Query parameters use `inject_in="query"`.
- Request-body targets use `inject_in="auto"` with no named parameter list. The endpoint is scanned, but named request-body parameter injection is not implemented because request-body schema capture is not part of the imported operation model.

Known completeness limitation: target-construction and per-target scan exceptions are logged and skipped so the loop can continue. The merged summary does not currently record those skipped runtime failures as an incomplete or aborted scan. A run can therefore return success despite a target failing at runtime. Parser/importer notes and skipped-operation reporting do not close this separate runtime accounting gap.

Validation evidence: 39 targeted OpenAPI tests passed in the reported Windows run. The real-HTTP integration test exercises one OpenAPI 3.0.3 GET operation with a query parameter against a local HTTP server; it is narrow integration evidence, not broad public-API or all-parameter-location coverage.

Postman collection import remains separate and is not included in this implementation.

## Tier 3 — considered, not pursued

Each has a revisit trigger. Not scheduled unless the trigger fires.

T3-1 Multi-step auth flow reasoning (2FA/OAuth bypass, cookie tossing). Out: requires modelling intended auth state machine. Revisit: authenticated multi-step scanning mode exists.

T3-2 Business logic. Out: no baseline for intent. Revisit: never in current architecture.

T3-3 Prompt injection / LLM-specific. Out: wrong product surface. Revisit: separate product.

T3-4 Broad auth-vs-authz confusion. Out: IDOR (M42, ADR-024) covers object-level; broad authz needs role model. Revisit: authenticated mode with role declaration.

T3-5 Verbose API error disclosure as named class. Out: weak signal, not differential. Revisit: user requests as candidate-only class.

T3-6 File-upload XSS. Out: requires upload state machine, scope creep. Revisit: named user needs upload testing.

T3-7 JS exec sink detection (Dalfox feature). Out: requires DOM-XSS path. Revisit: BL-4 delivered.

T3-8 gRPC protocol support (FN-17). Out: greenfield build, no existing implementation. ADR-014 already chose the protobuf dependency and ruled out HTTP-level guessing if reflection is unavailable. Revisit: named user asks for gRPC coverage, or the roadmap opens Phase 2.3. Full scope in docs/PHASE-6-PLAN.md FN-17.

## Cross-references

Strategic roadmap: docs/ROADMAP.md
Finding-gap registry: docs/PHASE-6-PLAN.md
Session tracker: WORKFLOW.md

### BL-1b — SSRF OOB-via-redirect — SHIPPED 2026-11-10

Status: shipped in session, commit pending. Two payloads `ssrf_redirect_oob_http` and `ssrf_redirect_oob_https` added inside `_ssrf_phase`, gated on `--ssrf-redirector`. Four tests in `tests/unit/test_ssrf_redirect_oob.py` verify plumbing. Full suite 1138 passing. Manual end-to-end verification against a live Interactsh and redirecting mock still pending (ADR-029 verification criterion 3).

Original gap text follows.

Gap: ADR-029 described two redirect payload families. `408098d` shipped only metadata-via-redirect (response-body oracle). The OOB family needs the per-probe Interactsh unique ID threaded into the payload value, which the current `(name, value, category, severity)` tuple cannot carry.

Needs: parallel allocation path in `_ssrf_phase`, or tuple change that ripples through `_ssrf_phase` and the body-oracle branch. Three payloads named `ssrf_redirect_oob_http` etc., value = `<redirector>?to=http://{uniq}.{collab}/`. Oracle is the existing collaborator poll.

Verification: mock server 302s to Interactsh unique URL; poll returns a hit; finding emitted.

Refs: ADR-029 (partial implementation note), ADR-012, ADR-015
