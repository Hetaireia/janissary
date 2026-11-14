# JANISSARY — Milestone Register

**Established:** 2026-11-14
**Supersedes:** the milestone-tracking role previously served by the local-only `JANISSARY-ASCENSION.md` and the local-only dashboard. Those remain historical artefacts; neither is authoritative.

## 1. Authority and governance

**Primary technical authority:** committed source, tests and ADRs. A milestone is not delivered because a document says so; it is delivered when source and tests demonstrate it.

**This register's role:** record milestone identity, status, dependencies and evidence — with provenance stated. It does not override source, tests, or ADRs; it points to them.

**Precedence when this register and other documents conflict:**

1. Committed source, tests, ADRs
2. This register
3. Committed documentation (`docs/`, `README.md`, `LIMITATIONS.md`)
4. Local-only documents (`JANISSARY-ASCENSION.md`, `JANISSARY_ASCENSION.md`, `docs/ROADMAP.md`, `docs/FUTURE-STATE-PLAN.md`, dashboard)
5. Historical AI conversation references

**Status provenance:** every status value in this register names its source. Where the source is the dashboard and the audit did not re-verify, this is stated. Status without provenance is not a valid register entry.

**Change control:**

- A status change requires a commit whose message names the evidence (source path, test reference, ADR, or a new audit finding).
- A status change whose evidence is contested is not automatically reverted. It is flagged in the register with the nature of the dispute, the reason, and the resolution path. The original status, the disputed change, and the correction are all preserved in the file's Git history; the register text states what the dispute was and how it was resolved, so a reader encountering only the current file understands why the status reads as it does.
- A status change without stated evidence is treated as a correction request: the entry is flagged in the register as `evidence-pending`, not reverted. The change to `evidence-pending` is itself recorded with the reason. If evidence is later supplied, the entry returns to its prior status with the evidence recorded; if evidence is not supplied, the entry remains `evidence-pending` and the absence is visible.
- Historical milestone identities are preserved (§8) and not reused for new milestones.
- Adding a milestone requires an approved scope.

## 2. Status definitions

| Status | Definition |
|---|---|
| `verified-delivered` | Committed source and tests demonstrate the milestone's stated acceptance criteria. Evidence path cited. |
| `verified-policy` | Milestone's scope is a decision or policy, not an implementation. Decision recorded in an ADR. |
| `verified-partial` | Committed source demonstrates some of the milestone's scope; specific gap named. |
| `no-implementation-identified` | A bounded audit inspection found no source or test artefact matching the milestone's stated capability. This is a **bounded finding**, not proof that no equivalent functionality exists elsewhere. The inspection boundaries (paths searched, patterns used, whether the search was content-level or filename-level) are recorded per milestone. Related functionality that was found is named. |
| `scoped` | Scope and acceptance criteria approved. Implementation design may be documented; implementation itself not yet started. A `scoped` milestone has passed its scope gate but has not entered Gate E. |
| `claimed-delivered` | Dashboard claims delivery. Audit did not re-verify. Claim recorded with provenance. |
| `claimed-pending` | Dashboard claims pending. Audit did not re-verify. Claim recorded with provenance. |
| `proposed-unapproved` | Proposed milestone, not approved. Not authorized for scoping or implementation. |
| `evidence-pending` | A status change was proposed without stated evidence. The prior status and the proposed status are both recorded; the entry awaits evidence or withdrawal. Not an accusation — a bookkeeping state. |

## 3. Verified-policy decisions

Policy and decision milestones are recorded separately from implementation milestones. They record what JANISSARY decided, not what it built.

| ID | Name | Evidence |
|---|---|---|
| M12 | ADR-014: gRPC/Protobuf dependency policy | `docs/decisions/ADR-014-grpc-protobuf-dependency.md:3` — Accepted 2026-11-03, Option 1 (`grpcio` + `google.protobuf`). ADR text explicitly states "`pyproject.toml` is unchanged by acceptance" and "Does not commit to implementing FN-17." Confirmed by audit: no `grpcio` or `google.protobuf` in `pyproject.toml`. The policy is recorded and unenacted. The 2026-11-14 bounded audit inspection identified no gRPC-specific source or test files for M39/M90; see §5.2. |

## 4. Verified-delivered implementation milestones

### 4.1 Delivered with full contract conformance

| ID | Name | Evidence |
|---|---|---|
| M82a | Heuristic multi-signal aggregation model | `src/janissary/heuristic/engine.py:43` — `MatchGroup` frozen dataclass with `signature_ids`, `categories`, `confidences`, `payload_families` as `frozenset`; `matches` tuple; `contributing_observation_ids`; `first/last_observation_index` and corresponding `_id` fields. Docstring lines 60–67 explicitly state first/last IDs are by index, not lexicographic. `:224` `aggregate()` method. Tests: `tests/unit/test_heuristic_engine.py:191-404`. |
| M82b | Candidate integration for aggregation | `src/janissary/heuristic/engine.py:224` `aggregate()`. Dedicated tests in `tests/unit/test_heuristic_candidate_aggregation.py`, including `test_aggregate_deterministic_regardless_match_order` (line 322, body through ~349) and the surrounding aggregation test body. The dedicated test file exercises the full candidate-integration path that consumes `aggregate()` output. |

### 4.2 M82a/M82b test-coverage observations (recorded, not defects, not reopened)

These are recorded for the historical record. No implementation work is implied by them.

- `test_aggregate_sorted_by_first_observation_index` supplies matches in observation order; it does not exercise reversed bucket insertion order.
- `test_aggregate_deterministic_regardless_match_order` (line 322, body through ~349) reverses two matches and asserts candidate count, signature ID, and category. It does not assert `matches` tuple order, `contributing_observation_ids` ordering, `payload_families`, `confidences`, or `first/last_observation_id` stability across input order.
- `MatchGroup.matches` retains input match order by design; not asserted by tests.

These are test-coverage observations. The implementation conforms to the milestone contract. M82a and M82b remain delivered.

### 4.3 Claimed delivered per dashboard, not audit-verified

The following milestones appear as delivered in the local dashboard (`renders/dashboard-refined.html`, ignored/untracked). The 2026-11-14 audit did not re-verify them. They are recorded as claims with provenance, not as verified fact.

- **M1–M11, M13–M15, M17–M23, M25–M32, M35–M36, M38, M61–M71, M73–M81** (~50 milestones)

Source: local dashboard. Independent verification of each not established by the 2026-11-14 audit.

## 5. Active and incomplete milestones

### 5.1 Verified partial

| ID | Name | Present | Gap |
|---|---|---|---|
| M37 | Path traversal recall improvement | Payload families present in `DEFAULT_PAYLOADS` (`src/janissary/engine/scanner.py:73`): plain, encoded, deep, absolute, Windows, double-dot, double-encoded variants. `detection/analyzer.py:784` `check_pathtraver_oracle`; `detection/collapse_oracle.py:108` `check_traversal_collapse`; SARIF rules at `sarif_rules.py:110-121`. Test: `tests/unit/test_pathtraver_oracle.py`. | Measured effectiveness against a documented corpus not established by the audit. The figure 0.075 reported for path-traversal recall is sourced from `docs/quality/REMEDIATION-REGISTER.md` L04a, which cites `docs/pathtraver.md:57` and artefact `run-1-recovery-score.txt`; **the artefact was not independently re-verified in the 2026-11-14 audit**. The figure is recorded as a reported baseline, not as an independently established measurement. |
| M76 | Evidence contracts | Failed-verification retention behaviour exists: `tests/unit/test_verification_engine.py:110` (`test_failed_verification_*`), `:221` (`test_rejected_still_*`). These demonstrate that failed-verification evidence is not silently dropped today. | No named contract module; no `failed_verification` or `evidence_contract` symbol in `src/`. Formalization of the existing behaviour into a named contract and expansion of the test suite are the gap. |
| M84 | OpenAPI request-body schema injection | `src/janissary/importers/dispatch.py:23,27,81` — `BODY_LIMITATION_NOTE` documented and emitted as a parser note. The note records why body injection by name is limited. | Body injection by name not implemented. |

### 5.2 No implementation identified

Each entry below records a **bounded finding**, not proof that no equivalent functionality exists. The inspection boundaries are stated. Related functionality that was found during the same inspection is named.

| ID | Name | Inspection performed | Related functionality found |
|---|---|---|---|
| M39 | gRPC integration (end-to-end) | Filename enumeration in `src/` and `tests/` for files matching `grpc\|proto`. No `src/` file matched. `tests/` returned only `test_protocols_graphql.py`, `test_protocols_http.py`, `test_protocols_websocket.py`, `test_protocols_wiring.py` — these matched the substring `proto` in "protocols", not gRPC. No `test_grpc.py` exists. | ADR-014 records the dependency policy (§3). No gRPC-specific source or test files were identified by the recorded filename inspection. The audit did not establish whether equivalent functionality exists under differently named files. |
| M85 | OpenAPI live-scan hardening | Content search in `src/` for `live_scan\|openapi_live\|scan_hardening` — no matches. **Tests were not searched in the 2026-11-14 audit for this milestone.** | OpenAPI import and dispatch machinery exists (`importers/dispatch.py`, `importers/openapi.py`), per earlier session work (ADR-030 Stages 2–6). Whether live-scan hardening can reuse or extend it is untested in this audit pass. |
| M86 | Scan coverage ledger | Content search in `src/` for `coverage_ledger\|scan_coverage\|skipped_reason\|coverage_report` — no matches. Content search in `tests/` for `coverage_ledger\|scan_coverage\|skipped_reason` — no matches. | Scan-completeness reporting exists (`_scan_completeness` at `cli.py:55-73`; SARIF wiring at `cli.py:1841`; tests in `tests/unit/test_scan_completeness.py`). The coverage ledger is a broader concept — what was attempted, skipped, unsupported — distinct from the completeness block, which reports four tracked scan-level conditions. |
| M87 | AuthStateManager | Content search in `src/` for `AuthStateManager\|class AuthState\|def reauth\|oauth2_refresh\|OAuth2Refresh` — no matches. Content search in `tests/` for `AuthStateManager\|M87\|def test.*reauth\|mock.*idp` — one match, a docstring mention at `tests/unit/test_auth_state.py:3` describing what does *not* exist yet. | Structured `auth_state` reporting exists (`dc09b70`, `e96f31c`; `ScanSummary.auth_state` with values `unknown`, `authenticated`, `unauthenticated`, `expired`, `recovery_failed`). SARIF carries `auth_state` at `properties.auth_state` (`1c8aaa8`). No manager for reauthentication during a scan when a session expires was identified by the recorded bounded searches. Session primitives exist (`auth.py` `SessionSpec`; tri-session auth shipped as M18 per dashboard). |
| M88 | Resumable scanning | Content search in `src/` for `checkpoint\|resumable\|scan_state\|resume_from` — no matches. Content search in `tests/` for `checkpoint\|resumable\|M88` — no matches. | None identified. No checkpoint or resume implementation was identified by the recorded content searches. The audit did not establish whether equivalent functionality exists under different names or mechanisms. |
| M89 | FP regression corpus | Directory inspection of `tests/regression/` — one file: `test_juice_shop_precision.py`, one test: `test_missed_sqli_reported_not_silently_dropped`. This was **direct directory inspection**, more conclusive than pattern search. Additional pattern search for `fixture\|corpus\|fp\|false.positive` directories in `tests/` returned only the general-purpose `tests/fixtures/` directory (used for OpenAPI specs and other test data, not an FP corpus). | The single juice-shop precision test provides one specific precision assertion. No SPA-catch-all, WAF-challenge, public-resource, or auth-redirect fixtures were identified in the inspected regression suite. |
| M90 | gRPC protocol adapter | Same inspection as M39. | Same as M39 — ADR-014 policy exists; no gRPC-specific source or test files were identified by the recorded filename inspection. The audit did not establish whether equivalent functionality exists under differently named files. |

**Inspection-scope caveat for the entire table:** these findings are bounded by the patterns and paths searched. A capability implemented under a name that does not contain any of the search terms, in a file whose name does not contain any of the search terms, would not have been detected. The audit does not claim exhaustive source review — it claims targeted inspection with the boundaries stated above.

### 5.3 Claimed pending per dashboard, not audit-verified

- **M16, M24, M33, M34, M40, M41–M60, M72** (~26 milestones)

Source: local dashboard. Audit did not re-verify.

### 5.4 Scoped — implementation not yet started

A milestone that has passed its scope gate but has not entered implementation. The design is approved; no source code has been written.

| ID | Name | Scope | Design | Evidence |
|---|---|---|---|---|
| M83 | Traversal observability harness | `docs/m83_scope.md` | Gate D and Gate D.1 approved 2026-11-14 (documented in `docs/m83_gate_d_proposal.md`) | **Original 2026-11-14 audit finding** (recorded in §5.2 at commit `72f1161`): bounded content searches in `src/` for `case_records`, `TraversalRecord`, `observability_harness`, `M83`, and in `tests/` for `case_records`, `TraversalRecord`, `observability`, `M83` returned no matches. The traversal oracle exists (`check_pathtraver_oracle` at `analyzer.py:784`; `check_traversal_collapse` at `collapse_oracle.py:108`). The harness was not implemented at the time of the audit. **Subsequent status:** M83 passed Gate D and Gate D.1 on 2026-11-14; design is documented; implementation not started. Gate E must first inspect scanner control flow at `scanner.py:2125` to establish observation call count per subprocess (proposal §13). |

## 6. Proposed milestones (M91–M99)

**All nine are proposed and unapproved.** No scope, acceptance criteria, or implementation is authorized. None is included in the M1–M90 baseline; their addition is a denominator change only.

Each entry records existing infrastructure that a future scope would need to reckon with. **Existing infrastructure is not approval.** A milestone with substantial existing code still requires its own scope, acceptance criteria, test plan, and implementation approval before work begins.

| ID | Name | Existing infrastructure (not approval) |
|---|---|---|
| M91 | GraphQL Authorization & Security Assessment | `src/janissary/integrations/graphql.py` provides discovery and fuzzing primitives: `build_nested_query`, `build_alias_query`, `build_argument_query`, `depth_probe`, `alias_probe`, `enumerate_fields`, `fuzz_arguments`, `detect`, `resolve_endpoint`, and the `GraphQLClient` class. No identity or role comparison functions or cross-user access tests were identified in the inspected GraphQL integration and associated test evidence. GraphQL integration was shipped as M9; M91 is authorization assessment, a distinct capability. |
| M92 | AI Agent & Tool Security Assessment | **No agent or tool assessment capability was identified in the bounded source inspection.** The only relevant code is in `src/janissary/credentials/rules.py:190-316` — these are *credential-pattern detection rules* for Anthropic API keys. They scan for leaked credential strings; they do not assess agent tool permissions, tool invocation, or trust-boundary behaviour. Credential-pattern detection is categorically distinct from AI agent/tool security assessment. |
| M93 | OAuth/OIDC Authentication & Token Trust Assessment | **No OAuth/OIDC assessment capability was identified in the bounded source inspection.** The only relevant code is in `src/janissary/credentials/rules.py:66-67` — a *credential-pattern detection rule* for GitHub OAuth tokens. It scans for leaked token strings; it does not assess OAuth flows, redirect validation, code binding, PKCE, state, token audience, issuer, or cross-service acceptance. Credential-pattern detection is categorically distinct from OAuth/OIDC security assessment. |
| M94 | CSRF Enforcement & State-Changing Request Verification | `src/janissary/detection/analyzer.py:27-40` — `_CSRF_TOKEN_RE` extracts CSRF tokens for auth-replay. `src/janissary/finding_identity.py:38-40` — csrf/csrftoken as session-equivalent keys. Both support replay, not CSRF enforcement testing. No state-change verification, missing-token test, or invalid-token test was identified in the inspected source and test evidence. |
| M95 | Business-Logic Race Condition Assessment | **No business-logic race-testing capability was identified by the bounded source inspection.** Searches covered `ThreadPool`, `concurrent.futures`, `asyncio.gather`, and `httpx.Async` in `src/`. This does not establish that concurrency cannot be implemented using other mechanisms. `pyproject.toml` carries `requests>=2.31`, a synchronous HTTP client. Whether threaded `requests` suffices for a bounded first implementation is a design question, not a settled dependency. |
| M96 | HTTP/2 Multiplexing & Synchronized Race Testing | **No HTTP/2 implementation or dependency was identified by the bounded source inspection.** `pyproject.toml` carries only `requests>=2.31`; no `httpx`, `aiohttp`, or `h2` dependency. This does not establish that HTTP/2 support cannot be added. HTTP/2 multiplexing would require a new transport dependency. Relationship to M95 is unverified pending M95 scope or design investigation. |
| M97 | XSS Parser Differential & Context-Aware Payload Assessment | `src/janissary/detection/analyzer.py:570-632` — reflected XSS detection with `_is_inert_context` helper; `sarif_rules.py:141` reflected-XSS SARIF rules. Reflection detection with some context awareness; not a systematic parser differential. |
| M98 | DOM-Based XSS Source-to-Sink Analysis | **No browser automation capability was identified by the bounded source inspection.** The sole `playwright` reference is `src/janissary/credentials/scanner.py:138`, which detects Playwright report files as credential-leak targets — a scanner credential-scanning concern, not a browser automation capability. Relationship to M97 is unverified pending M97 scope or design investigation. |
| M99 | SAML Federation & Assertion Security Assessment | **No SAML implementation was identified in the bounded source inspection.** The search covered `saml`, `SAML`, `saml2`, and `SAMLResponse` in `src/`. XML parsing is available via `defusedxml` (existing dependency); XML *signature* validation is a distinct concern from XML parsing safety and is not established. |

## 7. Dependency register

| Relationship | Classification | Basis |
|---|---|---|
| M90 → M39 | Hard | M39's scope requires the adapter as a constituent component. M39 is end-to-end integration on top of M90's focused adapter component. |
| M83 → M37 measured acceptance | Recommended / acceptance prerequisite | M37 payload development can proceed independently. M37's measured-recall acceptance criterion requires a documented measurement harness, which is M83. |
| M76 → M83, M91, M93, M94, M99 | Recommended | Evidence-contract formalization improves consistency. Existing evidence retention already present (`test_verification_engine.py:110,221`). No acceptance criterion in a dependent milestone names M76 as a requirement. |
| M86 → M91, M93, M94, M99 | Recommended | Coverage accounting improves reporting. Not a capability prerequisite; no acceptance criterion names it. |
| M89 → M37, M91, M97 | Recommended | Regression protection. Not an implementation prerequisite; no acceptance criterion names it. |
| M87 → M93, M94, M99 | **Independent (verified 2026-11-14)** | Bounded inspection confirmed: `SessionSpec` (`auth.py:28`) and `SessionRotator` (`engine/session_rotator.py`, consumed at `scanner.py:655`) provide sequential 401-triggered rotation. `--alt-cookie`/`--alt-bearer` (`auth.py:123,132`) provide a two-identity mechanism for the `--idor` cross-identity probe (M42). M87 (`AuthStateManager` for reauth-during-scan) is orthogonal to both: it addresses session *expiry*, not cross-identity comparison. Whether the existing alt-identity mechanism generalizes to M93/M94/M99's cross-identity scope is a per-milestone scoping question, not an M87 prerequisite. Note: `--sessions-file` (rotation) is mutually exclusive with the primary `--cookie`/`--bearer` auth flags (`tests/unit/test_cli_sessions.py:22,29`); whether `--alt-cookie`/`--alt-bearer` can combine with `--sessions-file` is untested in the inspected evidence, so a milestone requiring both would need to verify or reconcile this at scope time. |
| M95 → M96 | Unverified | This relationship was asserted in the audit's action sequence and has been corrected to unverified. May be confirmed by M95 scope evidence or the concurrency design investigation. |
| M97 → M98 | Unverified | Same as M95 → M96. The two XSS-related milestones address distinct concerns (parser differential vs DOM source-to-sink) and may proceed in either order. |

**Design investigations (research, not ADRs, not implementation, not approved):**

Three proposed design investigations are recorded for future consideration. Their relationship to milestone sequencing and acceptance criteria must be established during the relevant scope approvals. They are not prerequisites by virtue of being listed; they are research questions that the relevant milestone scopes will determine whether to require.

- **Concurrency approach** for M95 (and any M96 relevance). Whether threaded `requests` suffices for a bounded first implementation.
- **Browser automation** for M98. Tooling choice and execution boundary.
- **XML signature validation** for M99. Whether `defusedxml` covers the need, or an additional library is required.

## 8. Historical identity notes

### 8.1 M36a–M48 (November 4 plan) versus current M37–M48

`docs/FUTURE-STATE-PLAN.md:238-260` maps M36a–M48 to an earlier work programme:

- M36a: ADR series 016–021
- M37–M40: heuristic engine and discovery formalization
- M41–M43.5: tri-session authentication and IDOR
- M44–M45: crawler
- M46–M48: local triage UI

Current M37 refers to *path traversal recall improvement*, M83 to *traversal observability harness*, M87 to *AuthStateManager*, M89 to *FP regression corpus*. The identifiers do not carry continuous meaning across documents.

**Rule:** any claimed continuity between a milestone ID in a historical document and a milestone ID in this register requires tracing the governing scope and implementation evidence. Shared ID is not shared meaning.

### 8.2 M82a/M82b supersedes Master Roadmap §2.3 and Part 5 Priority 1

The Master Roadmap (a conversation reference, not a tracked repository file) contains stale pre-delivery language that this register supersedes:

| Master Roadmap text | Treatment in this register |
|---|---|
| §2.3: "The M82a scope has been prepared for review. Do not assume that a draft scope is approved." | Superseded by §4.1 — M82a/M82b delivered, evidence cited. No scope remains to approve. |
| §2.3: "Do not change the **approved** M82a scope without explaining why and obtaining approval." | Superseded — internally inconsistent with the preceding sentence. §4.1 records the evidence-based delivery. |
| Part 5 Priority 1: "M82a MatchGroup model \| High \| Scope approval and provenance verification" | Superseded by §4.1 and §8.2 — the "scope approval" work item is retired; provenance verification is recorded in §4.1 with its test-coverage observations. |

The Master Roadmap, being a conversation reference, carries no further authority on M82. This register is the durable supersession.

## 9. Evidence and change history

**Evidence requirement per entry:** source path with line, test file with line, or ADR path with section. Where evidence is a dashboard claim only, provenance is stated. Where evidence is a bounded inspection (as in §5.2), the boundaries of the inspection are stated.

**Change log:** every status change requires a commit whose message names the evidence. A status change whose evidence is contested is not silently reverted — it is flagged with the reason, and the resolution is recorded (§1).

**Initial status baseline:** the 2026-11-14 audit. Its findings are the evidence for §3, §4.1, §4.2, §5.1, §5.2, and the infrastructure notes in §6.

**Audit traceability:** the 2026-11-14 audit's consolidated report lives in project conversation. This register is the durable record of the audit's findings; the audit itself remains conversational. Where the register cites a finding, the finding's basis is in this register's evidence column, not only in the conversation.

**Local-only documents:** the four local documents (`JANISSARY-ASCENSION.md`, `JANISSARY_ASCENSION.md`, `docs/ROADMAP.md`, `docs/FUTURE-STATE-PLAN.md`) are retained unchanged and are not promoted to authority by this register. The retired `tools/ascension.py` and `tools/ascension_state.json` pipeline must not be restored.