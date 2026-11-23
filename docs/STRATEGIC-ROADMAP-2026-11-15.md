# JANISSARY Strategic Remediation Roadmap

**Date:** 15 November 2026
**Status:** Strategic planning document — implementation sequencing and acceptance framework
**Repository baseline:** `1e66512`
**Documentation reconciliation:** 24 November 2026.
**Branch:** `main`
**Purpose:** Establish an evidence-led, strategically ordered remediation programme for JANISSARY, prioritising measurement integrity, detection quality, authentication reliability, and verification confidence.

---

## 1. Executive strategy

JANISSARY's next development cycle should be organised around one governing principle:

> **Measure first, improve second, prove improvement third.**

The project should not optimise detectors against an unverified baseline, treat increased finding counts as proof of better detection, or declare a milestone complete merely because related code exists.

The immediate objective is to establish reliable measurement and regression evidence, then use that evidence to guide targeted improvements to detection and scan reliability.

The programme prioritises:

1. Establishing a trustworthy path-traversal measurement pipeline (M83).
2. Building a realistic false-positive regression corpus (M89).
3. Improving path-traversal detection using measured evidence (M37).
4. Completing authentication-state management and recovery (M87).
5. Improving SSRF out-of-band evidence attribution (L05).
6. Strengthening IDOR evidence and triage (M42).
7. Establishing reproducible SQL injection measurement (L03).
8. Improving SQL injection delivery only where measurement demonstrates a real delivery limitation.
9. Strengthening cross-cutting evidence and scan-completeness contracts (M76 and M86).

This is a dependency-aware sequence, not permission to implement every item immediately. Each stage must establish its evidence, pass its acceptance criteria, and remain within its approved scope before the next stage proceeds.

### 1.1 Strategic outcomes

The programme should produce the following outcomes:

- Reproducible benchmark results with case-level provenance.
- Clear separation between confirmed findings, candidates, inconclusive results, and failures.
- Measurable precision, recall, and F1 performance.
- Regression tests that prevent known false-positive behaviour from returning.
- Authentication-state reporting that accurately represents scan reliability.
- Reliable attribution of out-of-band evidence to the originating test case.
- Reproducible SQL injection measurements before detector or payload changes.
- Explicit scan coverage and verification completeness.
- Milestone status claims supported by source, tests, ADRs, and reproducible evidence.

### 1.2 Operating model

Every work package follows the same cycle:

1. Inspect the current implementation and its design authority.
2. Establish the actual baseline.
3. Identify the specific unresolved behaviour.
4. Define bounded implementation scope.
5. Implement only the approved changes.
6. Run targeted tests.
7. Run relevant regression tests.
8. Run broader verification where required.
9. Record evidence, limitations, and residual risks.
10. Reconcile milestone status against the actual result.

A stage is not complete merely because its implementation exists. It is complete when its acceptance conditions have been demonstrated.

---

## 2. Repository authority and milestone reconciliation

Before implementation sequencing can be trusted, the project must distinguish registered milestones, proposed milestones, local dashboard entries, and historical planning material.

### 2.1 Source-of-truth hierarchy

Use the following precedence when determining project state:

1. Committed source code, tests, and Architecture Decision Records.
2. `docs/MILESTONE-REGISTER.md`.
3. Other committed project documentation.
4. Local-only documentation and dashboard material.
5. Conversation history and informal planning notes.

The milestone register is the tracked authority for milestone identity, status, dependencies, and supporting evidence. Source code, tests, and ADRs establish whether the claimed implementation or design actually exists.

A dashboard or planning document cannot independently establish milestone approval or delivery.

### 2.2 Dashboard and milestone-count reconciliation

The local `renders/dashboard-refined.html` has been inspected and contains:

- 108 unique sequential milestone identifiers, M1–M108.
- No gaps in that displayed identifier sequence.
- 54 completed ticks.

This does **not** mean that 108 milestones have been approved or registered.

The tracked milestone register establishes:

- M1–M90 as the existing registered milestone range.
- M91–M99 as proposed and unapproved.
- M100–M108 as additional dashboard entries requiring reconciliation against formal approval and scope records.

The correct distinction is:

| Item | Current interpretation |
|---|---|
| Dashboard rows | 108 displayed identifiers |
| Registered milestone range | M1–M90 |
| Proposed milestones | M91–M99, unapproved |
| Additional dashboard entries | M100–M108, approval and registration not established |
| Dashboard completed ticks | 54 displayed ticks; not independent proof of delivery |

Do not silently promote M91–M99 or M100–M108 into the approved milestone register.

Do not change dashboard completion ticks, milestone denominators, or dates merely to make the dashboard appear consistent.

Any reconciliation must establish the identity, approval authority, scope, dependencies, and evidence for each additional entry.

### 2.3 Milestone identity corrections

Preserve these milestone identities when interpreting historical documentation and planning material:

- **M19:** HTML and PDF reporting.
- **M42:** IDOR candidate detection.
- **M37:** Path-traversal detection and recall improvement.
- **M83:** Path-traversal observability and measurement harness.
- **M87:** AuthStateManager and authentication-state management.
- **M89:** False-positive regression corpus.

M42 and M19 are distinct. Historical references must not conflate IDOR detection with reporting.

### 2.4 Documentation governance

The roadmap supplements the milestone register; it does not replace it.

The roadmap may describe sequencing, strategic rationale, dependencies, and proposed acceptance criteria. It must not silently:

- Approve an unapproved milestone.
- Change a milestone's identity.
- Invent delivery dates.
- Reclassify a milestone without evidence.
- Override an ADR.
- Treat dashboard ticks as delivery proof.
- Turn a recommended dependency into an approved hard dependency.

The register's existing governance and historical identity notes must be preserved.

---

## 3. Current implementation baseline and strategic assessment

The following baseline reflects the evidence identified during the repository review. It is not a declaration that every related milestone is complete.

### 3.1 M83 — path-traversal observability harness

M83 is no longer accurately described as unimplemented.

Existing implementation evidence includes:

- `src/janissary/harness/pathtraver.py`
- Recorder logic for per-case observations.
- Hashes and structural signatures.
- Classification and diagnostics.
- Failure handling and persistence behaviour.
- Unit tests covering classification, persistence, truncation, diagnostics, immutability, and failure cases.
- `benchmark/track_a/runner.py` integration.
- Capability probing for the recording flag.
- Per-case directory creation.
- Case selection and attempt bookkeeping.
- Recording-status handling.
- Enrichment and coverage output.
- `tests/integration/test_harness_runner.py` mocked runner integration tests.

The recorder tests also cover important failure conditions, including simultaneous record-build and failure-log failures, diagnostics invariants, and rejection of unsanitised case identifiers.

The runner's disposition logic distinguishes:

- Cases not reached.
- Cases with scan errors.
- Cases aborted before completion.
- Timed-out cases with indeterminate execution state.
- Recording disabled.
- Missing or invalid recording status.
- Recording failures.
- Cases with observations.
- Cases with zero observations.

This is meaningful implementation, but it does not automatically establish complete end-to-end acceptance.

**Current strategic assessment:** M83 remains `verified-partial`, consistent with its registered status. Stage 1 validation was completed on 2026-11-18 and recorded in commit `40d1715` (Amendment 30). The clean-exit run executed 2,740 subprocesses, created 2,740 case directories with zero collisions, reported `accounting_valid: true`, and measured DAST-applicable F1 of 0.938. Dispositions were 2,621 `has_observations`, 26 `zero_observations`, 0 `recording_failed`, 0 `recording_indeterminate`, and 93 `not_reached`.

Two residual checks remain before the broader M83 acceptance claim can be closed:

1. Run-to-run repeatability under identical conditions has not been performed.
2. Gate E observation call-count inspection at `scanner.py:2125` remains outstanding.

The Stage 1 result is meaningful validation evidence, but it does not promote M83 to complete. The next M83 work should address those two residuals and assess the remaining acceptance protocol against the evidence, without treating the successful run alone as proof of full milestone completion.

### 3.2 M37 — path-traversal detection

M37 is the detection-quality workstream that benefits from M83's measurement capability.

The central problem is not simply whether a payload produces a response. The detector must reliably distinguish meaningful traversal evidence from ordinary application behaviour, error pages, reflected strings, and unrelated content.

M83 provides the measurement foundation. M37 should use that foundation to identify and improve actual false negatives without introducing unacceptable false positives.

### 3.3 M89 — false-positive regression corpus

M89 is an important prerequisite for safely improving detector quality.

The existing regression coverage is insufficient to establish broad real-world false-positive resistance.

The corpus must include representative application behaviours, frontend frameworks, authentication redirects, WAF and challenge responses, public resources, and ordinary application errors.

It must include both positive and negative controls.

The purpose is not to suppress all ambiguous findings. It is to ensure that the detector's confidence and classification accurately reflect the evidence available.

### 3.4 M87 — authentication-state management

M87 has existing authentication-related infrastructure.

Evidence includes:

- Structured `auth_state` reporting.
- `SessionSpec`.
- `SessionRotator` in `src/janissary/engine/session_rotator.py`.
- Session rotation consumed by the scanner.
- Unit tests for rotation and authentication-state behaviour.
- Authentication-state plumbing in CLI, scanner, and SARIF-related paths.

Existing tests cover such behaviour as:

- Default unknown state.
- Authentication-state serialization.
- Unauthenticated operation when credentials are absent.
- Authenticated state when credentials are configured.
- Expired state after repeated authentication failures in applicable conditions.
- Recovery failure when the rotator is exhausted.
- Unauthenticated scans continuing appropriately when a 401 response does not represent an authenticated-session failure.

However, the full AuthStateManager workflow remains an outstanding gap.

**Current strategic assessment:** Existing session rotation and structured authentication-state reporting must be acknowledged. They must not be confused with completion of the full M87 requirement.

The remaining work includes health checks, in-scan reauthentication, bounded recovery, and reliable scan-state accounting.

### 3.5 L05 — SSRF out-of-band attribution

The SSRF workstream needs stronger confidence and attribution rules.

The payload inventory includes:

- HTTP.
- HTTPS.
- Gopher.
- Dict.
- DNS-only.
- AWS metadata.
- AWS IPv6 metadata.
- GCP metadata.
- Azure metadata.

`file://` remains deferred.

The critical risk is attributing a callback to the wrong test case, payload, or scan attempt.

A callback must not be treated as proof merely because it arrives during a scan. Its attribution must be tied to the relevant case, payload, timing, and correlation information.

### 3.6 M42 — IDOR candidate detection

M42 has delivered IDOR candidate-detection functionality, including a detection module, confirmer-related components, scanner integration, CLI wiring, and alternative-authentication support.

The strategic task is therefore evidence quality and triage, not pretending the original detection capability does not exist.

The work should distinguish:

- Candidate findings.
- Findings supported by corroborating evidence.
- Confirmed authorisation-boundary violations.
- Inconclusive results.
- Failed verification.

The project should preserve the distinction between detection and confirmation. A candidate must not become a confirmed IDOR finding merely because the application returned a different response.

Relevant design authority includes ADR-024 and ADR-031. Their requirements should be reviewed before changing the confirmation or triage model.

### 3.7 L03 — SQL injection measurement and delivery

L03 has a committed run-level reproducibility schema in the existing repository history.

That schema is a foundation, not proof that the complete SQL injection measurement protocol has been implemented.

The remaining work includes:

- SQLi-specific recording.
- Case and run provenance.
- Scoring.
- Reproducibility.
- Corpus definition.
- Validation of results.

Framework-aware delivery improvements must follow measurement, not precede it.

### 3.8 Cross-cutting work

M76 and M86 provide important supporting capabilities:

- M76 concerns evidence contracts.
- M86 concerns scan coverage accounting.

These should be considered when designing the acceptance contracts for M83, M89, M87, L05, and L03.

They are strategically important, but their implementation must not displace the immediate measurement and regression priorities without a demonstrated dependency.

---

## 4. Priority model and sequencing

Priorities are based on risk reduction, measurement value, dependency relationships, and the ability to prove an improvement.

### 4.1 Priority tiers

**Tier 1 — Establish trustworthy evidence**

- M83 measurement validation.
- M89 false-positive regression corpus.

These provide the foundation for safe detection improvement.

**Tier 2 — Improve core detection and scan reliability**

- M37 path-traversal detection.
- M87 authentication-state management.

These address important detection and scan-integrity limitations.

**Tier 3 — Improve specialised verification**

- L05 SSRF attribution.
- M42 IDOR evidence and triage.
- L03 SQL injection measurement.

These should build on consistent evidence and verification practices.

**Tier 4 — Improve delivery and cross-cutting assurance**

- L03 framework-aware SQLi delivery, where measurement justifies it.
- M76 evidence contracts.
- M86 scan coverage ledger.

### 4.2 Recommended dependency sequence

The recommended sequence is:

1. M83 measurement pipeline validation.
2. M89 false-positive regression corpus.
3. M37 path-traversal detection improvement.
4. M87 AuthStateManager.
5. L05 SSRF confidence-aware attribution.
6. M42 IDOR evidence and triage improvement.
7. L03 SQL injection measurement.
8. L03 framework-aware SQLi delivery, if justified by results.
9. Cross-cutting M76/M86 assurance improvements, brought forward where a demonstrated dependency requires them.

This is a recommended strategic order. It does not override the milestone register's dependency classifications.

### 4.3 Dependency interpretation

Preserve the distinction between hard dependencies and recommended sequencing:

- M90 → M39 is recorded as a hard dependency.
- M83 → M37 is a recommended measurement dependency.
- M76 → M83/M91/M93/M94/M99 is recommended.
- M86 → M91/M93/M94/M99 is recommended.
- M89 → M37/M91/M97 is recommended.
- M87 is independent of M93/M94/M99.
- M95 → M96 and M97 → M98 remain unverified dependency relationships.

Do not promote a recommended dependency to a hard dependency without formal review.

---

## 5. Staged remediation programme

### Stage 0 — Repository baseline and evidence reconciliation

**Purpose:** Establish a reliable picture of the current implementation, milestone status, documentation authority, and unresolved work before further implementation.

**Scope:**

- Confirm repository HEAD and branch.
- Inspect working-tree changes and untracked files.
- Reconcile registered milestones against dashboard and local-only planning material.
- Review M83, M87, M89, L05, M42, and L03 evidence.
- Inspect relevant source, tests, and ADRs.
- Identify implementation that already exists.
- Identify remaining acceptance gaps.
- Record confirmed dependencies and unresolved questions.
- Update documentation only where explicitly authorised.

**Required outputs:**

1. Evidence-backed repository baseline.
2. Milestone identity and status reconciliation.
3. Accurate M83 and M87 descriptions.
4. Strategic remediation roadmap.
5. List of unresolved technical questions.
6. Explicit separation between implementation evidence and acceptance evidence.

**Acceptance criteria:**

- No unapproved milestone is promoted.
- Dashboard counts are not represented as approved milestone counts.
- M42 and M19 identities are correct.
- M83 is not described as unimplemented.
- M87 acknowledges existing session rotation and structured authentication-state reporting.
- The remaining M87 AuthStateManager gap is explicit.
- Existing untracked files are preserved.
- All documentation changes are within the authorised scope.

**Exit condition:** The documentation diff and supporting evidence have been reviewed. Implementation stages remain separately scoped.

### Stage 1 — M83 measurement pipeline completion and validation

**Purpose:** Establish that the path-traversal harness records, classifies, and reports benchmark observations accurately under real execution conditions.

**Existing foundation:**

- Per-case recorder.
- Hash and structural-signature generation.
- Classification and diagnostics.
- Recorder failure handling.
- Runner capability probing.
- Per-case directory management.
- Case selection.
- Attempt bookkeeping.
- Recording status and enrichment.
- Coverage and disposition outputs.
- Unit and mocked runner integration tests.

**Remaining validation work:**

1. Confirm the CLI `--record-case-dir` option is correctly wired.
2. Confirm the actual scanner invocation receives the recording directory.
3. Verify the real executable path, not only mocked subprocess behaviour.
4. Confirm the recorder and runner agree on the schema.
5. Verify case identifiers and directory naming remain safe and deterministic.
6. Confirm per-case recording status is written and interpreted correctly.
7. Verify missing, invalid, and failed status files are represented accurately.
8. Confirm zero-observation cases are distinguishable from recording failures.
9. Confirm timeout, aborted, skipped, and not-reached cases are not misrepresented.
10. Verify repeatability across repeated runs.
11. Confirm corpus selection and case provenance.
12. Validate benchmark scoring and aggregate output.

**Measurement requirements:**

The benchmark must provide enough information to determine:

- True positives.
- False positives.
- False negatives.
- Precision.
- Recall.
- F1 score.
- Cases not reached.
- Cases aborted or timed out.
- Cases with zero observations.
- Recording failures.
- Recording-indeterminate cases.

A missing observation must not automatically be interpreted as a detector false negative. The case's execution and recording disposition must first be understood.

**Acceptance criteria:**

- Real end-to-end recording is demonstrated.
- Case-level provenance is complete.
- Recording failures remain visible.
- The benchmark can distinguish execution failure from zero observations.
- Repeated runs produce explainable and reproducible outputs.
- Aggregate metrics can be traced back to individual cases.
- All twelve validation areas have documented evidence or an explicit unresolved disposition.

**Exit condition:** M83's measurement pipeline is accepted for use as the evidence foundation for M37.

### Stage 2 — M37 path-traversal detection improvement

**Purpose:** Improve path-traversal detection using the validated M83 measurement pipeline.

**Preconditions:**

- Stage 1 has passed.
- The benchmark corpus and scoring methodology are understood.
- Existing detection behaviour has been recorded as a baseline.

**Scope:**

- Identify missed traversal cases.
- Categorise false negatives by payload, encoding, response behaviour, and application characteristics.
- Identify false-positive patterns.
- Review normalisation and response-comparison behaviour.
- Investigate whether detection limitations arise from payload delivery, response interpretation, or classification.
- Make targeted improvements only where evidence supports them.

**Evaluation:**

Compare baseline and revised behaviour using the same corpus and execution conditions.

Track:

- Recall.
- Precision.
- F1.
- False-positive rate.
- False-negative categories.
- Regression results.
- Execution and recording completeness.

An increase in findings is not sufficient evidence of improvement.

**Acceptance criteria:**

- Improvements are supported by repeatable benchmark results.
- Previously detected cases continue to pass.
- Known false-positive cases remain controlled.
- New regressions have dedicated tests.
- Changes do not conceal inconclusive or failed verification.
- Performance changes are documented.

**Exit condition:** Detection improvements are supported by measured results and regression evidence.

### Stage 3 — M89 real-world false-positive regression corpus

**Purpose:** Establish a durable regression corpus that reflects realistic web application behaviour and protects detector precision.

**Scope:**

Build a representative set of positive and negative controls covering:

- Single-page applications.
- React applications.
- Angular applications.
- Vue applications.
- Client-side navigation.
- Authentication redirects.
- Login and session-expiry pages.
- WAF responses.
- Challenge and bot-protection pages.
- Public static resources.
- Ordinary application errors.
- Generic error templates.
- Responses that reflect input without demonstrating a vulnerability.
- Responses that contain suspicious strings without meaningful security evidence.

**Test design:**

Each case should have:

- A stable identifier.
- A defined expected disposition.
- Relevant request and response context.
- A clear positive or negative rationale.
- Reproducible setup instructions.
- A record of detector behaviour.
- A regression test or benchmark reference.

The corpus must not consist only of known positives. Negative controls are essential to measure precision.

**Acceptance criteria:**

- Positive and negative cases are both represented.
- Framework-specific behaviours are covered.
- Authentication and challenge responses are represented.
- Cases have stable provenance and expected outcomes.
- Regression execution is deterministic.
- Results can be compared across detector versions.
- The corpus is suitable for M37 evaluation and future detection work.

**Exit condition:** The regression corpus is sufficiently representative to serve as a recurring precision guard.

### Stage 4 — M87 AuthStateManager

**Purpose:** Complete authentication-state management so that authentication failures, session expiry, and recovery behaviour are represented accurately during a scan.

**Existing foundation:**

- Structured `auth_state`.
- `SessionSpec`.
- `SessionRotator`.
- Scanner integration.
- Authentication-state tests.
- CLI and SARIF-related reporting.

**Outstanding work:**

Design and implement the full AuthStateManager workflow within an approved scope.

The design should cover:

1. Initial authentication state.
2. Authentication health checks.
3. Detection of session expiry.
4. Distinction between endpoint-specific 401 responses and actual session failure.
5. In-scan reauthentication.
6. Bounded recovery attempts.
7. Session rotation.
8. Exhaustion and recovery failure.
9. Explicit unauthenticated operation.
10. Final scan-state and coverage reporting.

**Important behavioural distinction:**

A 401 response from an individual endpoint does not necessarily mean that the scan's authenticated session has expired.

The manager must use appropriate evidence and health checks rather than treating every 401 as a global authentication failure.

Recovery must be bounded. Repeated reauthentication attempts must not create infinite loops or conceal scan failure.

**Acceptance criteria:**

- Authentication state transitions are explicit and testable.
- Health checks distinguish session failure from endpoint-specific responses.
- Reauthentication is bounded.
- Session rotation integrates with the existing infrastructure.
- Recovery failures remain visible.
- Unauthenticated scans retain their intended behaviour.
- Scan coverage reflects authentication-related interruptions.
- CLI and output formats communicate the final state accurately.

**Exit condition:** Authentication state and recovery behaviour are reliable, bounded, observable, and covered by tests.

### Stage 5 — L05 SSRF confidence-aware out-of-band attribution

**Purpose:** Improve the reliability of SSRF verification by ensuring out-of-band evidence is attributed to the correct test.

**Scope:**

Review the existing payload inventory and callback handling.

Establish a correlation model that associates each callback with:

- The scan.
- The originating test case.
- The payload.
- The execution attempt.
- The relevant callback time.
- Any available correlation identifier.

**Classification model:**

Distinguish:

- Confirmed: sufficient evidence establishes the expected interaction.
- Probable: evidence is suggestive but does not meet the confirmation threshold.
- Inconclusive: evidence cannot reliably establish attribution or behaviour.
- Failed verification: the verification process itself failed or could not complete.

A callback that cannot be reliably attributed must not be reported as a confirmed vulnerability.

Stale callbacks and callbacks from another case must not be allowed to contaminate current results.

**Payload considerations:**

Preserve the existing inventory:

- HTTP.
- HTTPS.
- Gopher.
- Dict.
- DNS-only.
- AWS metadata.
- AWS IPv6 metadata.
- GCP metadata.
- Azure metadata.

`file://` remains deferred unless a separately reviewed scope authorises it.

**Acceptance criteria:**

- Callback attribution is deterministic.
- Cross-case attribution is prevented.
- Stale evidence is handled explicitly.
- Confidence classification is consistent.
- Failed verification is retained and reported.
- Tests cover positive, negative, delayed, stale, and ambiguous callback scenarios.

**Exit condition:** SSRF findings are supported by attributable evidence and explicit confidence classification.

### Stage 6 — M42 IDOR evidence and triage improvement

**Purpose:** Improve the quality of IDOR evidence and confirmation without rewriting or misrepresenting the delivered candidate-detection capability.

**Existing foundation:**

- IDOR detection module.
- Candidate-finding functionality.
- Confirmer-related components.
- Scanner integration.
- CLI wiring.
- Alternative-authentication support.
- ADR-024 and ADR-031 design authority.

**Scope:**

Audit the current candidate and confirmation workflow.

Ensure the system distinguishes:

- A candidate caused by a potentially interesting response difference.
- A candidate with corroborating evidence.
- A confirmed authorisation-boundary violation.
- An inconclusive result.
- A failed verification.

Review the two-identity testing mechanism and its assumptions.

A response difference alone must not be treated as proof of IDOR. The evidence must demonstrate an authorisation boundary violation.

**Acceptance criteria:**

- Candidate and confirmed findings remain distinct.
- Confirmation requirements are explicit.
- Evidence is attributable to the relevant identities and requests.
- Inconclusive outcomes are preserved.
- Negative controls prevent ordinary response variation from becoming a confirmed finding.
- ADR-024 and ADR-031 remain respected.
- Existing delivered functionality does not regress.

**Exit condition:** IDOR triage is evidence-based, repeatable, and appropriately conservative.

### Stage 7 — L03 SQL injection measurement protocol

**Purpose:** Establish reproducible SQL injection measurement before changing payload delivery or detector behaviour.

**Existing foundation:**

The run-level reproducibility schema has been committed. The remaining work is to connect it to SQL injection-specific production, provenance, scoring, and validation.

**Scope:**

- Define SQLi-specific benchmark cases.
- Establish case-level and run-level provenance.
- Record execution and verification dispositions.
- Capture relevant payload and response evidence.
- Define positive and negative controls.
- Establish scoring methodology.
- Validate repeatability.
- Distinguish detector behaviour from delivery and execution failures.

**Measurement requirements:**

The protocol should make it possible to identify:

- Confirmed detections.
- False positives.
- False negatives.
- Inconclusive cases.
- Cases not reached.
- Timeouts.
- Execution failures.
- Verification failures.
- Recording failures.

Results must be traceable from aggregate metrics to individual test cases and execution attempts.

**Acceptance criteria:**

- SQLi-specific evidence is recorded.
- Case and run provenance are linked.
- Scoring is documented.
- Positive and negative controls exist.
- Results are reproducible.
- Execution failure is not confused with detector failure.
- Aggregate metrics are traceable to underlying evidence.

**Exit condition:** SQLi measurement is accepted as a reliable baseline for subsequent delivery work.

### Stage 8 — L03 framework-aware SQL injection delivery

**Purpose:** Improve SQL injection delivery only where Stage 7 demonstrates that delivery limitations are materially reducing detection.

**Precondition:**

Stage 7 must identify a measurable delivery limitation. Do not implement framework-specific payload changes based only on speculation.

**Investigation areas may include:**

- ORM behaviour.
- Database dialect differences.
- Framework request handling.
- Parameter binding.
- Encoding and normalisation.
- Middleware transformations.
- Query construction patterns.
- Response behaviour.

**Scope discipline:**

Each proposed change must identify:

1. The affected benchmark cases.
2. The measured failure mode.
3. The hypothesised cause.
4. The smallest targeted change.
5. The expected measurable improvement.
6. The regression risks.

Do not introduce broad payload expansion without evidence that it addresses the observed failure.

**Acceptance criteria:**

- The delivery limitation is demonstrated by Stage 7.
- Changes target an identified cause.
- Existing positive and negative controls remain valid.
- Improvements are measured using the same protocol.
- Regression and performance effects are documented.

**Exit condition:** Framework-aware delivery improvements demonstrate measurable benefit without unacceptable regression.

### Stage 9 — Cross-cutting evidence contracts and scan coverage

**Purpose:** Strengthen the consistency of evidence and scan-completeness reporting across JANISSARY.

**Relevant milestones:**

- M76 — evidence contracts.
- M86 — scan coverage ledger.

These workstreams should be brought forward if a specific Stage 1–8 acceptance requirement depends on them.

**M76 considerations:**

Review and formalise evidence requirements for:

- Candidate findings.
- Confirmed findings.
- Failed verification.
- Inconclusive verification.
- Missing evidence.
- Corroboration.
- Provenance.
- Reproducibility.

The system should preserve verification failures rather than silently dropping them.

**M86 considerations:**

Review scan coverage accounting for:

- Cases selected.
- Cases started.
- Cases completed.
- Cases skipped.
- Cases not reached.
- Cases aborted.
- Cases timed out.
- Cases with failed verification.
- Cases with missing or indeterminate evidence.

Coverage reporting must distinguish what was tested from what was merely planned or selected.

**Acceptance criteria:**

- Evidence states are consistently represented.
- Failed verification remains visible.
- Coverage states are explicit.
- Aggregate coverage can be reconciled to case-level records.
- Downstream consumers do not mistake missing evidence for a clean result.
- Existing output formats remain compatible or are deliberately versioned.

**Exit condition:** Evidence and coverage contracts provide consistent, auditable semantics across the relevant workflows.

---

## 6. Deferred and separately governed work

### 6.1 M91–M99

The following remain proposed and unapproved in the current milestone register:

- M91 — GraphQL Authorization & Security Assessment.
- M92 — AI Agent & Tool Security Assessment.
- M93 — OAuth/OIDC Authentication & Token Trust Assessment.
- M94 — CSRF Enforcement & State-Changing Request Verification.
- M95 — Business-Logic Race Condition Assessment.
- M96 — HTTP/2 Multiplexing & Synchronized Race Testing.
- M97 — XSS Parser Differential & Context-Aware Payload Assessment.
- M98 — DOM-Based XSS Source-to-Sink Analysis.
- M99 — SAML Federation & Assertion Security Assessment.

This roadmap does not approve or authorise their implementation.

Their dependencies and relationships may be considered during architecture planning, but their status must remain unchanged unless the required formal approval is obtained.

### 6.2 M100–M108

The dashboard displays M100–M108, but their registration and approval have not been established by the current tracked milestone register.

They require a separate reconciliation exercise.

No milestone identity, scope, status, delivery date, or approval should be inferred solely from dashboard entries.

### 6.3 M39 and M90

The register records a relationship between the gRPC integration and adapter work:

- M39 — gRPC integration.
- M90 — gRPC adapter.

Preserve the recorded hard dependency M90 → M39.

These workstreams should be scheduled according to their formal scope and dependency, not pulled into the immediate remediation sequence without a demonstrated reason.

### 6.4 M88 and crawler architecture

M88 resumable scanning and the ADR-021 crawler work are separate architectural concerns.

They remain relevant, but they should not displace the immediate measurement, regression, authentication, and evidence priorities unless a concrete dependency is established.

### 6.5 Deferred SSRF file scheme

`file://` remains deferred in the L05 payload inventory.

It must not be introduced as an incidental addition to the current SSRF work.

---

## 7. Stage governance, verification, and release controls

### 7.1 Scope before implementation

Before each implementation stage:

- Identify the relevant milestone and design authority.
- Inspect existing source and tests.
- Confirm what is already implemented.
- Define the exact remaining gap.
- Identify the files and interfaces likely to change.
- Define acceptance criteria.
- Identify compatibility and regression risks.
- Obtain explicit authorisation for the implementation scope.

A roadmap stage is a planning boundary, not blanket permission to modify the repository.

### 7.2 Implementation discipline

During a stage:

- Keep changes within the approved scope.
- Avoid unrelated cleanup.
- Avoid opportunistic refactoring.
- Preserve existing interfaces unless a change is explicitly required.
- Add targeted tests for new behaviour.
- Retain negative and failure-path tests.
- Do not weaken tests merely to make implementation pass.
- Do not convert unknown or failed states into success states.
- Do not claim acceptance based on code presence alone.

If implementation reveals a requirement outside the approved scope, stop and report it for a separate decision.

### 7.3 Verification sequence

Use a layered verification approach:

1. Focused unit tests.
2. Focused integration tests.
3. Relevant regression tests.
4. Type, lint, and static checks where applicable.
5. Broader test suite.
6. Benchmark or corpus execution.
7. Output and evidence inspection.
8. Final repository-state review.

The exact checks must be appropriate to the stage and the project's existing tooling.

A test that uses mocks must be described as a mocked integration test. It must not be presented as proof of real executable end-to-end behaviour.

### 7.4 Stage exit report

Every stage must report:

- Scope authorised.
- Files changed.
- Behaviour added or corrected.
- Tests added or changed.
- Commands executed.
- Test and verification results.
- Benchmark results where relevant.
- Remaining limitations.
- Known regressions or risks.
- Acceptance criteria satisfied.
- Acceptance criteria outstanding.
- Git status and staged state.

Do not move to the next implementation stage until the current stage's results have been verified.

### 7.5 Git and commit controls

Repository changes must remain controlled and auditable.

- Inspect Git status before editing.
- Preserve unrelated working-tree changes.
- Do not stage unrelated files.
- Use explicit file paths when staging.
- Do not use `git add -A` or `git add .` for scoped work.
- Review the complete staged diff before committing.
- Run normal commit hooks.
- Do not bypass hooks to force a commit.
- If a hook hangs or fails, stop and diagnose it.
- Do not push unless push is separately and explicitly authorised.

A commit authorisation is limited to the named files and approved changes. It does not include a push.

If unrelated tree drift appears, stop and report it. Do not absorb it into a scoped commit.

### 7.6 Documentation and status controls

Milestone status must reflect demonstrated evidence.

Use the register's defined status vocabulary and preserve its governance.

In particular:

- `verified-partial` means implementation or design evidence exists, but acceptance remains incomplete.
- `no-implementation-identified` is a bounded finding, not proof that no implementation could exist anywhere.
- `proposed-unapproved` must not be treated as approved.
- A dashboard tick is not independent evidence of delivery.
- A committed implementation does not automatically prove all acceptance criteria.

---

## 8. Risks and controls

| Risk | Consequence | Control |
|---|---|---|
| Unverified benchmark baseline | Misleading detection improvements | Complete M83 validation before detector optimisation |
| False-positive regression gaps | More findings but lower trust | Establish M89 positive and negative corpus |
| Mock-only integration evidence | False confidence in executable behaviour | Demonstrate real end-to-end execution |
| Missing or ambiguous case records | Incorrect benchmark scoring | Preserve per-case dispositions and recording failures |
| Authentication expiry misclassification | Incomplete or misleading scan results | Implement health checks and bounded recovery |
| Cross-case SSRF callback attribution | False vulnerability confirmation | Correlate callbacks to case, payload, and attempt |
| IDOR candidate overclaim | False confirmed findings | Separate candidate and confirmation states |
| SQLi delivery changes before measurement | Unproven complexity and regressions | Complete L03 measurement first |
| Dashboard/register divergence | Incorrect project reporting | Preserve tracked register authority |
| Unapproved milestone promotion | Governance failure | Keep M91–M99 and M100–M108 separately governed |
| Scope expansion during implementation | Unreviewed repository changes | Require explicit scope decisions |
| Hook bypass or broad staging | Integrity and auditability loss | Explicit paths and normal hooks |

### 8.1 Programme success measures

The remediation programme should be evaluated using evidence rather than activity counts.

Key measures include:

- Percentage of benchmark cases with complete provenance.
- Percentage of cases with a definitive execution disposition.
- Number of unexplained recording failures.
- Precision, recall, and F1 by detector and category.
- False-positive regression pass rate.
- Authentication recovery success and failure rates.
- SSRF callback attribution confidence.
- IDOR candidate-to-confirmation evidence quality.
- SQLi run reproducibility.
- Scan coverage reconciliation.
- Number of unresolved acceptance criteria.

Do not define arbitrary target values without a measured baseline and an agreed acceptance rationale.

---

## 9. Immediate execution plan and final direction

### 9.1 Immediate next actions

The bounded documentation and evidence reconciliation for this execution round has been prepared across the four explicitly authorised documents. It records the current capability and OpenAPI implementation state, removes contradictory stale backlog descriptions, and reconciles the roadmap with the available M83 Stage 1 evidence and its two remaining residual checks.

The reconciliation preserves M83 as `verified-partial`, acknowledges the existing M87 `SessionRotator` and structured authentication-state infrastructure while retaining the outstanding full `AuthStateManager` gap, and preserves the existing milestone identities, approval boundaries, dependency classifications, and dashboard counts.

No milestone register, workflow, dashboard, source-code, or unrelated documentation changes are part of this reconciliation. This documentation stage is complete only after the resulting diff and checks have been reviewed and the explicitly scoped local commit has passed its normal hooks. Subsequent implementation stages remain separately scoped and require separate authorisation.

### 9.2 Subsequent execution order

After the documentation stage is reviewed and completed:

1. M83 full measurement validation.
2. M89 false-positive regression corpus.
3. M37 measured detection improvement.
4. M87 AuthStateManager.
5. L05 SSRF attribution.
6. M42 IDOR evidence and triage.
7. L03 SQLi measurement.
8. L03 framework-aware delivery, if justified.
9. M76/M86 cross-cutting assurance, brought forward where needed.

Each implementation stage must be separately scoped and authorised.

### 9.3 Final strategic direction

JANISSARY should prioritise trustworthy security evidence over feature-count growth.

The strongest next release is not necessarily the one with the most new detectors, payloads, or milestone ticks. It is the one that can demonstrate, reproducibly:

- What was tested.
- What was detected.
- What was not detected.
- What could not be tested.
- Why a finding was classified as a candidate or confirmed.
- Whether authentication remained valid.
- Whether verification completed.
- Whether the evidence belongs to the relevant test.
- Whether a measured improvement is real.

The project should advance through bounded, evidence-backed stages, preserving milestone governance and repository integrity throughout.

**The roadmap defines strategic priorities and acceptance expectations. It does not override existing design authority, milestone approval, or explicit authorisation controls.**
