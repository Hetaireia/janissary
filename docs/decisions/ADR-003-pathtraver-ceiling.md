# ADR-003: Pathtraver support ceiling

**Status:** Accepted
**Date:** 2026-10-25
**Related:** ADR-001 (benchmark methodology), ADR-002 (DOM structural hashing)

## Context

Path traversal F1 in the DAST-applicable benchmark has been consistently low: 0.049 (r1 baseline) to 0.308 (per-category ceiling, but that ceiling is over a small case set — see below). The current state is documented in `docs/pathtraver.md` and reproduced across runs 1-3 of the 3-run baseline.

The pathtraver categories in the OWASP Benchmark (`pathtraver-00` through `pathtraver-03`) test whether a scanner detects path traversal payloads that would disclose files on the target file system. The target in the benchmark is a containerized servlet application. Whether `../../../../etc/passwd` succeeds depends on:

1. The application's actual file read logic
2. The container's filesystem layout
3. The JVM's process user and permissions
4. The specific encoding the application decodes at the point of vulnerability

A DAST scanner observes: request sent, response received. It cannot see the server's file read. It sees only status, headers, length, and body. The benchmark target is configured so that **successful traversal disclosure is not distinguishable from a servlet error page** by HTTP status or length — the "reading /etc/passwd" case returns a response shape that is very close to the "rejected" case. This is a benchmark target property, not a JANISSARY defect.

But "it's the target's fault" is not a sufficient answer. A DAST tool with a path traversal class must do *something* honest with the case. Two dishonest options: emit a finding on every 200 response in a traversal probe (creates FPs); exclude traversal from the benchmark (misrepresents coverage). Both are refused.

## Decision

**Path traversal is partially supported. The ceiling is documented and stable. It is not scheduled for full support within Phase 0-3.**

"Partial support" means, concretely:

- Traversal probes are sent (`benchmark/track_a` includes them in the corpus, they count in TP/FN/FP)
- Detection relies on the differential engine (status, length, body) — the same logic used for all classes
- A finding is emitted when the differential signal is unambiguously traversal-shaped (e.g. response body matches `/etc/passwd` line format, response body is flat text where baseline was HTML)
- A finding is *not* emitted on "response changed but did not change in a traversal-specific way"
- The resulting F1 is what the benchmark measures, without adjustment

That last point — no benchmark adjustment — is the substance of this ADR. A future contributor who wants traversal F1 to rise must either improve detection (legitimate) or propose to change the corpus/exclusion set (which requires amending ADR-001 and re-baselining). Silently excluding traversal from the benchmark, or weighting the metric differently for traversal cases, is out of scope.

### What is not being decided

- **Not** "path traversal will never be fully supported." It might be, in a future phase not currently scheduled.
- **Not** a specific F1 target. The current F1 is what it is. A specific target number would be a promise this ADR does not make.
- **Not** a promise of parity with other DAST tools. Other tools may score differently on the same corpus for the same underlying reasons (target property, encoding coverage, fixture detail). Parity is not a stated goal.

### Revisit triggers

This ADR is revisited when **either**:

1. **Phase 1.3d ships.** The `>20` structural-collapse path in ADR-002 may catch flat-text `/etc/passwd` responses that the current differential engine misses. If 1.3d's benchmark re-run shows traversal F1 materially improves (the threshold for "materially" is set when 1.3d ships, not now — the 3-run baseline is the reference), this ADR is superseded by a new ADR recording the improved state.
2. **A named customer or user requests full traversal support.** The request must be specific — "we need traversal parity with tool X on corpus Y" or "we cannot ship until traversal F1 is above Z" — not "traversal should work better." If such a request arrives, it becomes a Phase 2 entry with its own ADR and its own target.

Absent either trigger, the ceiling stands. It does not decay with time; it does not get quietly re-opened in a retrospective.

## Rationale

Three reasons this is the correct decision, in order of weight:

**1. It is honest.** A DAST tool that claims full traversal support while scoring F1 0.05-0.31 on a public benchmark is either lying or has not read its own benchmark. Publishing the low number alongside the high numbers is what makes the high numbers credible. This ADR is the commitment to keep publishing it.

**2. It is within scope.** Full traversal support requires an OOB-callback infrastructure (Interactsh, Phase 2.6) for blind traversal where the file read is not reflected, plus a broader encoding/dictionary engine (Phase 2.2). Committing to full support in Phase 0-3 would compress those phases and delay higher-ROI work (auth integration, SARIF, differential refinement) for a class where the underlying benchmark is unfriendly to any HTTP-observable scanner.

**3. It is reversible.** Nothing about this ceiling prevents a future ADR from raising it. If 1.3d improves the number, or if a customer asks, the path is clear. What the ceiling prevents is *uncontrolled* attempts to improve the number by tuning to the benchmark — which is the failure mode that ruins DAST benchmarks in general.

## Consequences

- **No implementation work** on traversal until a revisit trigger fires.
- **Pathtraver-00 through pathtraver-03** remain in the DAST-applicable corpus and remain counted in TP/FN/FP. The F1 contribution from these categories is real and is what it is.
- **`docs/pathtraver.md`** remains the user-facing document. Its content is consistent with this ADR; if they diverge, this ADR is normative.
- **Phase 2.2 (traversal dictionary/encoding)** remains in the roadmap as **prereq: 1.3d**, not as a standalone traversal initiative. The re-scoping from earlier — 1.3d supplies confirmation, 2.2 supplies payload coverage — is confirmed by this ADR.
- **README §Known Issues** continues to list pathtraver F1 0.049-0.308 as a documented limitation. It is not hidden.
- Any future change to traversal *counting* (e.g. excluding specific cases, changing weighting) is an ADR-001 change, not an ADR-003 change.

## References

- `docs/pathtraver.md` — user-facing traversal limitation document
- `docs/decisions/ADR-001-benchmark-methodology.md` — the corpus and exclusion rules
- `docs/decisions/ADR-002-dom-structural-hashing.md` — the 1.3d mechanism that is expected to improve traversal recall
- `BENCHMARK.md` Amendment 22 — per-category F1 including pathtraver