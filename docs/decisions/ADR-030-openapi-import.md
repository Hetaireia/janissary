# ADR-030 — OpenAPI / Swagger import (BL-5)

**Status:** Accepted (implemented `33d6091`, CLI/dry-run `507bbd1`, real-HTTP test `e188afb`)
**Parent:** ADR-021 (crawler placement), ADR-016 (verified/discovery vocabulary)
**Backlog:** docs/DETECTION-BACKLOG.md BL-5
**Scope:** OpenAPI 3.0.x and Swagger 2.0 import, operation-level parameter dispatch, CLI enumeration, and per-operation scanning. This ADR records the original design and the shipped implementation, including known limitations.

## Problem

JANISSARY takes a URL and a param list. For a target with a published OpenAPI spec, this is redundant work: the spec already declares every endpoint, every parameter, every method, every content type. A user pointing JANISSARY at an OpenAPI-documented API today must transcribe that spec by hand into case lists or scan URL-by-URL.

Every competitor has this feature (ZAP has OpenAPI import, Nuclei has an api-spec template, StackHawk's entire workflow is built around it). Not having it is not a differentiator — it is friction.

## Decision

Add an `--openapi PATH` flag to `janissary scan`. When set, JANISSARY imports the spec, enumerates operations, and scans each one using the existing differential oracle. No new detection logic; only a new source of scan targets.

**Both OpenAPI 3.0 and Swagger 2.0.** 3.0 is more used today, but 2.0 is embedded in millions of legacy enterprise specs. Rejecting 2.0 would exclude the enterprise market the project is aimed at.

**Local file and HTTP URL sources.** `--openapi ./spec.json` and `--openapi https://api.example.com/openapi.json`. No authentication on the fetch — if the spec requires auth, the user fetches it themselves and points at the local file.

## Scope

### In scope

- OpenAPI 3.0.x and Swagger 2.0
- Local file (`file://` and bare path) and HTTP/HTTPS URL
- JSON and YAML formats
- `$ref` resolution — local (`#/components/...`) and external file references
- Server URL templating — `{protocol}`, `{host}`, `{basePath}` variables with declared defaults
- Path parameters, query parameters, header parameters, cookie parameters, request bodies
- Security scheme identification — logged in the manifest but not implemented (auth is out of scope, see BL-2 in the roadmap)

### Out of scope

- Authentication during spec fetch — user supplies a pre-fetched spec
- Authentication during scan — that is a separate authenticated-scanning workstream (roadmap Phase 2, M41–M43, already shipped for sessions but not for OpenAPI-declared auth)
- Callbacks, webhooks, links — OpenAPI 3.0 features that do not map to a scanner-target model
- Response schema comparison — the differential oracle already handles response comparison; the spec's response schemas are not consulted
- Postman collection import — a separate format, a separate ADR if pursued
- gRPC / GraphQL SDL — separate protocols, separate ADRs

## Original functional requirements (historical proposal)

The following records the original design expectations. They are historical proposal requirements, not a statement that every behaviour shipped or is currently guaranteed. Delivered behaviour and known limitations are documented in *Shipped implementation and current limitations* below.

When `--openapi PATH` is supplied, the original proposal intended:

1. JANISSARY parses the spec without crashing on any valid 2.0 or 3.0 spec
2. It enumerates every operation (path × method) declared in the spec
3. For each operation, it constructs one or more scan targets — one per declared parameter
4. For path parameters, it substitutes the parameter name into the path and scans the substituted URL
5. For query/header/cookie parameters, it appends/attaches and scans
6. For JSON request-body parameters, the original proposal intended reuse of the existing `--json-template` machinery; named body-parameter injection was not delivered
7. It logs at the top of the scan: `[runner] imported N operations from spec`
8. It logs any operation it could not use: `[runner] skipped M operations: <reason>`

## Non-functional requirements

The original design treated these as higher priority than the functional requirements. The items below distinguish shipped behaviour from historical proposal criteria.

1. **Parser/importer visibility.** Imported operations and parser-level skipped operations or notes should be visible. This does not currently guarantee complete runtime scan accounting: target-construction and scan exceptions can be logged and skipped without marking the merged summary incomplete. See *Known runtime accounting limitation* below.
2. **Operation enumeration is inspectable.** `--dry-run` prints imported operations and generated targets without scanning. This supports manual review; it is not a guarantee that every operation or construct is represented.
3. **Original reference-parser requirement (historical).** The design proposed comparing parser output against `prance` or `openapi-spec-validator`. This is historical test-strategy material, not evidence of exhaustive differential testing in the shipped implementation.
4. **Explicit opt-in.** OpenAPI scanning is invoked through `--openapi`; it is not part of the default scan path. The original merge-behind-a-flag, monitor-CI, then-announce sequence is historical rollout planning.
## Original staged implementation plan

The following records the original six-stage implementation plan. Its sequencing and differential-testing criteria describe the historical proposal; they are not additional acceptance requirements for future work or proof that every proposed check remains applicable.

### Stage 1 — parser skeleton, 3.0 only, no `$ref`

Read a single-file OpenAPI 3.0 JSON spec. Enumerate `paths` → methods → parameters. Return an operation list. Test against Petstore and a second small spec. Assert operation count.

### Stage 2 — `$ref` resolution

Resolve local `#/components/...` and external file `$ref` chains. Test against a spec that uses `$ref` heavily (the large torture test is deferred until a 2-4 MB 3.0 spec is pinned; the published Kubernetes spec is Swagger 2.0 and would be rejected by Stage 2's 3.0-only validator, so kube moves to Stage 3). Assert resolved operation count equals `prance`'s count.

### Stage 3 — Swagger 2.0 support

2.0 has a different schema (`definitions` not `components/schemas`, `host`+`basePath`+`schemes` not `servers`). Write the adapter. Same tests, different fixtures. Stage 3 also carries the Kubernetes torture test (api/openapi-spec/swagger.json, ~3 MB, Swagger 2.0), moved here from Stage 2 because Stage 2 validates 3.0 only.

**Shipped 2026-11-11.** Version gate accepts both openapi 3.0.x and swagger 2.0 (9a997c0). petstore-2.0 fixture, 14 paths and 20 operations, flows through the oracle and the parameter-name differential (38624fe). Kubernetes swagger.json, 4.3 MB and 1172 operations, parses in 0.27s at 17.4 MB peak against a 100 MB ceiling (3e497ed). The torture test found a performance bug the small-fixture tests could not: RefResolver.resolve called Path.resolve unconditionally before checking for $ref, then again per parameter; kube parse went from minutes to 0.27s after the fast-path and path-cache fix (7cfc8ad). No prance differential exists for the kube fixture; see the exception note under Differential testing.

### Stage 4 — server URL templating

Handle `servers[].url` with `{protocol}`, `{host}`, `{basePath}` variables. Fill from `servers[].variables` defaults. If a template variable has no default, log skipped with reason.

**Shipped 2026-11-11 (2ad849b), with two clarifications.** The original wording conflated versions: template substitution from servers[].variables is OpenAPI 3.0 only; Swagger 2.0 has no templating, its base URL is schemes[0] + host + basePath. Both are implemented, dispatched on the version key. Second, unresolved template variables append a note and leave Operation.base_url empty rather than emitting SkipRecords: SkipRecord is operation-scoped and server resolution is spec-scoped, so a literal skip would zero out every operation for one missing default. Per-operation and per-path servers overrides remain out of scope.

### Stage 5 — parameter dispatch

Route path/query/header/cookie/body parameters to the correct scan call. Path params substitute into URL path. Query params append. Header and cookie params need `--inject-in` dispatch. Body params reuse `--json-template`.

**Initial dispatch implementation shipped 2026-11-11 (`7597258`).** Operation gains `parameter_locations`, populated from each resolved parameter. `build_scan_targets(op)` returns one target per distinct location because `Scanner.inject_in` is a single mode per instance. The initial mode map recorded here was path→path, query→`param-name`, header→header, cookie→cookie, body→auto. The query mapping was subsequently corrected; the authoritative current mapping is recorded in the 2026-11-13 amendment immediately below. Unsupported locations (including Swagger 2.0 `formData`) append a parser note and are excluded. Stage 5 implemented target transformation; the per-target Scanner construction and execution loop was delivered separately in Stage 6.

**Stage 5 amendment, 2026-11-11 (body targets).** As shipped, body locations emitted inject_in='json-body' with json_template=None. Scanner.__init__ rejects that combination, so any operation declaring a body parameter produced a target that raised ValueError on construction. The transformation was internally consistent (dispatch.py imports no scanner, by design), but the join went untested: six dispatch tests asserted emission, and none constructed a Scanner. Body locations now emit inject_in='auto', params=[], and a note; the endpoint is still scanned, without named body-param injection. New test_openapi_dispatch_consumption.py constructs a Scanner from every emitted target type, so the join is covered. Injecting body parameters by name requires request-body schema capture in the importer, which Operation does not carry; that is filed separately, not folded into Stage 6.

**Stage 5 query-dispatch correction, 2026-11-13.** The original Stage 5 dispatch record above incorrectly states that query parameters map to `param-name`. The current implementation maps OpenAPI `query` parameters to Scanner `inject_in="query"` (`src/janissary/importers/dispatch.py`). This is intentional: `query` preserves the declared parameter name and injects the payload as its value (`?limit=PAYLOAD`); `param-name` instead injects the payload as the parameter name (`?PAYLOAD=limit`). Verification: `tests/unit/test_openapi_dispatch.py`, `tests/unit/test_openapi_dispatch_consumption.py`, `tests/integration/test_openapi_query_dispatch.py` — **15 passed** on 2026-11-13. The integration tests assert the actual outgoing query strings. No Scanner or dispatch code change was required. This resolves the query name/value dispatch concern; it does not resolve the separately documented request-body limitation.

### Stage 6 — CLI wiring, `--dry-run`, integration

Add `--openapi PATH` and `--dry-run` flags. Wire to scanner. Integration test: dry-run on a public spec, count operations, scan the smallest 3 operations against a mock. Assert no crashes and no silent drops. **Revised estimate: 7-9 hours** (was 2-3h). The revision reflects what Stage 5's description implied but did not need: extracting the CLI's Scanner construction into a helper, the loop that builds one Scanner per build_scan_targets output, aggregation of N ScanSummary objects, and the body-target amendment above.

## Shipped implementation and current limitations

The original six-stage plan above is historical design and implementation history. The following records the delivered CLI and scan-loop behaviour as currently evidenced.

### Stage 6 delivery

- Stage 6a, commit `2bb0f6b` (2026-11-12): extracted `_resolve_scan_deps` from `cmd_scan`.
- Stage 6b, commit `5001f09` (2026-11-12): extracted `_emit_scan_result` from `cmd_scan`.
- Stage 6c, commit `33d6091` (2026-11-12): wired the per-operation scan loop.
- Stage 6d, commit `8c5a520` (2026-11-12): added integration tests for the OpenAPI scan loop.
- CLI/dry-run, commit `507bbd1` (2026-11-11): added `--openapi` and `--dry-run` target enumeration.
- Real-HTTP integration, commit `e188afb` (2026-11-17): exercised the scan pipeline against a local HTTP server.

`_cmd_scan_openapi_dry_run` parses the specification and prints its version, imported and skipped operations, and generated targets. Import errors return exit code 64. Dry-run does not construct a Scanner or perform target network requests or preflight.

`_run_openapi_scan` constructs a Scanner for each target emitted by `build_scan_targets`, executes the per-target scan, merges the resulting summaries, and emits the shared single-scan output. The OpenAPI operation loop does not include the separate `--graphql`, `--ws`, `--host-bypass`, `--heuristic`, or `--idor` extension scans. Parser notes and imported/skipped operation information are logged.

### Known runtime accounting limitation

Target-construction and per-target scan exceptions are logged and skipped so later targets can continue. However, the caller does not mark the merged summary `scan_incomplete` or aborted when it skips a failed target. `merge_scan_summaries` combines the available findings, candidates, request measurements, parameters, baselines, WAF/pacer data, and existing abort/incomplete state, but it has no field for per-target runtime failures and does not itself mark the result incomplete when the caller omits a failed target. The loop's log-and-continue behaviour is explicitly covered by `tests/integration/test_openapi_loop.py`; the test does not establish incomplete-summary accounting. Consequently, a run may return success even though one or more targets failed at runtime. This is a known gap against the original complete-accounting/no-silent-drops intent, not a claim that the importer silently discards parser operations.

### Request-body and parameter coverage limitations

Request-body targets currently use `inject_in="auto"` and `params=[]`. The endpoint is still scanned, but named body-parameter injection is not implemented because request-body schema capture is not represented in the imported operation model. Query dispatch currently uses `inject_in="query"`, not the superseded initial `param-name` mapping described in the Stage 5 history. The current mapping and its query-string integration tests are recorded in the 2026-11-13 correction above.

### Test evidence and its limits

The reported targeted Windows test run collected and passed 39 tests across the OpenAPI loop, real-HTTP path, query dispatch, dry-run, dispatch, dispatch-consumption, and summary-merge suites. The real-HTTP test uses one OpenAPI 3.0.3 GET operation (`/search`) with a query parameter against a local HTTP server. It asserts baseline and marker-payload requests and a successful command result. This is useful end-to-end evidence for that narrow path; it is not broad public-API coverage or proof of every HTTP method, parameter location, or supported OpenAPI construct.

The original `prance` comparison remains historical test-strategy material. It is not a runtime dependency and should not be read as evidence that every shipped parser path has been exhaustively compared against it.

### Source documentation discrepancy

The current CLI parser help text still says that `--openapi` requires `--dry-run`, despite the per-operation scan loop having shipped. That wording is stale relative to the implementation. The CLI source is outside the scope of this documentation reconciliation and has not been changed here; correcting it requires separate authorisation.

## Original test strategy (historical)

### Differential testing proposal

The original plan proposed running parser fixtures through JANISSARY and `prance`, then comparing operation counts, parameter counts, and per-operation parameter names. This describes the proposed test strategy, not a guarantee that every current parser test performs that comparison.

**Historical exception, 2026-11-11.** The original test plan documented that the Kubernetes torture test had no `prance` differential because `prance` could not parse that fixture. The test instead asserted a measured operation count (1172) and a memory ceiling. The original plan stated that other fixtures used the `prance` differential; this historical statement does not establish the current extent of differential coverage.

The original proposal identified `prance` as a reference parser for differential tests, not as a runtime dependency. This historical proposal does not establish that `prance` is currently installed or used by every parser test.

### Canonical corpus

Pin the following fixtures under `tests/fixtures/openapi/`:

| Fixture | Purpose |
|---|---|
| `petstore-3.0.json` | Smallest canonical 3.0 spec |
| `petstore-2.0.json` | Smallest canonical 2.0 spec |
| `ref-heavy-3.0.json` | Exercises local `$ref` chains |
| `external-ref-3.0.json` + `external-ref-target.json` | External file `$ref` |
| `templated-servers-3.0.json` | `{protocol}`/`{host}` templating |
| `overlapping-paths-3.0.json` | `/users/{id}` vs `/users/me` |
| `kube-openapi.json (Stage 3)` | Real-world large spec (~3 MB) — torture test |

For each, the expected operation count is committed alongside the fixture. Any change to the count is a regression until reviewed.

### Original proposed silent-drop detection

The original proposal called for a parser result containing imported operations and parser-level skipped operations with reasons. Its proposed tests would reconcile imported and skipped counts and compare imported operations with the reference parser. These were design criteria; they should not be interpreted as verified guarantees of the shipped implementation.

### Original `--dry-run` verification intent

The original design intended dry-run output to help users inspect and compare operation enumeration. The shipped dry-run provides parser enumeration visibility; it does not guarantee that no operations are omitted, nor does it account for runtime target-construction or scan failures.

## Failure modes addressed by the original design

The following are original design goals. They should not be read as a claim that every goal has been fully demonstrated by the shipped implementation.

1. **Silent parser drop** — differential tests against `prance` fail loudly; silent-drop invariant test fails; `--dry-run` shows the user the count.
2. **`$ref` infinite loop** — reference resolution is depth-limited and cycle-detected. A cycle logs skipped and stops, not hangs.
3. **Large spec OOM** — the Kubernetes spec is 3 MB. Parser streams paths rather than loading a fully resolved tree. Peak memory bounded to ~100 MB above baseline. Test asserts this.
4. **Server template with no default** — logged as skipped with reason, not crashed on, not silently defaulted to localhost.
5. **Overlapping path collapse** — the operation list preserves both `/users/{id}` and `/users/me`. The scan runs both. The differential oracle decides which is actually vulnerable. Parser does not "helpfully" dedupe.

## Effort

| Stage | Effort |
|---|---|
| 1 — skeleton | 3–4 hours |
| 2 — `$ref` | 6–8 hours |
| 3 — 2.0 adapter | 3–4 hours |
| 4 — server templates | 1–2 hours |
| 5 — parameter dispatch | 4–6 hours (+1–2h body amendment) |
| 6 — CLI + integration | 7–9 hours (revised from 2–3h) |
| **Total** | **~4 working days (revised)** |

Not counting test fixture collection (a few hours), CI wiring, and the inevitable first real-world-spec bugs that emerge post-merge.

Actuals for Stages 1-4 were not recorded. The row values for those stages remain the original estimates, not measurements; a future session should append an actuals table rather than infer one.

## Revisit triggers

- If a user's real-world spec fails to import and the failure is not fixable without major parser rework — new ADR, new design
- If OpenAPI 3.1 (released 2021, increasingly adopted) diverges enough to justify its own stage — new ADR
- If Postman collection import is requested by 3+ named users — new ADR (separate format, separate effort)

## What this ADR does not promise

- It does not promise 100% coverage of every legal OpenAPI construct. Parser/importer-level unsupported constructs should be surfaced through notes or skipped-operation reasons where implemented. Runtime target failures are logged and skipped without necessarily marking the merged summary incomplete; this remains a known accounting gap.
- It does not promise correctness on malformed specs. If the spec does not validate against the OpenAPI schema, the parser will reject it with a clear error. Validating the spec is a separate tool (openapi-spec-validator, prance).
- It does not promise the differential oracle works well on APIs. OWASP Benchmark has 2,740 cases designed for differential detection. A real-world API may behave differently. The parser delivers targets; whether the oracle finds vulnerabilities on them is a separate question, measured by running it against DVWA's API, crAPI, and the Juice Shop REST endpoints.
