# ADR-030 — OpenAPI / Swagger import (BL-5)

**Status:** Proposed (design)
**Parent:** ADR-021 (crawler placement), ADR-016 (verified/discovery vocabulary)
**Backlog:** docs/DETECTION-BACKLOG.md BL-5
**Scope:** Design only. No code in this ADR.

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

## Functional requirements

When `--openapi PATH` is supplied:

1. JANISSARY parses the spec without crashing on any valid 2.0 or 3.0 spec
2. It enumerates every operation (path × method) declared in the spec
3. For each operation, it constructs one or more scan targets — one per declared parameter
4. For path parameters, it substitutes the parameter name into the path and scans the substituted URL
5. For query/header/cookie parameters, it appends/attaches and scans
6. For request-body parameters (JSON), it uses the existing `--json-template` machinery
7. It logs at the top of the scan: `[runner] imported N operations from spec`
8. It logs any operation it could not use: `[runner] skipped M operations: <reason>`

## Non-functional requirements

These matter more than the functional ones.

1. **No silent drops.** Every operation in the spec either becomes a scan target or is logged as skipped with a reason. Never silently omit.
2. **Operation count is verifiable.** A `--dry-run` mode prints the enumeration (paths, methods, parameters) without scanning. The user can diff this against their own reading of the spec.
3. **The parser is measured against a reference.** Every parser test runs the same spec through `prance` (or `openapi-spec-validator`) and asserts operation-count agreement. Silent drops become loud failures.
4. **The feature is disabled by default.** No user gets this until `--openapi` is passed. Staged rollout: merge behind the flag, watch CI, then announce.
## Staged implementation

Six stages, one commit each. Each stage is independently verifiable. Do not start stage N+1 until stage N's tests are green and the differential count against `prance` matches.

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

**Dispatch layer shipped 2026-11-11 (7597258).** Operation gains parameter_locations, populated from each resolved parameter in key. New dispatch.py exposes build_scan_targets(op), returning one target per distinct location: Scanner.inject_in is a single mode per instance, so an operation declaring path, query, and header parameters requires three scanners and therefore three targets. Mode map: path->path, query->param-name, header->header, cookie->cookie, body->auto. Parameterless operations yield one target with mode auto. Unsupported locations (Swagger 2.0 formData) append a parser note and are excluded. Stage 5 is the transformation only; the loop that constructs one Scanner per target and drives them is Stage 6, and Stage 6 effort is revised upward from 2-3h to account for it.

**Stage 5 amendment, 2026-11-11 (body targets).** As shipped, body locations emitted inject_in='json-body' with json_template=None. Scanner.__init__ rejects that combination, so any operation declaring a body parameter produced a target that raised ValueError on construction. The transformation was internally consistent (dispatch.py imports no scanner, by design), but the join went untested: six dispatch tests asserted emission, and none constructed a Scanner. Body locations now emit inject_in='auto', params=[], and a note; the endpoint is still scanned, without named body-param injection. New test_openapi_dispatch_consumption.py constructs a Scanner from every emitted target type, so the join is covered. Injecting body parameters by name requires request-body schema capture in the importer, which Operation does not carry; that is filed separately, not folded into Stage 6.

**Stage 5 query-dispatch correction, 2026-11-13.** The original Stage 5 dispatch record above incorrectly states that query parameters map to `param-name`. The current implementation maps OpenAPI `query` parameters to Scanner `inject_in="query"` (`src/janissary/importers/dispatch.py`). This is intentional: `query` preserves the declared parameter name and injects the payload as its value (`?limit=PAYLOAD`); `param-name` instead injects the payload as the parameter name (`?PAYLOAD=limit`). Verification: `tests/unit/test_openapi_dispatch.py`, `tests/unit/test_openapi_dispatch_consumption.py`, `tests/integration/test_openapi_query_dispatch.py` — **15 passed** on 2026-11-13. The integration tests assert the actual outgoing query strings. No Scanner or dispatch code change was required. This resolves the query name/value dispatch concern; it does not resolve the separately documented request-body limitation.

### Stage 6 — CLI wiring, `--dry-run`, integration

Add `--openapi PATH` and `--dry-run` flags. Wire to scanner. Integration test: dry-run on a public spec, count operations, scan the smallest 3 operations against a mock. Assert no crashes and no silent drops. **Revised estimate: 7-9 hours** (was 2-3h). The revision reflects what Stage 5's description implied but did not need: extracting the CLI's Scanner construction into a helper, the loop that builds one Scanner per build_scan_targets output, aggregation of N ScanSummary objects, and the body-target amendment above.

## Test strategy

### Differential testing from day one

Every parser test runs the same fixture through two parsers — JANISSARY's new parser and `prance` — and asserts they agree on operation count, parameter count, and per-operation parameter names. Disagreement is a test failure, not a warning.

**Exception, 2026-11-11.** The Kubernetes torture test has no prance differential. prance cannot parse the Kubernetes spec: its ref discoverer treats every $ref key as a URL reference, and Kubernetes uses $ref as a JSON Schema property name (ObjectReference.ref -> type string), so prance raises AttributeError: dict object has no attribute decode inside prance.util.resolver._discover_refs. JANISSARY resolves refs only in path items and parameter entries, never inside schemas, so it is unaffected. The kube test asserts a measured operation count (1172) and a memory ceiling instead, and documents the prance failure in its docstring. All other fixtures run the full prance differential unchanged.

`prance` is a mature OpenAPI parser used by Bravado and other API tooling. It supports 2.0 and 3.0. It is a test dependency only (add to `pyproject.toml` under `[project.optional-dependencies] dev`), not a runtime dependency.

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

### Silent-drop detection

Add a parser mode that returns both `imported: list[Operation]` and `skipped: list[tuple[str, str]]` (path+method, reason). Tests assert:

- `len(imported) + len(skipped) == total_paths * total_methods_in_spec`
- `prance`-counted operations all appear in `imported` (none dropped)

If a real-world spec fails the differential test, that is a bug to fix before merging, not a case to add to a skip list.

### `--dry-run` verification

Dry-run prints operations to stdout. The user can diff against their own reading of the spec. This is the human-visible guarantee that silent drops did not happen.

## Failure modes this design actively prevents

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

- It does not promise 100% coverage of every legal OpenAPI construct. It promises no *silent* drops. If a construct is unsupported, the user sees it skipped with a reason.
- It does not promise correctness on malformed specs. If the spec does not validate against the OpenAPI schema, the parser will reject it with a clear error. Validating the spec is a separate tool (openapi-spec-validator, prance).
- It does not promise the differential oracle works well on APIs. OWASP Benchmark has 2,740 cases designed for differential detection. A real-world API may behave differently. The parser delivers targets; whether the oracle finds vulnerabilities on them is a separate question, measured by running it against DVWA's API, crAPI, and the Juice Shop REST endpoints.
