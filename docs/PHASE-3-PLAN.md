# PHASE-3-PLAN: Path-Parameter Injection (Phase 1c)

**Status:** design -- awaiting implementation
**Parent:** `docs/AMENDMENT-24.md` (Phase 3 harness extension)
**Predecessors:** Phase 1a (JWT auth, `5f54032`) and Phase 1b (class-aware attribution, `cbd33cd`)

## Problem

The Track C runner builds scan URLs as `base_url + case.path` and passes `-p case.param` to `janissary scan`. The scanner `--inject-in` flag supports `auto, query, body, cookie, header, param-name`. None of these can inject a payload into a path segment such as `/books/v1/{book_title}` where the vulnerable parameter is not a query parameter, body field, cookie, or header.

This blocks testing of:

- VAmPI `/books/v1/{book_title}` -- known SQLi in path parameter
- Any future app whose vulnerable endpoint places the parameter in the URL path
- REST APIs with resource-by-name routes

## Design decisions

### 1. Injection model

When `--inject-in path` is set:

- The target URL contains `{param}` where `param` is the value passed via `-p`.
- Scanner replaces `{param}` with the payload on each request.
- No query string, body, cookie, or header modification is made for that parameter.

Example: `-u "http://host/books/v1/{book_title}" -p book_title --inject-in path`

### 2. Scanner change

Location: `src/janissary/engine/scanner.py`

a) Add `path` to the valid `inject_in` choices in `__init__` (currently `{auto, query, body, cookie, header, param-name}`).

b) Add a `path` branch to `_request()` before the default query fallthrough:

```python
if self.inject_in == "path":
    path_url = url.replace(f"{{{param}}}", quote(value, safe=""))
    return self.session.get(
        path_url,
        headers=self._headers(),
        timeout=self.timeout,
        allow_redirects=False,
        proxies=self.proxies,
    )
```

c) Validate that `{param}` placeholder is present in the URL when `inject_in=="path"`; raise a clear error otherwise.

### 3. Runner change

Location: `benchmark/track_c/runner.py`

a) New config lookup: `case.get("inject_in", "").strip()`.

b) When non-empty, append `--inject-in <value>` to the janissary scan command. Default behavior (auto) unchanged when empty.

c) URL construction: for path-mode trials, `case["path"]` contains the placeholder (e.g. `/books/v1/{book_title}`). The runner does not append query parameters for these rows.

d) Baseline value: VAmPI path trials need an initial value for the `{book_title}` placeholder.

   - Option A: add column `baseline_value` to `cases.csv`. Explicit, simple.
   - Option B: use a convention (e.g. always `test` for path-mode unless overridden). Fragile.
   - **Decision:** Option A. Explicit per-trial baseline.

### 4. cases.csv schema

Add two columns: `inject_in` and `baseline_value`.

- Existing rows: both empty. Behavior unchanged.
- Path-param trials: `inject_in=path`, `baseline_value=<known-good value>`, `path` contains `{param}` placeholder.

Column addition is additive. Scorer, validator, and old runs unaffected (columns absent = empty = no change).

### 5. Version bump

Scanner source change adds a new CLI capability. Per SemVer:

- 7.5.1 -> 7.6.0 (minor version bump, new flag value).
- Changelog entry: `--inject-in path` mode for path-segment injection.

### 6. Test target

VAmPI `/books/v1/{book_title}`:

- Requires JWT auth (Phase 1a support present).
- Known SQLi vulnerability in book_title parameter.
- Baseline title: `bookTitle23` (from `/books/v1` list).
- Path SQLi payload: single-quote character (URL-encoded as `%27`).

**Verification required before adding as test trial:** with JWT auth via `--bearer`, the baseline request `/books/v1/bookTitle23` must return 200 with book data, and the payload request `/books/v1/%27` must return a different body (SQL error, 500, or content change). This is the same discipline as Juice Shop 20261029: verify vulnerability before treating as trial.

### 7. Rollback

- Scanner: revert to 7.5.1 tag. `path` mode is additive; removing it does not affect existing modes.
- Runner: revert to previous commit. `inject_in` and `baseline_value` columns absent = current behavior.
- cases.csv: empty `inject_in` column = no change.

## Test plan

1. **Standalone scanner test:** `janissary scan -u "http://127.0.0.1:5000/books/v1/{book_title}" -p book_title --inject-in path --bearer <jwt>` against VAmPI. Expected: baseline 200 with book data, payload returns different body (SQL error or content change). Verify via `--jsonl`.
2. **Runner integration:** add VAmPI path-param trial to cases.csv with `inject_in=path`, `baseline_value=bookTitle23`. Run `runner.py --app vampi`. Expected: 6 trials (5 safe + 1 vuln), tp=1, fp=0, fn=0, tn=5.
3. **Regression:** all 6 current-case-set runs fresh-scored unchanged (dvwa x2, juice-shop, gitea, nextcloud, vampi).
4. **Amendment 24:** document the change with before/after measurement.

## Anti-goals

- Not adding POST path injection (different code path, defer to 7.7).
- Not adding path injection to Nuclei or ZAP arms (separate tool configs, out of scope).
- Not auto-generating path placeholders (manual annotation is safer).
- Not modifying the `path` column format for existing trials.

## Estimated effort

- Scanner change: ~15 lines, 1 command (edit + syntax check + revert-if-broke)
- Scanner standalone test: 1 command
- Runner + cases.csv schema: 1 command
- Live test on VAmPI: 1 command
- Amendment 24 doc: 1 command
- Total: 5 commands, possibly split across sessions.

## Burned-data rule

VAmPI path SQLi is a **dev** trial. If `--inject-in path` implementation is found wrong later, the fix is committed as a new version, the path trial is re-run fresh, and both results are published.

## See also

- `docs/AMENDMENT-24.md` -- parent amendment
- `docs/WORKFLOW.md` -- process discipline
- `benchmark/track_c/SCHEMA.md` -- cases.csv schema (needs update when this lands)
