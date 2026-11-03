# Bootstrap and Corpus Invocation Guide

**Scope.** This document covers (a) getting the corpus applications into a
testable state, and (b) the correct `janissary scan` invocations for each
injectable-endpoint shape. It does not cover installation, configuration, or
CLI surface outside injection.

## Corpus setup

### VAmPI: `/createdb` is not idempotent

VAmPI's `/createdb` route runs `drop_all()` followed by a re-insert. If the
insert fails partway (observed failure mode: `bookTitle` unique-constraint
collision mid-insert), the database is left half-seeded and the app returns
500 on subsequent requests.

**Recovery:** re-run the `/createdb` request one or two more times until it
returns 200. Do not assume a single call succeeded.

**Source:** FN-11, `docs/PHASE-6-PLAN.md`.

## Injectable-endpoint shapes

`janissary scan --inject-in` accepts eight values. The choices list is in
`src/janissary/cli.py`; the enforced whitelist is in
`src/janissary/engine/scanner.py`.

| `--inject-in` | Payload placement | Requires | Exercised by corpus |
|---|---|---|---|
| `auto` (default) | query string for GET; body for POST | - | yes (default) |
| `query` | URL query string | - | no (equivalent to `auto` on GET) |
| `body` | HTTP body, form-encoded | - | no |
| `json-body` | HTTP body, JSON-encoded | `--json-template PATH` with `{{PAYLOAD}}` | no |
| `path` | URL path segment | `{param}` in `-u`; `--baseline-value VAL` | yes (1 case) |
| `header` | HTTP header value | - | no |
| `cookie` | Cookie value | - | no |
| `param-name` | The parameter name itself | - | no |

**"Exercised by corpus"** means at least one case in
`benchmark/track_c/cases.csv` sets that `inject_in` value. Shapes not
exercised by the corpus are supported by code but have not been verified
end-to-end against a live target in a benchmark run.

For automated Track C runs, the runner builds invocations from the
`inject_in` and `baseline_value` columns in `benchmark/track_c/cases.csv`;
see `benchmark/track_c/runner.py` for substitution logic.

### Why shape matters: `--inject-in path` (worked example)

VAmPI's scored SQLi endpoint is `/users/v1/{username}` with injection-location
`path` (`cases.csv` row `path_param_sqli`). Query-string injection against
this route produces 0 findings - correctly - because the payloads never
reach the SQL.

Verified correct invocation (bash):

    janissary scan \
      -u "http://127.0.0.1:5000/users/v1/{username}" \
      -p username \
      --inject-in path \
      --baseline-value name1

On PowerShell, replace each line-continuation backslash with a backtick.

Findings produced (all CRITICAL): `sql_single_quote`, `sql_union_null`,
`sql_sleep_mysql`, `sql_paren_quote`, `sql_paren_double`, `sql_paren_union`,
`sql_paren_or`, `sql_hash_comment`, `sqli_quote_oracle`.

**Why both flags are required:**
- The URL must contain `{username}` - the value passed to `-p username` is the
  placeholder key, and each payload is substituted into that segment.
- `--baseline-value name1` provides a known-good segment so the scanner can
  distinguish payload-driven responses from baseline. Without it, there is no
  meaningful delta.

**Source:** FN-6 resolution, `docs/PHASE-6-PLAN.md` (verified 2026-11-01).

### `--inject-in json-body`

Requires a `--json-template` file containing a `{{PAYLOAD}}` placeholder, e.g.:

    { "email": "{{PAYLOAD}}", "password": "x" }

The scanner substitutes the payload at `{{PAYLOAD}}` on each request. Not
exercised by the current corpus; the shape exists for JSON APIs where the
vulnerable parameter is a JSON body field.

**Source:** `src/janissary/cli.py` help text; `docs/PHASE-4-PLAN.md`.

### `--inject-in auto` (the default)

For GET requests, resolves to query injection. For POST requests, resolves to
body injection. Use `auto` unless you have a specific reason to force a
shape.

**Do not use `auto` on a path-injection endpoint.** `auto` resolves to `query`
for GET; query injection cannot reach a path segment. This was the root cause
of FN-6's 90-minute false-negative investigation on VAmPI.

## See also

- `docs/PHASE-3-PLAN.md` - path injection design and scanner changes
- `docs/PHASE-4-PLAN.md` - json-body design
- `docs/PHASE-6-PLAN.md` - FN-6 resolution with the verified invocation
- `LIMITATIONS.md` - known *detection* gaps (distinct from invocation-shape mismatches)
