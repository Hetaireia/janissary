# Track C — Schema (v2.1)

Amendment 24 reference: `docs/AMENDMENT-24.md`. This file defines the
data model for the real-world negatives campaign. It is the contract
between the corpus builder, the runner, and the scorer.

## `apps.json` — app-level metadata

One object per app. Keys are stable app identifiers used everywhere
else (`cases.csv`, run directory names, `score.json`).

| Field | Type | Required for dev | Required for locked | Notes |
|---|---|---|:---:|---|
| `base_url` | string | yes | yes | `http://host:port` (no trailing slash) |
| `healthcheck` | string | yes | yes | Path that returns <500 when app is ready |
| `image_digest` | string\|null | no | **yes** | `sha256:...` of the pinned container. `null` = app is not pinned; dev-only |
| `security_level` | string\|null | no | **yes** if app has a level dial | e.g. `"low"` for DVWA |
| `login` | object\|null | no | yes | see below |
| `login.url` | string | | | login form URL (relative to `base_url`) |
| `login.data` | object | | | form fields |
| `login.post_url` | string | | | post-login endpoint (e.g. `security.php`) |
| `login.post_data` | object | | | form fields for `post_url` |
| `login.cookies` | string[] | | | cookie names to preserve across scans. Empty = preserve all |
| `login.setup` | string[] | | | extra paths to hit after login (e.g. `setup.php`) |
| `safe_endpoints` | string[] | yes | yes | app paths with no known vuln. Presence of these in `cases.csv` with `safe=true` is what generates TN/FP |
| `known_vulnerable` | object[] | yes | yes | `[{"path": "...", "class": "sqli"}, ...]` — summary of documented vulns. Used for corpus design; actual trials live in `cases.csv` |
| `trial_class` | string[] | yes | yes | categories the app is expected to exercise, e.g. `["sqli","xss"]`. Any subset of: `sqli, sqli_blind, xss, cmdi, traversal, ssrf, ldapi, xpathi, weakrand, securecookie, trustbound` |
| `excluded` | bool | yes | yes | `true` = documented but not scored (e.g. WAF-training apps). Filtered out by the campaign aggregator, not by the runner |

## `cases.csv` — trial-level data

One row per trial. **A trial is `(app, path, method, param)`.**

| Column | Type | Notes |
|---|---|---|
| `app` | string | must key into `apps.json` |
| `path` | string | may include full query string, e.g. `/vulnerabilities/sqli/?id=test&Submit=Submit` |
| `method` | `GET`\|`POST` | passed to `janissary scan --method` |
| `param` | string | parameter name the scanner fires at |
| `vuln_class` | string | trial category (informational); used as fallback for `expected_finding_class` |
| `safe` | `true`\|`false` | `true` = this trial expects **no findings**. Any finding on it is FP |
| `expected_finding_class` | string | class a finding must carry to count as TP. Empty for safe trials |
| `notes` | string | free-form. Structured suffix: `json_body:<path>`. |
| `inject_in` | string | optional; auto/query/body/cookie/header/param-name/json-body/path. Empty=auto. path mode: {param} in path + baseline_value. |
| `baseline_value` | string | optional; baseline sample value for inject_in=path. |

**Row semantics:**

- `safe=false`: the trial is a known-vulnerable endpoint. A finding whose
  `class` == `expected_finding_class` and whose URL path matches the
  trial's path counts as **TP**. If no matching finding, **FN**.
- `safe=true`: the trial is a known-safe endpoint. If **any** finding
  fires on the trial's URL, it counts as **FP**. If no findings, **TN**.

The FP rate reported under Amendment 23 Item A is computed over the
`safe=true` rows only (see AMENDMENT-24, "Adjudication").

## Scoring model (`score.py`)

Per-trial accounting. For each row in `cases.csv`:

1. Attribute findings to trials by URL path (two-priority):
   - Priority 1 (literal): endswith() for cases without {param}.
   - Priority 2 (placeholder): [^/?#]+ per {param} placeholder,
     only when priority 1 matches no case.
2. If `safe=true`:
   - any matching findings → **FP** (1 per trial, regardless of how many findings)
   - no matching findings → **TN**
3. If `safe=false`:
   - matching findings include one with `class == expected_finding_class` → **TP**
   - matching findings exist but none have the expected class → **FP** (per the rules in Amendment 24; a real finding of the wrong class is still a false claim)
   - no matching findings → **FN**

Findings whose URL does not match any trial are counted as `unmatched_findings` in `score.json` and do not enter TP/FP/FN/TN. This includes findings on URLs the runner was never asked to scan (should not happen; flagged for diagnosis if it does).

Metrics:

- Precision = TP / (TP + FP)
- Recall = TP / (TP + FN)
- F1 = 2·P·R / (P + R)
- FP rate on safe trials = FP / (FP + TN) — **this is the raw fraction, not
  the interval**. Cluster-aware Clopper-Pearson is computed at the corpus
  level by a separate layer.

## Backwards compatibility

The v1 schema had no `safe`, `expected_finding_class`, or `image_digest`.
Existing rows in `cases.csv` were all vulnerable trials; backfilled with:

- `safe = false`
- `expected_finding_class = <vuln_class>`

`score.py` retains a fallback: if `expected_finding_class` is missing,
it uses `vuln_class`. If `safe` is missing, it uses `false`.

The `apps.json` v1 schema only had `base_url`, `healthcheck`, `login`.
Existing apps are backfilled with `image_digest=null`, `security_level=null`,
`excluded=false`, `trial_class=[]`, `safe_endpoints=[]`,
`known_vulnerable=[]`, `login.cookies=[]`, `login.setup=[]`.

### v2 -> v2.1

Additive: cases.csv gained optional inject_in and baseline_value columns. Empty values = v2 behavior. Attribution adds placeholder matching (priority 2); literal unchanged (priority 1).

## Locked-run requirements

Before an app is locked (Amendment 24 Phase 5):

- `image_digest` must be non-null OR `image_digests` must be a non-empty array (see Multi-container apps below)
- `security_level` must be non-null if the app has one
- `safe_endpoints` must be non-empty
- `known_vulnerable` must be non-empty
- `trial_class` must be non-empty
- Every row in `cases.csv` for that app must have `safe` and
  `expected_finding_class` set (safe rows have empty `expected_finding_class`)

**Multi-container apps** (e.g. crAPI - 10 services): apps whose trial behavior depends on more than one container use `image_digests` (array of `image:tag@sha256:...` strings) instead of the scalar `image_digest`. Pinning one image would falsely claim reproducibility of behavior driven by the others. Every running container in the app's deployment must appear in the array.

**Negative-only apps** (e.g. gitea, nextcloud): apps included in the corpus solely to measure FP rate have no documented vulnerabilities by design. They are exempt from the `known_vulnerable` and `trial_class` non-empty rules, provided `safe_endpoints` is non-empty. Their FP rate is the whole point.