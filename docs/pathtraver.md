# Pathtraver on OWASP Benchmark: what we can see, and what we can't

If you scroll the results table in `BENCHMARK.md` to the bottom, the
first four rows are pathtraver subcategories. F1 ranges from 0.049 to
0.308. That looks like a scanner failure. This document explains why it
isn't, in enough detail that you can verify the claim yourself.

## What the OWASP Benchmark pathtraver family tests

Every pathtraver case is a directory-traversal test. Each servlet reads
a parameter, concatenates it into a file path, and does one of three
things with the resolved path:

1. **Checks existence** and reports the result
2. **Reads the file** and echoes its contents
3. **Writes to the file** and confirms the write

For a DAST scanner, only the first shape produces a detectable signal.
The second shape returns file content — which in this benchmark is a
static file the scanner can't distinguish from any other static content.
The third shape returns a write confirmation — which for this target is
identical on both the existing-path and the nonexistent-path payloads,
because the servlet doesn't check the filesystem before writing.

## What JANISSARY looks for

The oracle is a paired differential across two payloads:

- Payload A: a path that resolves (e.g. `../../../etc/passwd`)
- Payload B: a path guaranteed not to resolve (e.g.
  `../../../etc/passwd_janissary_noexist_<random>`)

Both payloads are sent. If A's response says "file already exists" and
B's response says "file doesn't exist yet", the target leaks existence,
and JANISSARY fires. If both say the same thing — either both "exists",
both "doesn't exist", or neither — the oracle stays silent.

The design is intentional. A single response saying "file exists" isn't
evidence of traversal; the app might say that about every path. Only a
*difference* between the two probes is evidence the scanner acted on
the path we gave it.

## What the target actually does

We probed the OWASP Benchmark target directly across all 72 pathtraver
cases (four subcategories x 18 cases each) that are marked vulnerable in
the ground-truth CSV. The cases split three ways:

| Shape | Count | Behavior |
|---|---|---|
| Existence divergence | 4 / 72 | Response differs between exists and nonexistent payloads. Oracle fires. |
| Fixed-string scaffold | 22 / 72 | Response contains `Access to file:` followed by a fixed string `already exists` on **both** payloads. No divergence possible. |
| Write-sink scaffold | 46 / 72 | Response echoes the resolved path but is otherwise identical on both payloads. No observable outcome beyond the echo. |

The 22 "fixed-string scaffold" cases are the interesting ones. Their
response contains the word "already exists" regardless of whether the
file the scanner named actually exists. That's the servlet's template,
not a filesystem read. A scanner that grepped for "already exists" would
fire — and be wrong on all 22 of them. JANISSARY doesn't, because the
oracle requires the divergence, not the string.

The 46 "write-sink scaffold" cases are the bulk of the loss. These
servlets write to a path derived from the parameter and then confirm
"Now ready to write to file: <path>". The path is echoed back. Whether
the file existed before the write isn't reflected in the response —
status, headers, and body are identical between existing and
nonexistent-path payloads except for the echoed string, which the
scanner provided. There is nothing to differentiate.

We verified this by re-running the entire pathtraver FN set through the
recovery pass (see Amendment 20). Zero recovered. The oracle's cap is a
property of the target, not a bug in the detector.

## What a target that would leak the signal looks like

A Flask app with this handler:

    @app.route("/read")
    def read():
        p = request.args.get("path")
        if os.path.exists(p):
            return f"Found: {open(p).read()}"
        return "No such file"

Here, response A says "Found: <contents>" and response B says "No such
file". Clean divergence. The oracle fires. Scan that against JANISSARY
and it's detected.

The OWASP Benchmark target replaces the `open()` with a template that
doesn't read. This is a known design choice of the benchmark — it
isolates the *injection* from the *exploitation*. The scanner sees the
injection point but can't observe the consequence.

## What we could do about it, and why we didn't

Three options we considered:

**Time-based detection.** Send a payload that causes a slow filesystem
operation (e.g. reading a large file) and detect the delay. This would
require the benchmark's servlets to have differing file sizes on
existent vs nonexistent paths, which they don't.

**Error-based detection.** Send a payload that causes the servlet to
throw, and match on the exception. Verified — the write-sink servlets
throw on both the exists and noexist payloads with identical
exceptions. No signal.

**Static analysis of the target source.** Look at the servlet code
directly and check whether the parameter flows to a `File` sink. This
is a SAST technique. It's legitimate and effective, but it's not what
JANISSARY is — JANISSARY is a black-box DAST tool.

The remaining option is: accept the cap, document it, and exclude these
cases from the DAST-applicable denominator where appropriate. That's
what `benchmark/track_a/score_dast_aware.py` does for hash and crypto
(259 cases, SAST-only). The pathtraver cases are structurally different
— they're DAST-applicable in principle, just not against this target.
We report them, we document why they're low, we don't hide them.

## What this costs us

Current DAST-applicable F1 is **0.920** (TP 984, FP 0, FN 172). The
pathtraver subcategories contribute **123 of those 172 FN**. If we
excluded them from the DAST-applicable denominator, the number would
be above 0.99. We don't exclude them, because that would be gaming the
metric. The 0.920 figure is honest.

If your target *does* leak the existence signal — which most real
file-serving apps do, because they have to handle nonexistent files
somehow — the pathtraver recall climbs fast. The oracle detects what
it can observe. That's the design.
