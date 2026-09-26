---
title: "We refuse to emit a finding from a single response"
published: false
description: "How differential gating killed false positives in JANISSARY at the architecture level — and what we gave up to get there."
tags: security, dast, false-positives, tooling
---

# We refuse to emit a finding from a single response

Every DAST tool I've used has the same failure mode, and it isn't detection.
It's trust.

You run a scan. You get 200 findings. You triage 30. You discover 22 are
noise. You stop reading findings. The tool that was supposed to save you
time now costs you time, and the next time you run it you skim.

I built JANISSARY around one rule: **a finding that isn't a difference is a
guess.** Here's what that means in practice, why it's harder than it sounds,
and what we gave up to ship it.

---

## What "differential" actually requires

A finding should never be emitted from a single response. That sounds like a
one-line policy. It's actually four engineering problems stacked on top of
each other.

**First, you need a baseline you can trust.** Before probing, JANISSARY
sends N benign requests to the same endpoint, same parameter, same headers.
If the baseline isn't stable — if the response time varies by more than a
threshold, if the body length jumps between runs — the tool refuses to
engage the timing gates and tells you so:

```
[q] baseline is static - timing gates disabled
```

That's not a bug, it's the tool being honest. A flaky baseline produces
flaky deltas, and flaky deltas produce false positives. Better to run
fewer gates than to run wrong ones.

**Second, you need a probe that produces a *reproducible* delta.** Firing
a payload and seeing the response change isn't enough. The change has to be
consistent, tied to the payload, and not explained by normal variance.

**Third, you need to distinguish a delta from a WAF block.** Cloudflare
returns a 403 with a challenge page — that's not an SQL injection, that's
Cloudflare doing its job. JANISSARY's pacer watches for those signatures
and feeds them into the differential gate so a block doesn't get reported
as a vulnerability.

**Fourth, you need to normalise time-varying responses.** CSRF tokens,
nonces, timestamps, session IDs, dynamic ad copy — the response body
changes constantly for reasons that have nothing to do with your payload.
Comparison has to strip those out or the gate fires on everything.

Each of those is a separate subsystem. Together, they produce output that
looks like this:

```
  Findings:
    F-001  CRITICAL sqli:sql_injection  (param=q)
           - [sql_single_quote] db_error: SQLITE error signature matched
           - [sql_single_quote] status_change: Baseline 200 -> Payload 500
           - [sql_or_1eq1]      length_anomaly: Response 3.2x baseline
           - [sql_union_null]   status_change: Baseline 200 -> Payload 500
           - [sql_union_null]   length_anomaly: Response 8.3x baseline
           - [sql_sleep_mysql]  status_change: Baseline 200 -> Payload 500
           - [sql_sleep_pg]     status_change: Baseline 200 -> Payload 500
           - [sql_sleep_pg]     length_anomaly: Response 4.7x baseline

    F-002  LOW      sqli:reflection  (param=q)
           - [sql_single_quote] payload_reflected: Payload reflected (raw)
```

Eleven signals. **One bug.** Every piece of evidence for `F-001` points at
the same SQL injection, so JANISSARY groups them. `F-002` is a different
root cause — reflection — and stays separate.

The first version of this scan reported nine findings. A reviewer looking
at the summary saw `9 findings` and moved on. Now they see `2 groups` and
read the one that matters.

---

## What we gave up

We gave up speed.

A baseline-gated scan runs the target 3–5x more than a naive scanner. On a
100-endpoint target, that's the difference between a 4-minute scan and a
12-minute scan. We also gave up recall: when the baseline is unstable, we
disable the gates and miss findings rather than flood the report with
maybes.

We think that's the right trade. Here's the number that convinced us:

> On two local vulnerable Flask endpoints (SQL injection and reflected
> XSS), JANISSARY emitted **23 findings across 3 groups** — and the
> SQL-injection scan returned the *identical* finding set across two
> back-to-back runs. A naive scan of the same endpoints produces 23
> signals with no grouping, so the same bug shows up as 11 separate
> findings, and triage starts at the wrong number.

That last word — *reproducible* — is the one most DAST tools can't claim.
Run the same scan twice and compare the output. If your tool's finding set
changes between identical runs, it isn't gating on differences, and you're
paying triage tax on every scan.

---

## What this means if you're evaluating DAST

Ask your current tool one question: **if I run this scan twice, do I get
the same findings?**

If the answer is no, differential gating isn't in it, and the tool is
producing guesses. That's not a moral judgment — a guess is useful if
you're hunting for leads. It's a problem if you're handing the output to a
client, an auditor, or your own backlog and expecting it to be actionable
without re-verification.

JANISSARY is the precision tool in your toolbox. It won't find everything.
It will only tell you what it can prove.

```
pip install janissary
```

[github.com/Damn-Infidel/janissary](https://github.com/Damn-Infidel/janissary)

---

*JANISSARY is a dual-use security testing tool. Run it only against
systems you own or have prior written permission to test. See the
[Terms of Use](https://github.com/Damn-Infidel/janissary/blob/main/LEGAL.md).*