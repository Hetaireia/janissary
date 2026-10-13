# Launch Assets — 14 October 2026 (Wednesday 8 AM ET)

Copy from here on launch night. Do not edit unless a number changes.

---

## Timeline

- **Wed 8:00 AM ET (Wed ~11 PM AU):** HN Show HN submission
- **Immediately after:** HN first-comment (benchmarks)
- **Wed 8:15 AM ET:** r/AskNetsec + r/blueteamsec posts
- **Wed 10:00 AM ET:** X thread + OWASP Slack (if invite arrived)
- **Wed 6:00 PM ET:** HN evening check-in

---

## 1. HN submission

**Title:**
Show HN: JANISSARY – DAST that only reports reproducible differences

**Body:**
Every DAST tool I've used has the same failure mode: not detection, but trust. Findings that can't be reproduced cost more to triage than they're worth, and after a while you stop reading them. JANISSARY gates every finding on a baseline comparison — nothing is emitted from a single response — and groups multiple payload confirmations of the same bug into one finding with attached evidence.

https://github.com/Hetaireia/janissary

Dual-use security tool; run it only against authorised targets.

**First comment (post yourself, immediately after submitting):**
Benchmarks, since someone will ask:

On the OWASP Benchmark DAST-applicable subset (2,740 cases minus the crypto/hash cases that only a source-aware tool can observe):
F1 0.920, precision 1.000, recall 0.851, 984 TP, 0 FP, 172 FN.
Eighteen categories at F1 1.000.

The precision figure is the design claim — every oracle requires evidence of a specific kind, not a pattern match. DB error signatures, session sink echoes, raw XSS past its trailing char, paired differentials on file-existence. Nothing fires from a single response.

Full write-up (differential engine, what we gave up, comparison against Nuclei and ZAP): https://dev.to/janissary/we-refuse-to-emit-a-finding-from-a-single-response-3bld

The weakest category is path traversal (F1 0.049–0.308). Documented honestly in docs/pathtraver.md — it's a property of the benchmark target, not a scanner gap.

Reproduce: `pip install janissary`

---

## 2. r/AskNetsec post

**Title:**
JANISSARY — differential DAST that only emits reproducible findings (F1 0.920, precision 1.000 on OWASP Benchmark)

**Body:**
Most DAST tools report findings from a single response — anything that looks suspicious becomes a candidate. The result is triage tax: you triage 30, discard 22, stop reading findings.

JANISSARY gates every detection on a baseline comparison. Nothing is emitted from a single response. Every oracle requires evidence of a specific kind:

- DB error signature matched against a compiled pattern set
- Session sink echo of a per-scan random marker
- XSS payload reflected raw past its trailing character
- Paired differential on a file-existence oracle (exists vs guaranteed-nonexistent payload)

On the OWASP Benchmark DAST-applicable subset:
  F1 0.920, P 1.000, R 0.851
  984 TP, 0 FP, 172 FN
  18 categories at F1 1.000

Compared against the same corpus:
  JANISSARY   984 TPs, 0 FPs
  Nuclei 3.11   0 TPs (CVE-keyed, benchmark has no CVEs)
  ZAP baseline  0 TPs (passive-only; 27 findings, all hygiene)

These tools are complementary — Nuclei for CVE coverage, ZAP for passive hygiene, JANISSARY for differential detection on the injection classes. They don't compete for the same triage slot.

Full write-up: https://dev.to/janissary/we-refuse-to-emit-a-finding-from-a-single-response-3bld
Repo: https://github.com/Hetaireia/janissary
Install: pip install janissary

Dual-use security tool. Run it only against targets you own or have written permission to test.

---

## 3. r/blueteamsec post

Same title and body as r/AskNetsec. If r/AskNetsec removed the post for account age, wait 10 minutes and check the removal reason before posting to r/blueteamsec.

---

## 4. X/Twitter thread

**1/4**
A finding that isn't a difference is a guess.

I built JANISSARY around one rule: no DAST finding is emitted from a single response. Every detection is a baseline comparison.

F1 0.920, precision 1.000 on OWASP Benchmark.

**2/4**
The result: 984 true positives, 0 false positives on the DAST-applicable corpus.

Every oracle requires specific evidence — DB error signatures, session sink echoes, raw XSS past its trailing char. Nothing fires on pattern match alone.

**3/4**
Compared against the same corpus:

JANISSARY    984 TPs
Nuclei 3.11    0 TPs (CVE-keyed; benchmark has no CVEs)
ZAP baseline   0 TPs (passive-only)

Complementary tools, not competitors.

**4/4**
Blog: https://dev.to/janissary/we-refuse-to-emit-a-finding-from-a-single-response-3bld
Repo: https://github.com/Hetaireia/janissary

pip install janissary
Apache 2.0. Dual-use — authorised targets only.

---

## 5. OWASP Slack message

Sharing an open-source DAST tool I've been building: JANISSARY is a differential scanner — every finding is gated on a baseline comparison, nothing emits from a single response.

On OWASP Benchmark: F1 0.920 at precision 1.000 (984 TP, 0 FP). Eighteen categories at F1 1.000.

Write-up: https://dev.to/janissary/we-refuse-to-emit-a-finding-from-a-single-response-3bld
Repo: https://github.com/Hetaireia/janissary

Apache 2.0, Python, pip install janissary. Feedback welcome, especially false positives — those are bugs by definition.

---

## Pre-written objection replies

**"Differential detection isn't new — Burp has baseline comparison."**
True, and Burp's implementation is good. The difference is that in Burp it's a feature you can turn on per-scan; in JANISSARY it's the only way a finding can exist. That constraint changes what the tool does with ambiguous responses: it drops them, where most tools surface them with a confidence score and let you sort it out. Different bet, not a new idea.

**"So you miss real findings because the baseline was flaky."**
Yes. That's the tradeoff, and it's the point of the design. A missed finding on a flaky endpoint is a real cost. A false positive in a report you hand to a client is a worse one. If you'd rather have recall over precision, JANISSARY is the precision tool in your toolbox, not the only tool.

**"WAF pacing is just evasion."**
It's rate adaptation, and it's the same thing every scanner does when it sees a 429. The difference is JANISSARY detects the ten most common WAFs and adapts before it gets blocked, rather than after. If you're scanning a target you're authorised to test, getting blocked mid-scan wastes the scan.

**"Another scanner, we have enough."**
Fair. If your current scanner's output is trustworthy enough that you don't triage, you don't need JANISSARY. If you triage 70% of it away, run one differential scan and compare your triage load.

**"0, 0, 984 — that comparison is rigged."**
I know how it reads. It isn't rigged, and the numbers are reproducible in one command against the public corpus. Nuclei found 0 findings at medium+ severity across 550 URLs — its templates are CVE-keyed, the benchmark has no CVEs. ZAP baseline found 27 findings, all passive (headers, CSP, error disclosure) — it doesn't inject. The honest reading is that these tools answer different questions. JANISSARY's question is the one the benchmark asks.

**"Why Flask apps instead of real targets?"**
Because I could publish the full benchmark source and everyone can reproduce it locally in five minutes. If you want numbers against a named target (Juice Shop, DVWA), run it and send them — happy to add a row.

---

## If it goes badly

- **Front page, hostile comments.** Reply once per person, technical, no defensiveness.
- **Nobody shows up.** Default outcome. Post the blog to your own channels, retry in a month with real-target numbers.
- **Someone finds a real false positive.** Thank them, open a GitHub issue, link it in the thread. This is the best outcome — the claim is trustworthiness, and one honest FP corrected in public makes that stronger.
