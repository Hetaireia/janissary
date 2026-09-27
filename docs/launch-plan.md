# Launch Plan — P4.4

Reference doc for launch day. Do not execute ahead of schedule.

## Pre-flight (day before)

- [ ] CI green on `main`
- [ ] README renders correctly on GitHub (GIF plays, badges resolve, code blocks copy cleanly)
- [ ] Blog post spell-checked, benchmark numbers verified against `bench-*.json`
- [ ] Terms of Use reachable via `janissary terms show`
- [ ] `pip install janissary` works from a fresh venv on a clean machine
- [ ] `janissary --help` exits 0 and lists every documented command
- [ ] Two backup terminal windows open with the demo command ready to re-run

## Day 1 — Show HN

**Post at 08:00 ET (Tuesday or Wednesday).**

Title:

```
Show HN: JANISSARY – DAST that only reports reproducible differences
```

Body (three sentences, no more):

```
Every DAST tool I've used has the same failure mode: not detection, but
trust. Findings that can't be reproduced cost more to triage than they're
worth, and after a while you stop reading them. JANISSARY gates every
finding on a baseline comparison — nothing is emitted from a single
response — and groups multiple payload confirmations of the same bug into
one finding with attached evidence.

https://github.com/Hetaireia/janissary

Dual-use security tool; run it only against authorised targets.
```

Rules:
- **Do not** ask for upvotes anywhere. HN detects it and bans.
- **Do not** post a link to the blog in the HN body. Keep the repo as the single destination. Blog goes in a comment if someone asks "is there a write-up?"
- **Reply to every top-level comment** within the first 90 minutes. Be boring, technical, non-defensive.
- If it dies off /new, do not repost. HN will downweight it.

## Day 1 — same-day, staggered

**08:15 ET — r/netsec**

Title: `JANISSARY — differential DAST that only emits reproducible findings`

Body: same three sentences as HN, plus:
- one paragraph on the grouping change (11 findings → 2 groups on a real SQLi)
- link to both repo and blog
- explicit dual-use disclaimer at the bottom

**09:00 ET — Lobste.rs** (skip if you don't have an invite; low-karma submissions backfire)

Tag: `security`. Link: blog post, not repo.

**10:00 ET — X/Twitter** thread, 4 tweets:

1. The thesis: "A finding that isn't a difference is a guess."
2. The demo GIF (12s)
3. The benchmark: 23 findings / 3 groups; SQLi scan returns identical results across two runs
4. `pip install janissary` + repo link

## Day 2

- Check HN thread — if it held the front page for 4+ hours, reply to any late comments.
- If it didn't, do not chase. Post the blog to your own channels and move on.
- Watch GitHub issues for the first 48 hours. Respond to every one. Report false positives as bugs.

## Pre-written objection replies

**"Differential detection isn't new — Burp has baseline comparison."**

> True, and Burp's implementation is good. The difference is that in Burp
> it's a feature you can turn on per-scan; in JANISSARY it's the only way
> a finding can exist. That constraint changes what the tool does with
> ambiguous responses: it drops them, where most tools surface them with
> a confidence score and let you sort it out. Different bet, not a new
> idea.

**"So you miss real findings because the baseline was flaky."**

> Yes. That's the tradeoff, and it's the point of the design. A missed
> finding on a flaky endpoint is a real cost. A false positive in a report
> you hand to a client is a worse one. If you'd rather have recall over
> precision, JANISSARY is the precision tool in your toolbox, not the only
> tool. Run it alongside a broad scanner.

**"WAF pacing is just evasion."**

> It's rate adaptation, and it's the same thing every scanner does when it
> sees a 429. The difference is JANISSARY detects the ten most common WAFs
> and adapts *before* it gets blocked, rather than after. If you're
> scanning a target you're authorised to test, getting blocked mid-scan
> wastes the scan. If you're scanning without authorisation, the Terms of
> Use are already against you.

**"Another scanner, we have enough."**

> Fair. If your current scanner's output is trustworthy enough that you
> don't triage, you don't need JANISSARY. If you triage 70% of it away,
> run one differential scan and compare your triage load. That's the whole
> test.

**"9 findings from one bug is still noise."**

> That was true before the grouping change. Current output is 1 group
> with 8 evidence rows: `F-001 CRITICAL sqli:sql_injection (param=q)` —
> one thing to triage, with the receipts attached. The README has the
> full output.

**"Why Flask apps for the benchmark instead of real targets?"**

> Because I could publish the full benchmark source and everyone can
> reproduce it locally in five minutes. If you want the numbers against a
> named target (Juice Shop, DVWA) run it and send them — happy to add a
> row to the table.

## What to do if it goes badly

- **Front page, hostile comments.** Reply once per person, technical,
  no defensiveness. Let the code answer.
- **Nobody shows up.** That's the default outcome. Post the blog to your
  own channels, keep working, retry in a month with real-world scan
  numbers.
- **Someone finds a real false positive.** Thank them, open an issue,
  link the issue in the thread. This is the best possible outcome — the
  tool's claim is that it can be trusted, and one honest FP corrected in
  public makes that claim stronger, not weaker.