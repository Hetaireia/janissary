# DEMO_VIDEO.md

Demo video script + production notes for the JANISSARY launch.

**Target length:** 75 seconds.
**Format:** screen recording, on-screen text, optional voice-over.
**Voice:** design a generic voice (see Appendix A). Do not imitate a real person.

---

## Shot list

| # | Time | On screen | Voice-over |
|---|---|---|---|
| 1 | 0:00-0:06 | Black. White text: \Most DAST tools give you a wall of false positives.\ | (silence) |
| 2 | 0:06-0:14 | Terminal. Cursor. Text fades in: \JANISSARY.\ | \JANISSARY is different.\ |
| 3 | 0:14-0:24 | Terminal types: `pip install janissary` -> output | `Install it in one line from PyPI.` |
| 4 | 0:24-0:44 | \janissary agent https://target.example --attack-confirm\ running live | \One command. It fingerprints the target, detects the WAF, picks the modules that apply, and runs them.\ |
| 5 | 0:44-0:60 | Findings output scrolls. Text callout: \1,500+ tests. 1.000 precision on the OWASP Benchmark DAST-applicable subset.\ | \Every finding is gated by a baseline comparison. No single response is ever enough.\ |
| 6 | 0:60-0:70 | GitHub repo view. Star count. \github.com/Hetaireia/janissary\ | \Open source. Apache 2.0. Built for pentesters who need results they can trust.\ |
| 7 | 0:70-0:75 | Black. Text: \JANISSARY\ | (silence) |

---

## Recording steps

1. Open a clean terminal. 80 columns. Dark theme. Large font.
2. Have a target ready. Use a local mock server, never a live site.
3. Record with OBS Studio (free) or Windows Game Bar (Win+G).
4. Capture at 1080p, 30fps. No webcam.
5. Do the whole run in one take. Trim dead air in the editor.
6. Keep the mouse still unless you are pointing at something.

## Editing

- Free editors: DaVinci Resolve, Shotcut, CapCut.
- Add the voice-over as a separate track.
- Keep music minimal or none. If used, royalty-free only.
- Export 1080p MP4, H.264.
- Upload to YouTube as unlisted first. Watch it once end to end.

## Where to publish

- Link it from the top of README.md.
- Post to the Show HN thread (M6).
- Pin it on the GitHub repo.
- Add it to the G2 listing (M7).

---

## Appendix A - Voice design

Do NOT instruct a voice tool to imitate a real person.
Describe acoustic qualities only. Test for recognisability.

### Safe prompt template

Design a female voice with:
- pitch: low-to-mid female range
- timbre: warm, slightly husky
- pace: measured, unhurried
- delivery: confident, conversational, slight breathiness
- accent: neutral, no strong regional markers
- emotion: calm, assured, not seductive or performative

End with: Do not imitate any real person or public figure.

### Recognisability test

Play the generated voice to two people who know the celebrity.
Ask: Who does this sound like?

- Both say nobody or I do not know: safe to use.
- Either names a specific celebrity: regenerate.

### Tools

- ElevenLabs Voice Design (prompt-based, no person clone)
- Play.ht
- Murf AI
- Licensed voice actor via Fiverr or Voices.com (safest)

### Keep a record

Save the exact prompt you used and the tool name.
If anyone questions the voice later, you can show you described
qualities, not a person.
