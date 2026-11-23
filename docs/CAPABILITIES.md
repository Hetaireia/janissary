# JANISSARY Capability Matrix

**Last updated:** 2026-11-24.
**Purpose:** Consolidated capability status for external readers, auditors, and procurement reviewers. The README capability matrix is a summary; this document is the authoritative reference.

## Status legend

Four distinct meanings, not four colours. A row may change status tier without changing the meaning of its colour.

| Indicator | Status | Meaning |
|---|---|---|
| 🟢 | **Implemented** | Supported, tested, default-enabled |
| 🟠 | **Partial** | Implemented with a disclosed measured weakness |
| 🔴 | **Not yet supported** | No implementation; out of implied coverage |
| 🟣 | **Separate integration** | Explicit invocation; not automatic in every scan |
| 🟡 | **Discovery candidates** | Emits unproven candidates; requires manual triage |
| 🩵 | **Discovery path** | Broader discovery; always candidate-only |
| 🔵 | **Explicit opt-in** | Requires additional confirmation flags |

## Capability matrix

| Capability | Status | Notes |
|---|---|---|
| Differential HTTP scanning | 🟢 Implemented | Baseline + comparison; sole VerifiedFinding emitter |
| OpenAPI 3.0.x / Swagger 2.0 importer | 🟢 Implemented | Local-file/URL import, `$ref` resolution, operation-level parameter dispatch, CLI enumeration and per-operation live scan loop. Request-body targets use `auto`; named body-parameter injection is not implemented. Runtime target failures are logged and skipped without marking the merged scan summary incomplete. |
| SQL injection — blind and union differential | 🟢 Implemented | No error-based class; verification is differential (blind + union) |
| XSS (reflected) | 🟢 Implemented | Context-aware reflection check; not a parser differential |
| XPath injection | 🟢 Implemented | SQL-style oracle reuse; broad benchmark coverage not established |
| Command injection | 🟢 Implemented | — |
| Path traversal | 🟠 Partial | Recall **0.075** at 7.11.1; per-category F1 0.049 / 0.154 / 0.160 / 0.308 |
| SSRF | 🟠 Partial | OOB + metadata-marker only; `file://` deferred; confidence-aware attribution pending |
| IDOR | 🟡 Discovery candidates | Candidate-only per ADR-031; two identities required; manual triage |
| Host-header ACL bypass | 🟡 Discovery candidates | Bypasses VerificationEngine by design (ADR-030 Rule 1) |
| Heuristic discovery | 🩵 Discovery path | `--heuristic` required; always candidate-only |
| WAF fingerprinting | 🟢 Implemented | Active probe detections (10-vendor table). Passive response-header classification (M109/B-8) remains proposed and unapproved; it is not represented as implemented. |
| GraphQL | 🟣 Separate integration | Explicit invocation; discovery + fuzzing primitives |
| WebSocket | 🟣 Separate integration | Explicit invocation; payload input required |
| Attack subcommands | 🔵 Explicit opt-in | `--attack-confirm` required; separate from standard DAST |
| JWT / prototype pollution | 🔴 Not yet supported | Out of implied coverage |

## Reference palette

For HTML renderers (GitHub Pages, local preview, interactive architecture page). GitHub Markdown uses the emoji indicators above; this block exists so any future HTML renderer uses the same palette values.

```css
:root{
  --st-green:#22C55E; --st-orange:#F97316; --st-violet:#8B5CF6;
  --st-amber:#EAB308; --st-cyan:#06B6D4; --st-blue:#3B82F6; --st-red:#EF4444;
  --brand-gold:#D4AF37; --brand-obsidian:#0B0B0F; --brand-slate:#4B5057; --brand-platinum:#EBEBEB;
}
.status-chip{
  background: color-mix(in srgb, var(--st-green) 14%, transparent);
  border: 1px solid color-mix(in srgb, var(--st-green) 40%, transparent);
}
```

Note: `#D4AF37` is the brand accent, not a status colour.

