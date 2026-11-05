"""Single-file HTML report renderer (M19).

Consumes the payload dict produced by cli._summary_to_dict() - the same
shape used by --export results.json - and writes a self-contained HTML
file. No dependencies: inline CSS, no JavaScript, no external assets.
"""

from __future__ import annotations

from collections import Counter
from html import escape as _html_escape
from pathlib import Path

_SEV_ORDER = ("critical", "high", "medium", "low", "info")
_SEV_CSS = {
    "critical": "crit",
    "high": "high",
    "medium": "med",
    "low": "low",
    "info": "info",
}


def _esc(value) -> str:
    if value is None:
        return ""
    return _html_escape(str(value), quote=True)


def _normalize(payload):
    """Return (meta, findings) from a summary dict or a bare findings list."""
    if isinstance(payload, list):
        return {}, payload
    if not isinstance(payload, dict):
        return {}, []
    meta = {k: v for k, v in payload.items() if k != "findings"}
    findings = payload.get("findings") or []
    if not isinstance(findings, list):
        findings = []
    return meta, findings


def _sev(finding) -> str:
    s = (finding.get("severity") or "info").lower()
    return s if s in _SEV_CSS else "info"


def _render_finding(f: dict, idx: int) -> str:
    sev = _sev(f)
    cls = f.get("class") or f.get("category") or "?"
    param = f.get("parameter") or "?"
    url = f.get("url") or "?"
    payload = f.get("payload") or ""
    detail = f.get("detail") or ""
    raw_req = f.get("raw_request") or ""
    raw_resp = f.get("raw_response") or ""
    vstatus = f.get("verification_status") or ""
    vreason = f.get("verification_reason") or ""
    verification = vstatus + (f" ({vreason})" if vreason else "")

    parts = [
        f'<details class="finding sev-{_esc(sev)}">',
        "  <summary>",
        f'    <span class="sev">{_esc(sev.upper())}</span>',
        f'    <span class="idx">#{idx + 1}</span>',
        f'    <span class="cls">{_esc(cls)}</span>',
        f'    <code class="url">{_esc(url)}</code>',
        f'    <span class="param">param=<b>{_esc(param)}</b></span>',
    ]
    if payload:
        parts.append(
            f'    <span class="payload">payload=<code>{_esc(payload)}</code></span>'
        )
    parts.append("  </summary>")
    if detail:
        parts.append(f'  <p class="detail">{_esc(detail)}</p>')
    if verification:
        parts.append(
            f'  <p class="verify"><b>Verification:</b> {_esc(verification)}</p>'
        )
    if raw_req:
        parts.append("  <h4>Raw request</h4>")
        parts.append(f'  <pre class="raw">{_esc(raw_req)}</pre>')
    if raw_resp:
        parts.append("  <h4>Raw response</h4>")
        parts.append(f'  <pre class="raw">{_esc(raw_resp)}</pre>')
    parts.append("</details>")
    return "\n".join(parts)


_CSS = """
:root { --bg:#fafbfc; --panel:#fff; --border:#d0d7de; --text:#1f2328;
        --muted:#656d76; --crit:#cf222e; --high:#bc4c00; --med:#9a6700;
        --low:#0969da; --info:#6e7781; }
* { box-sizing: border-box; }
body { margin:0; padding:24px; background:var(--bg); color:var(--text);
       font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;
       font-size:14px; line-height:1.5; }
h1 { margin:0 0 4px; font-size:24px; }
h2 { margin:24px 0 8px; font-size:18px; border-bottom:1px solid var(--border);
     padding-bottom:4px; }
h4 { margin:12px 0 4px; font-size:13px; color:var(--muted); }
code, pre { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
            font-size:12px; }
.meta { color:var(--muted); margin-bottom:16px; }
.meta b { color:var(--text); }
.summary { display:flex; gap:8px; flex-wrap:wrap; margin:8px 0 16px; }
.badge { display:inline-block; padding:2px 8px; border-radius:12px;
         font-size:12px; font-weight:600; color:#fff; }
.finding { background:var(--panel); border:1px solid var(--border);
           border-left:4px solid var(--muted); border-radius:6px;
           margin-bottom:8px; padding:10px 14px; }
.finding.sev-critical { border-left-color:var(--crit); }
.finding.sev-high     { border-left-color:var(--high); }
.finding.sev-medium   { border-left-color:var(--med); }
.finding.sev-low      { border-left-color:var(--low); }
.finding.sev-info     { border-left-color:var(--info); }
.finding summary { cursor:pointer; display:flex; align-items:center;
                   gap:10px; flex-wrap:wrap; }
.finding .sev { display:inline-block; padding:1px 8px; border-radius:10px;
                font-size:11px; font-weight:700; color:#fff; background:var(--info); }
.finding.sev-critical .sev { background:var(--crit); }
.finding.sev-high .sev     { background:var(--high); }
.finding.sev-medium .sev   { background:var(--med); }
.finding.sev-low .sev      { background:var(--low); }
.finding .idx { color:var(--muted); font-size:12px; }
.finding .cls { font-weight:600; }
.finding .url { background:#f6f8fa; padding:1px 6px; border-radius:3px; }
.finding .param, .finding .payload { color:var(--muted); font-size:12px; }
.finding .detail { margin:8px 0; }
.finding .verify { margin:4px 0; font-size:12px; color:var(--muted); }
pre.raw { background:#f6f8fa; border:1px solid var(--border);
          border-radius:4px; padding:8px; white-space:pre-wrap;
          word-break:break-all; max-height:400px; overflow:auto;
          margin:4px 0 0; }
.empty { color:var(--muted); font-style:italic; }
footer { margin-top:32px; color:var(--muted); font-size:12px; text-align:center; }
"""


def write_html_report(payload, path: str) -> None:
    """Render payload as a self-contained HTML report at `path`."""
    meta, findings = _normalize(payload)
    target = meta.get("target") or meta.get("url") or "?"
    timestamp = meta.get("timestamp") or ""

    counts = Counter(_sev(f) for f in findings)
    badges = []
    for sev in _SEV_ORDER:
        n = counts.get(sev, 0)
        if n:
            badges.append(
                f'<span class="badge" style="background:var(--{_SEV_CSS[sev]})">'
                f"{_esc(sev)}: {n}</span>"
            )
    summary_html = "".join(badges) or '<span class="empty">no findings</span>'

    findings_html = "\n".join(_render_finding(f, i) for i, f in enumerate(findings))
    if not findings_html:
        findings_html = '<p class="empty">No findings.</p>'

    stamp = f"<div><b>Timestamp:</b> {_esc(timestamp)}</div>" if timestamp else ""

    doc = (
        "<!doctype html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        f"<title>JANISSARY report - {_esc(target)}</title>\n"
        f"<style>{_CSS}</style>\n"
        "</head>\n"
        "<body>\n"
        "<h1>JANISSARY report</h1>\n"
        '<div class="meta">\n'
        f"  <div><b>Target:</b> <code>{_esc(target)}</code></div>\n"
        f"  {stamp}\n"
        f"  <div><b>Total findings:</b> {len(findings)}</div>\n"
        "</div>\n"
        f'<div class="summary">{summary_html}</div>\n'
        "<h2>Findings</h2>\n"
        f"{findings_html}\n"
        "<footer>Generated by JANISSARY. Findings carry raw HTTP/1.1 for "
        "direct verification in Burp Repeater.</footer>\n"
        "</body>\n"
        "</html>\n"
    )
    Path(path).write_text(doc, encoding="utf-8")
