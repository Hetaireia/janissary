"""Finding replay / explain (M15).

Loads a finding from a JSONL or JSON file, renders a human-readable
summary, and (with --replay) re-sends the finding's raw_request to the
recorded target so a hunter can verify the finding by hand.

The raw_request / raw_response fields are produced by
janissary.output.raw_http (see ADR-012 and the launch plan: "findings
carry raw HTTP/1.1 so you can paste them into Repeater").
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from urllib.parse import urlsplit

import requests

from janissary.output.raw_http import serialize_response


class ReplayError(Exception):
    """Raised on load, parse, or transport failure during replay/explain."""


def load_findings(path: str | Path) -> list[dict]:
    """Load findings from a .jsonl (one per line) or .json file."""
    p = Path(path)
    if not p.exists():
        raise ReplayError(f"file not found: {p}")
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise ReplayError(f"cannot read {p}: {exc}") from exc
    if not text.strip():
        return []
    if p.suffix.lower() == ".jsonl":
        findings: list[dict] = []
        for n, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError as exc:
                raise ReplayError(f"{p}:{n}: invalid JSON: {exc}") from exc
            if isinstance(obj, dict):
                findings.append(obj)
        return findings
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ReplayError(f"{p}: invalid JSON: {exc}") from exc
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    raise ReplayError(f"{p}: expected JSON object or array")


def format_explanation(finding: dict) -> str:
    """Render a finding as a multi-line, human-readable block."""
    fid = finding.get("id") or finding.get("fingerprint") or "?"
    klass = finding.get("class") or finding.get("vuln_class") or "?"
    severity = finding.get("severity") or "?"
    vstatus = finding.get("verification_status") or "?"
    vreason = finding.get("verification_reason")
    verification = vstatus + (f" ({vreason})" if vreason else "")
    lines = [
        f"FINDING {fid}",
        f"  class:        {klass}",
        f"  severity:     {severity}",
        f"  verification: {verification}",
        f"  timestamp:    {finding.get('timestamp') or '?'}",
        "",
        f"  URL:          {finding.get('url') or '?'}",
        f"  method:       {finding.get('method') or '?'}",
        f"  parameter:    {finding.get('parameter') or '?'}",
        f"  payload:      {finding.get('payload') or ''}",
        "",
    ]
    signals = finding.get("signals") or []
    if signals:
        lines.append("  signals:")
        for s in signals:
            lines.append(f"    - {s}")
        lines.append("")
    raw_req = finding.get("raw_request")
    if raw_req:
        lines.append("  --- raw request ---")
        lines.append(raw_req.rstrip("\r\n"))
        lines.append("")
    raw_resp = finding.get("raw_response")
    if raw_resp:
        lines.append("  --- raw response ---")
        lines.append(raw_resp.rstrip("\r\n"))
    return "\n".join(lines)


def _parse_raw_request(raw: str) -> dict:
    if not raw:
        raise ReplayError("empty raw_request")
    head, _, body = raw.partition("\r\n\r\n")
    lines = head.split("\r\n")
    request_line = lines[0] if lines else ""
    parts = request_line.split(" ", 2)
    if len(parts) < 2:
        raise ReplayError(f"malformed request line: {request_line!r}")
    method, path = parts[0], parts[1]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    return {"method": method, "path": path, "headers": headers, "body": body}


def replay_finding(
    finding: dict,
    timeout: float = 10.0,
    session: requests.Session | None = None,
) -> dict:
    """Re-send the finding's raw_request; return a summary of the response."""
    parsed = _parse_raw_request(finding.get("raw_request") or "")
    url = finding.get("url") or ""
    if not url:
        raise ReplayError("finding has no url; cannot replay")
    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        raise ReplayError(f"finding url is not absolute: {url!r}")
    base = f"{parts.scheme}://{parts.netloc}"
    target = base + parsed["path"]
    body = parsed["body"].encode("utf-8") if parsed["body"] else None
    sess = session or requests.Session()
    t0 = time.perf_counter()
    try:
        r = sess.request(
            parsed["method"],
            target,
            headers=parsed["headers"],
            data=body,
            timeout=timeout,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        raise ReplayError(f"replay request failed: {exc}") from exc
    elapsed = time.perf_counter() - t0
    content = getattr(r, "content", None)
    length = len(content) if content is not None else len(r.text or "")
    return {
        "status": r.status_code,
        "length": length,
        "elapsed": elapsed,
        "raw_response": serialize_response(r),
        "match": finding.get("response_status") == r.status_code,
    }