"""Minimal pure-Python PDF report renderer (M19).

Produces a valid PDF 1.4 file with Helvetica text, auto-paginated.
No external dependencies. Consumes the same payload dict as the HTML
renderer (the output of cli._summary_to_dict()).
"""

from __future__ import annotations

from pathlib import Path

PAGE_W = 612
PAGE_H = 792
MARGIN = 50
LINE_H = 12
MAX_CHARS = 90
MAX_LINES_PER_PAGE = 55


def _escape_pdf_text(s: str) -> str:
    """Escape (, ), backslash for PDF strings; strip non-ASCII to '?'."""
    out = []
    for ch in s:
        if ch == "(":
            out.append("\\(")
        elif ch == ")":
            out.append("\\)")
        elif ch == "\\":
            out.append("\\\\")
        elif 32 <= ord(ch) < 127:
            out.append(ch)
        else:
            out.append("?")
    return "".join(out)


def _normalize(payload):
    if isinstance(payload, list):
        return {}, payload, []
    if not isinstance(payload, dict):
        return {}, [], []
    meta = {k: v for k, v in payload.items() if k not in ("findings", "candidates")}
    findings = payload.get("findings") or []
    if not isinstance(findings, list):
        findings = []
    candidates = payload.get("candidates") or []
    if not isinstance(candidates, list):
        candidates = []
    return meta, findings, candidates


def _wrap(text: str, width: int = MAX_CHARS):
    text = text or ""
    if len(text) <= width:
        return [text]
    return [text[i : i + width] for i in range(0, len(text), width)]


def _render_one(f: dict, idx: int, *, is_candidate: bool = False):
    lines: list[str] = []
    sev = (f.get("severity") or "info").upper()
    cls = f.get("class") or f.get("category") or "?"
    param = f.get("parameter") or "?"
    url = f.get("url") or "?"
    payload = f.get("payload") or ""
    detail = f.get("detail") or ""
    vstatus = f.get("verification_status") or ""
    vreason = f.get("verification_reason") or ""
    verification = vstatus + (f" ({vreason})" if vreason else "")
    idx_label = f"C#{idx}" if is_candidate else f"#{idx}"
    marker = "[UNPROVEN] " if is_candidate else ""

    lines.append("-" * 78)
    lines.append(f"{idx_label}  [{sev}]  {marker}{cls}")
    lines.extend(_wrap(f"URL:        {url}"))
    lines.extend(_wrap(f"Parameter:  {param}"))
    if payload:
        lines.extend(_wrap(f"Payload:    {payload}"))
    if verification:
        lines.extend(_wrap(f"Verified:   {verification}"))
    if detail:
        lines.extend(_wrap(f"Detail:     {detail}"))

    raw_req = f.get("raw_request") or ""
    if raw_req:
        lines.append("--- raw request ---")
        for raw_line in raw_req.replace("\r\n", "\n").split("\n")[:40]:
            lines.extend(_wrap(raw_line))
    raw_resp = f.get("raw_response") or ""
    if raw_resp:
        lines.append("--- raw response ---")
        for raw_line in raw_resp.replace("\r\n", "\n").split("\n")[:40]:
            lines.extend(_wrap(raw_line))
    lines.append("")
    return lines


def _build_lines(meta: dict, findings: list, candidates: list):
    lines = ["JANISSARY report", "=" * 78]
    target = meta.get("target") or meta.get("url") or "?"
    lines.extend(_wrap(f"Target: {target}"))
    ts = meta.get("timestamp")
    if ts:
        lines.extend(_wrap(f"Timestamp: {ts}"))
    lines.append(f"Verified: {len(findings)} | Candidates: {len(candidates)}")
    lines.append("")

    lines.append("--- Verified Findings ---")
    if not findings:
        lines.append("No verified findings.")
    else:
        for i, f in enumerate(findings, 1):
            lines.extend(_render_one(f, i))

    lines.append("")
    lines.append("--- Discovery Candidates (unproven) ---")
    if not candidates:
        lines.append("No discovery candidates.")
    else:
        for i, c in enumerate(candidates, 1):
            lines.extend(_render_one(c, i, is_candidate=True))

    return lines


def _paginate(lines, per_page: int = MAX_LINES_PER_PAGE):
    if not lines:
        return [[""]]
    return [lines[i : i + per_page] for i in range(0, len(lines), per_page)]


def _render_content_stream(lines):
    ops = []
    y = PAGE_H - MARGIN
    for line in lines:
        ops.append(f"BT /F1 9 Tf {MARGIN} {y} Td ({_escape_pdf_text(line)}) Tj ET")
        y -= LINE_H
    return "\n".join(ops).encode("latin-1", errors="replace")


def _emit_pdf(pages) -> bytes:
    n = len(pages)
    page_ids = [3 + 2 * i for i in range(n)]
    content_ids = [4 + 2 * i for i in range(n)]
    font_id = 3 + 2 * n

    objects = []
    objects.append(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")

    kids = " ".join(f"{pid} 0 R" for pid in page_ids)
    objects.append(
        f"2 0 obj\n<< /Type /Pages /Kids [{kids}] /Count {n} >>\nendobj\n".encode()
    )

    for page_id, content_id, page_lines in zip(
        page_ids, content_ids, pages, strict=False
    ):
        objects.append(
            (
                f"{page_id} 0 obj\n"
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W} {PAGE_H}] "
                f"/Contents {content_id} 0 R "
                f"/Resources << /Font << /F1 {font_id} 0 R >> >> >>\n"
                f"endobj\n"
            ).encode()
        )
        stream = _render_content_stream(page_lines)
        objects.append(
            f"{content_id} 0 obj\n<< /Length {len(stream)} >>\nstream\n".encode()
            + stream
            + b"\nendstream\nendobj\n"
        )

    objects.append(
        f"{font_id} 0 obj\n"
        f"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n".encode()
    )

    header = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
    body = b"".join(objects)

    offsets = {}
    pos = len(header)
    for obj in objects:
        num = int(obj.split(b" ", 1)[0])
        offsets[num] = pos
        pos += len(obj)

    total = font_id
    xref_start = pos
    xref = [b"xref\n", f"0 {total + 1}\n".encode(), b"0000000000 65535 f \n"]
    for i in range(1, total + 1):
        if i in offsets:
            xref.append(f"{offsets[i]:010d} 00000 n \n".encode())
        else:
            xref.append(b"0000000000 65535 f \n")
    xref_bytes = b"".join(xref)

    trailer = (
        f"trailer\n<< /Size {total + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_start}\n%%EOF\n"
    ).encode()

    return header + body + xref_bytes + trailer


def write_pdf_report(payload, path: str) -> None:
    """Render payload as a valid PDF 1.4 report at `path`."""
    meta, findings, candidates = _normalize(payload)
    lines = _build_lines(meta, findings, candidates)
    pages = _paginate(lines)
    Path(path).write_bytes(_emit_pdf(pages))
