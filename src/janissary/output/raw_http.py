"""Serialize requests.PreparedRequest / requests.Response to raw HTTP/1.1.

Attached to findings as `raw_request` / `raw_response` so hunters can paste
them directly into Burp Repeater.

Contract:
  * CRLF line endings (RFC 7230, Burp-compatible).
  * Bodies decoded UTF-8 with errors="replace". Binary bodies show
    replacement chars; a future --raw-b64 flag can carry bytes.
  * Host header is synthesized from the URL when not present on the request.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit


def serialize_request(prepared: Any) -> str | None:
    if prepared is None:
        return None

    method = (getattr(prepared, "method", None) or "GET").upper()
    url = getattr(prepared, "url", "") or ""
    parsed = urlsplit(url)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    headers = _extract_headers(getattr(prepared, "headers", None))
    if "host" not in {k.lower() for k in headers} and parsed.netloc:
        headers["Host"] = parsed.netloc

    body_text = _body_to_text(getattr(prepared, "body", None))

    head = "\r\n".join(
        [f"{method} {path} HTTP/1.1", *(f"{k}: {v}" for k, v in headers.items())]
    )
    return head + "\r\n\r\n" + (body_text or "")


def serialize_response(response: Any) -> str | None:
    if response is None:
        return None

    status = getattr(response, "status_code", 0) or 0
    reason = getattr(response, "reason", "") or ""
    version = _http_version(response)
    headers = _extract_headers(getattr(response, "headers", None))
    body_text = _body_to_text(getattr(response, "content", None))

    status_line = f"{version} {status} {reason}".rstrip()
    head = "\r\n".join(
        [status_line, *(f"{k}: {v}" for k, v in headers.items())]
    )
    return head + "\r\n\r\n" + (body_text or "")


def _extract_headers(headers: Any) -> dict:
    out: dict = {}
    if headers is None:
        return out
    try:
        for k, v in headers.items():
            out[str(k)] = str(v)
    except Exception:
        return out
    return out


def _body_to_text(body: Any) -> str:
    if body is None:
        return ""
    if isinstance(body, str):
        return body
    if isinstance(body, (bytes, bytearray, memoryview)):
        return bytes(body).decode("utf-8", errors="replace")
    return str(body)


def _http_version(response: Any) -> str:
    raw = getattr(response, "raw", None)
    version = getattr(raw, "version", None)
    if version == 10:
        return "HTTP/1.0"
    return "HTTP/1.1"
