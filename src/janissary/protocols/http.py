"""HTTP BaselineNormalizer (Phase 0.3).

Wraps the existing normalize_body() (regex + whitespace) from
detection/analyzer.py and adds header-level normalization: session
cookies, CSRF tokens, and volatile Set-Cookie values are redacted so
that a baseline's incidental refresh does not look like a delta.

See docs/ROADMAP.md Phase 0.3.
"""

from __future__ import annotations

import re
from typing import Any

from janissary.detection.analyzer import normalize_body

from .base import NormalizedResponse

_VOLATILE_HEADER_NAMES = frozenset(
    {
        "set-cookie",
        "x-csrf-token",
        "x-csrftoken",
        "x-xsrf-token",
        "x-request-id",
        "x-trace-id",
        "x-correlation-id",
    }
)

_VOLATILE_COOKIE_NAMES = re.compile(
    r"(?i)\b(session|sessionid|jsessionid|phpsessid|csrf|csrftoken|nonce|xsrf|_ga|_gid)\b\s*=\s*[^;]+"
)

_BODY_CSRF_PATTERNS = (
    re.compile(
        r"(?i)(\bcsrf[_\-]?token\b)\s*[=:]\s*[\"']?[A-Za-z0-9\-_+/=.]{8,}[\"']?"
    ),
    re.compile(r"(?i)(\bnonce\b)\s*[=:]\s*[\"']?[A-Za-z0-9\-_+/=.]{8,}[\"']?"),
    re.compile(
        r"(?i)(\bsession[_\-]?id\b)\s*[=:]\s*[\"']?[A-Za-z0-9\-_+/=.]{8,}[\"']?"
    ),
)


class HTTPNormalizer:
    """BaselineNormalizer for HTTP responses.

    Accepts requests.Response or anything with .text/.status_code/.headers.
    Returns NormalizedResponse whose .body matches normalize_body() output.
    """

    protocol_name = "http"

    def normalize(self, response: Any) -> NormalizedResponse:
        body_raw = _get_text(response)
        status = _get_status(response)
        headers_raw = _get_headers(response)

        stripped: list[str] = []

        normalized_body = normalize_body(body_raw)
        for pattern in _BODY_CSRF_PATTERNS:
            before = normalized_body
            normalized_body = pattern.sub(r"\1=[REDACTED]", normalized_body)
            if normalized_body != before:
                stripped.append("body:" + pattern.pattern[:40])

        normalized_headers: dict[str, str] = {}
        for name, value in headers_raw.items():
            lname = name.lower()
            if lname == "set-cookie":
                redacted = _VOLATILE_COOKIE_NAMES.sub(
                    lambda m: m.group(1) + "=[REDACTED]", str(value)
                )
                normalized_headers[name] = redacted
                if redacted != str(value):
                    stripped.append("header:set-cookie")
            elif lname in _VOLATILE_HEADER_NAMES:
                normalized_headers[name] = "[REDACTED]"
                stripped.append(f"header:{lname}")
            else:
                normalized_headers[name] = str(value)

        return NormalizedResponse(
            body=normalized_body,
            length=len(normalized_body),
            status=status,
            headers=normalized_headers,
            stripped=tuple(stripped),
        )


def _get_text(response: Any) -> str:
    text = getattr(response, "text", None)
    if text is None:
        text = getattr(response, "body", "")
    return str(text) if text is not None else ""


def _get_status(response: Any) -> int | None:
    status = getattr(response, "status_code", None)
    if status is None:
        status = getattr(response, "status", None)
    try:
        return int(status) if status is not None else None
    except (TypeError, ValueError):
        return None


def _get_headers(response: Any) -> dict[str, str]:
    headers = getattr(response, "headers", None)
    if not headers:
        return {}
    try:
        return {str(k): str(v) for k, v in headers.items()}
    except AttributeError:
        return {}
