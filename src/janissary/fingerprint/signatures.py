"""Signature tables for passive stack classification.

All matchers return (value, confidence, evidence) or None.
Conflicting strong signals of the same family resolve to "Ambiguous",
never to first-match-wins. Weak signals never override strong ones.
"""

from __future__ import annotations

# Confidence thresholds
STRONG = 0.80


def _hdr(headers: dict[str, str], name: str) -> str:
    """Case-insensitive header lookup."""
    low = name.lower()
    for k, v in headers.items():
        if k.lower() == low:
            return v
    return ""


def _resolve(
    strong: list[tuple[str, float]], weak: list[tuple[str, float]], evidence: list[str]
):
    """Resolve candidate list into (value, confidence, evidence).

    - Two or more strong candidates with different values => Ambiguous.
    - One strong candidate => that value at its confidence.
    - Only weak candidates => highest weak candidate.
    - No candidates => None.
    """
    strong_labels = {v for v, _ in strong}
    if len(strong_labels) > 1:
        return "Ambiguous", 0.50, evidence
    if strong:
        return strong[0][0], strong[0][1], evidence
    if weak:
        best = max(weak, key=lambda c: c[1])
        return best[0], best[1], evidence
    return None


def match_server(headers: dict[str, str]):
    """Identify HTTP server software from the Server header."""
    srv = _hdr(headers, "Server").strip()
    if not srv:
        return None
    low = srv.lower()
    strong_table = [
        ("cloudflare", ("cloudflare",), 0.95),
        ("akamai", ("akamaighost", "akamai"), 0.95),
        ("aws-alb", ("awselb",), 0.95),
        ("iis", ("microsoft-iis",), 0.90),
        ("nginx", ("nginx",), 0.90),
        ("apache", ("apache",), 0.90),
        ("caddy", ("caddy",), 0.90),
        ("litespeed", ("litespeed",), 0.90),
        ("openresty", ("openresty",), 0.90),
        ("gunicorn", ("gunicorn",), 0.90),
        ("uvicorn", ("uvicorn",), 0.90),
        ("werkzeug", ("werkzeug",), 0.90),
    ]
    strong: list[tuple[str, float]] = []
    for label, needles, conf in strong_table:
        if any(n in low for n in needles):
            strong.append((label, conf))
    evidence = [f"Server: {srv}"]
    return _resolve(strong, [], evidence)


def match_framework(headers: dict[str, str]):
    """Identify application framework from X-Powered-By, cookies, and headers."""
    evidence: list[str] = []
    strong: list[tuple[str, float]] = []
    weak: list[tuple[str, float]] = []

    xpb = _hdr(headers, "X-Powered-By").strip()
    if xpb:
        evidence.append(f"X-Powered-By: {xpb}")
        low = xpb.lower()
        if "express" in low:
            strong.append(("express", 0.85))
        if "asp.net" in low or "aspnet" in low:
            strong.append(("asp.net", 0.85))
        if "php" in low:
            strong.append(("php", 0.85))

    runtime = _hdr(headers, "X-Runtime").strip()
    if runtime:
        evidence.append(f"X-Runtime: {runtime}")
        strong.append(("rails", 0.85))

    req_id = _hdr(headers, "X-Request-Id").strip()
    if req_id:
        evidence.append(f"X-Request-Id: {req_id}")

    cookie = _hdr(headers, "Set-Cookie").lower()
    if cookie:
        if "connect.sid" in cookie:
            evidence.append("Set-Cookie: connect.sid")
            weak.append(("express", 0.78))
        if "csrftoken" in cookie or "django" in cookie:
            evidence.append("Set-Cookie: csrftoken")
            weak.append(("django", 0.78))
        if "_rails_session" in cookie or "_session_id" in cookie:
            evidence.append("Set-Cookie: rails session")
            weak.append(("rails", 0.78))
        if "php" in cookie:
            evidence.append("Set-Cookie: php session")
            weak.append(("php", 0.72))

    return _resolve(strong, weak, evidence)


def match_language(headers: dict[str, str]):
    """Identify implementation language from X-Powered-By and Server."""
    evidence: list[str] = []
    strong: list[tuple[str, float]] = []

    xpb = _hdr(headers, "X-Powered-By").strip()
    srv = _hdr(headers, "Server").strip()

    if xpb:
        evidence.append(f"X-Powered-By: {xpb}")
        low = xpb.lower()
        if "php" in low:
            strong.append(("php", 0.85))
        if "asp.net" in low or "aspnet" in low:
            strong.append(("csharp", 0.85))
        if "express" in low:
            strong.append(("javascript", 0.85))

    if srv:
        low = srv.lower()
        if "gunicorn" in low or "uvicorn" in low or "werkzeug" in low:
            evidence.append(f"Server: {srv}")
            strong.append(("python", 0.85))

    return _resolve(strong, [], evidence)


def match_waf(headers: dict[str, str]):
    """Identify WAF from distinctive headers. Conflicts resolve to Ambiguous."""
    evidence: list[str] = []
    strong: list[tuple[str, float]] = []

    cf_ray = _hdr(headers, "CF-RAY")
    if cf_ray:
        evidence.append(f"CF-RAY: {cf_ray}")
        strong.append(("cloudflare", 0.95))

    cf_status = _hdr(headers, "CF-Cache-Status")
    if cf_status:
        evidence.append(f"CF-Cache-Status: {cf_status}")
        strong.append(("cloudflare", 0.85))

    akamai_t = _hdr(headers, "X-Akamai-Transformed")
    akamai_g = _hdr(headers, "Akamai-Grn")
    if akamai_t or akamai_g:
        evidence.append("Akamai headers present")
        strong.append(("akamai", 0.95))

    imperva = _hdr(headers, "X-Iinfo")
    if imperva:
        evidence.append(f"X-Iinfo: {imperva}")
        strong.append(("imperva", 0.90))

    return _resolve(strong, [], evidence)


def match_cdn(headers: dict[str, str]):
    """Identify CDN from distinctive headers (separate from WAF)."""
    evidence: list[str] = []
    strong: list[tuple[str, float]] = []

    via = _hdr(headers, "Via").strip()
    if via:
        evidence.append(f"Via: {via}")
        if "varnish" in via.lower():
            strong.append(("fastly", 0.90))
        if "google" in via.lower():
            strong.append(("google", 0.85))

    xserved = _hdr(headers, "X-Served-By").strip()
    if xserved:
        evidence.append(f"X-Served-By: {xserved}")
        if "cache-" in xserved.lower():
            strong.append(("fastly", 0.90))

    x_cache = _hdr(headers, "X-Cache").strip()
    if x_cache:
        evidence.append(f"X-Cache: {x_cache}")

    return _resolve(strong, [], evidence)
