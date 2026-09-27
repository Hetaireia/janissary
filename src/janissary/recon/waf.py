"""WAF detection for JANISSARY.

Sends a small set of obviously-malicious probes and inspects the
responses for signatures of common web application firewalls. The
result drives the scanner's starting pace and biases the adaptive
pacer toward slower, stealthier requests when a WAF is confirmed.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

# ---------------------------------------------------------------------------
# Probe payloads
# ---------------------------------------------------------------------------

WAF_PROBES: list[tuple[str, str]] = [
    ("sqli_quote", "' OR '1'='1"),
    ("sqli_union", "' UNION SELECT NULL--"),
    ("xss_script", "<script>alert(1)</script>"),
    ("traversal", "../../../etc/passwd"),
    ("cmdi", ";cat /etc/passwd"),
    ("rce_sleep", ";sleep(5)"),
]


# ---------------------------------------------------------------------------
# Vendor signatures
# ---------------------------------------------------------------------------

VENDOR_HEADERS: dict[str, tuple[str, ...]] = {
    "cloudflare": ("cf-ray", "cf-cache-status", "server:cloudflare"),
    "akamai": ("x-akamai-transformed", "akamai-grn"),
    "sucuri": ("x-sucuri-id", "x-sucuri-cache"),
    "imperva": ("x-iinfo", "x-cdn"),
    "aws_waf": ("x-amzn-requestid", "x-amz-cf-id"),
    "f5_bigip": ("x-wa-info",),
    "barracuda": ("barra_counter_session",),
    "modsecurity": ("mod_security", "modsecurity"),
    "wordfence": ("wordfence",),
    "fastly": ("x-served-by", "x-fastly-request-id"),
}

VENDOR_BODY_MARKERS: dict[str, tuple[str, ...]] = {
    "cloudflare": (
        "attention required! | cloudflare",
        "cloudflare ray id",
        "cf-error-details",
    ),
    "sucuri": ("sucuri website firewall", "access denied - sucuri"),
    "imperva": ("incapsula incident id", "request unsuccessful. incapsula"),
    "modsecurity": ("mod_security", "modsecurity", "not acceptable!"),
    "wordfence": ("wordfence", "your access to this site has been limited"),
    "aws_waf": ("request blocked", "aws waf"),
    "f5_bigip": (
        "the requested url was rejected",
        "please consult with your administrator",
    ),
    "barracuda": ("barracuda", "you have been blocked"),
}

BLOCK_STATUSES = frozenset({403, 406, 418, 429, 501, 503})


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class WAFProbeResult:
    name: str
    status: int | None
    elapsed: float
    blocked: bool
    vendor_hint: str | None = None
    note: str = ""


@dataclass
class WAFProfile:
    detected: bool = False
    vendor: str | None = None
    confidence: float = 0.0
    probes: list[WAFProbeResult] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "detected": self.detected,
            "vendor": self.vendor,
            "confidence": round(self.confidence, 3),
            "probes": [
                {
                    "name": p.name,
                    "status": p.status,
                    "elapsed": round(p.elapsed, 4),
                    "blocked": p.blocked,
                    "vendor_hint": p.vendor_hint,
                    "note": p.note,
                }
                for p in self.probes
            ],
            "notes": list(self.notes),
        }


# ---------------------------------------------------------------------------
# Signature matching helpers
# ---------------------------------------------------------------------------


def _header_vendor(headers: dict) -> str | None:
    lowered = {k.lower(): (v or "").lower() for k, v in headers.items()}
    for vendor, keys in VENDOR_HEADERS.items():
        for key in keys:
            if ":" in key:
                k, _, v = key.partition(":")
                if v and v in lowered.get(k, ""):
                    return vendor
            elif key in lowered:
                return vendor
    return None


def _body_vendor(text: str) -> str | None:
    blob = (text or "").lower()
    for vendor, markers in VENDOR_BODY_MARKERS.items():
        for marker in markers:
            if marker in blob:
                return vendor
    return None


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


class WAFDetector:
    def __init__(
        self,
        session: requests.Session,
        timeout: float = 10.0,
        proxies: dict | None = None,
        param: str = "q",
        user_agent: str | None = None,
    ) -> None:
        self.session = session
        self.timeout = timeout
        self.proxies = proxies
        self.param = param
        self.user_agent = user_agent or DEFAULT_UA

    def _headers(self) -> dict:
        return {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/json,*/*;q=0.8",
            "Accept-Encoding": "identity",
            "Connection": "close",
        }

    def _build_url(self, base_url: str, value: str) -> str:
        parsed = urlparse(base_url)
        query = parse_qs(parsed.query, keep_blank_values=True)
        query[self.param] = [value]
        return urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                urlencode(query, doseq=True),
                parsed.fragment,
            )
        )

    def _probe(self, base_url: str, name: str, value: str) -> WAFProbeResult:
        url = self._build_url(base_url, value)
        start = time.perf_counter()
        try:
            r = self.session.get(
                url,
                headers=self._headers(),
                timeout=self.timeout,
                allow_redirects=False,
                proxies=self.proxies,
            )
        except requests.RequestException as exc:
            return WAFProbeResult(
                name=name,
                status=None,
                elapsed=time.perf_counter() - start,
                blocked=False,
                note=f"request error: {exc}",
            )

        elapsed = time.perf_counter() - start
        vendor = _header_vendor(dict(r.headers)) or _body_vendor(r.text or "")
        blocked = r.status_code in BLOCK_STATUSES
        note = f"HTTP {r.status_code}" if blocked else ""
        return WAFProbeResult(
            name=name,
            status=r.status_code,
            elapsed=elapsed,
            blocked=blocked,
            vendor_hint=vendor,
            note=note,
        )

    def detect(self, base_url: str) -> WAFProfile:
        profile = WAFProfile()
        vendor_votes: dict[str, int] = {}
        blocked_count = 0

        for name, value in WAF_PROBES:
            result = self._probe(base_url, name, value)
            profile.probes.append(result)
            if result.blocked:
                blocked_count += 1
            if result.vendor_hint:
                vendor_votes[result.vendor_hint] = (
                    vendor_votes.get(result.vendor_hint, 0) + 1
                )

        if vendor_votes:
            best = max(vendor_votes, key=vendor_votes.get)
            profile.vendor = best
            profile.detected = True
            profile.confidence = min(1.0, 0.5 + 0.1 * vendor_votes[best])
        elif blocked_count >= 2:
            profile.detected = True
            profile.confidence = min(0.9, 0.3 + 0.15 * blocked_count)
            profile.notes.append(
                "multiple probes were blocked without a vendor signature"
            )
        elif blocked_count == 1:
            profile.confidence = 0.2
            profile.notes.append("one probe was blocked; may be a transient rate limit")
        else:
            profile.notes.append("no WAF signatures observed")

        return profile
