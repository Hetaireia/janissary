"""Burp-compatible collaborator client for SSRF detection (ADR-012 D1).

User supplies an external collaborator endpoint via --collaborator.
Client speaks the standard Burp poll protocol (Burp Pro, interactsh,
ProjectDiscovery interact.sh):

    GET <base>/poll?id=<unique>
    -> {"responses": [{"protocol": "dns"|"http", "data": {...}}, ...]}

Session 0.3.15 ships 5 OOB-detectable payloads. ADR-012 D2 lists 8;
the three deferred (metadata_http, metadata_v6, file) cannot be
detected via collaborator OOB; they require response-body inspection
and are planned for a follow-up. Handover records the scope delta.
"""

from __future__ import annotations

import contextlib
import secrets
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


class CollaboratorError(Exception):
    """Transport or protocol failure reaching the collaborator.

    Raised on transport exception, on non-2xx (except 204/404 which mean
    no hits), and on malformed base URL. Caller (Scanner._ssrf_phase)
    catches and continues: unreachable collaborator skips the phase,
    it does not abort the scan.
    """


@dataclass
class SsrfPayload:
    """One SSRF probe template. `url_template` supports {uniq} and {collab}."""

    name: str
    url_template: str
    severity: str = "critical"
    finding_type: str = "collaborator_hit"


@dataclass
class SsrfHit:
    """One collaborator response matching one issued uniq."""

    protocol: str
    payload_name: str
    subdomain: str
    source_ip: str = ""
    timestamp: str = ""
    raw: dict = field(default_factory=dict)


SSRF_PAYLOADS: list[SsrfPayload] = [
    SsrfPayload("ssrf_http", "http://{uniq}.{collab}/"),
    SsrfPayload("ssrf_https", "https://{uniq}.{collab}/"),
    SsrfPayload("ssrf_gopher", "gopher://{uniq}.{collab}:6379/_INFO"),
    SsrfPayload("ssrf_dict", "dict://{uniq}.{collab}:6379/"),
    SsrfPayload("ssrf_dns_only", "http://{uniq}.{collab}:9/"),
]


class CollaboratorClient:
    """Burp-compatible collaborator poll client (ADR-012 D1).

    Subdomain attribution (D2): new_unique_id() returns "jns-<16 hex>"
    and registers against a payload name. Hits map back by substring
    match against issued IDs.
    """

    def __init__(
        self,
        base_url: str,
        timeout: float = 10.0,
        session: requests.Session | None = None,
        user_agent: str | None = None,
    ) -> None:
        self.base_url = (base_url or "").rstrip("/")
        if not self.base_url:
            raise CollaboratorError("collaborator base_url is required")
        self.timeout = timeout
        self.session = session or requests.Session()
        self.user_agent = user_agent or DEFAULT_UA
        self._issued: dict[str, str] = {}

    def _headers(self) -> dict:
        return {
            "User-Agent": self.user_agent,
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "Connection": "close",
        }

    def _collab_host(self) -> str:
        host = urlparse(self.base_url).hostname
        return host or self.base_url

    def new_unique_id(self, payload_name: str = "") -> str:
        uniq = "jns-" + secrets.token_hex(8)
        if payload_name:
            self._issued[uniq] = payload_name
        return uniq

    def payload_for(self, payload: SsrfPayload, uniq: str) -> str:
        return payload.url_template.format(uniq=uniq, collab=self._collab_host())

    def poll(self, uniq: str) -> list[SsrfHit]:
        """Poll for hits matching `uniq` (or any issued uniq).

        204/404 -> empty list. Empty body -> empty list. Malformed JSON
        -> empty list. Transport failure -> CollaboratorError.
        """
        url = f"{self.base_url}/poll?id={uniq}"
        try:
            r = self.session.get(url, headers=self._headers(), timeout=self.timeout)
        except requests.RequestException as exc:
            raise CollaboratorError(f"poll request failed: {exc}") from exc

        if r.status_code in (204, 404):
            return []
        if r.status_code >= 400:
            raise CollaboratorError(f"poll HTTP {r.status_code}")

        text = (r.text or "").strip()
        if not text:
            return []
        try:
            data = r.json()
        except ValueError:
            return []

        responses = data.get("responses") if isinstance(data, dict) else None
        if not isinstance(responses, list):
            return []

        hits: list[SsrfHit] = []
        for item in responses:
            if not isinstance(item, dict):
                continue
            proto = str(item.get("protocol", "")).lower()
            payload_data = item.get("data") or {}
            addr = ""
            source_ip = ""
            if isinstance(payload_data, dict):
                addr = str(
                    payload_data.get("address", "") or payload_data.get("hostname", "")
                )
                source_ip = str(payload_data.get("source_ip", ""))

            matched_uniq = ""
            for issued_uniq in self._issued:
                if issued_uniq in addr or issued_uniq in str(item):
                    matched_uniq = issued_uniq
                    break
            if not matched_uniq and uniq in addr:
                matched_uniq = uniq
            if not matched_uniq:
                continue

            hits.append(
                SsrfHit(
                    protocol=proto,
                    payload_name=self._issued.get(matched_uniq, ""),
                    subdomain=matched_uniq,
                    source_ip=source_ip,
                    timestamp=str(item.get("timestamp", "")),
                    raw=item,
                )
            )
        return hits

    def hits_for(self, uniq: str) -> list[SsrfHit]:
        return self.poll(uniq)

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self.session.close()
