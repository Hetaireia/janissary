"""WebSocket reconnaissance harness.

Probes a WebSocket endpoint for a small set of well-known weaknesses:

- plaintext ``ws://`` on a non-loopback host,
- missing Origin validation (cross-site WebSocket hijacking),
- blind echo of client payloads (XSS / JSONi risk downstream),
- whether the server completes a handshake without authentication.

The module is async-first. ``scan()`` is the async entry point;
``scan_sync()`` wraps it via ``asyncio.run`` for callers that live in
synchronous code (CLI, scanner engine). Tests spin up an in-process
``websockets.serve`` instance.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from dataclasses import dataclass, field
from urllib.parse import urlparse

import websockets

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0"})  # nosec # classification set, not a bind address

DEFAULT_ECHO_PAYLOAD = "<script>alert(1)</script>"

DEFAULT_EVIL_ORIGIN = "http://evil.example.com"

PING_MESSAGE = "__janissary_ping__"

# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class WebSocketFinding:
    category: str
    severity: str
    detail: str

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "severity": self.severity,
            "detail": self.detail,
        }


@dataclass
class WebSocketProfile:
    url: str
    reachable: bool = False
    scheme: str = ""
    subprotocol: str = ""
    server_header: str = ""
    messages_sent: int = 0
    messages_received: int = 0
    findings: list[WebSocketFinding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "reachable": self.reachable,
            "scheme": self.scheme,
            "subprotocol": self.subprotocol,
            "server_header": self.server_header,
            "messages_sent": self.messages_sent,
            "messages_received": self.messages_received,
            "findings": [f.to_dict() for f in self.findings],
            "notes": list(self.notes),
        }


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------


def is_plaintext(url: str) -> bool:
    """True if the URL uses ws:// against a non-loopback host."""
    parsed = urlparse(url)
    if parsed.scheme.lower() != "ws":
        return False
    host = (parsed.hostname or "").lower()
    return host not in LOOPBACK_HOSTS


# ---------------------------------------------------------------------------
# Low-level connect
# ---------------------------------------------------------------------------


async def _connect(
    url: str,
    timeout: float = 10.0,
    origin: str | None = None,
    headers: dict | None = None,
    subprotocols: list[str] | None = None,
    proxy: str | None = None,
):
    kwargs: dict = {
        "open_timeout": timeout,
        "close_timeout": timeout,
        "user_agent_header": DEFAULT_UA,
        # Never inherit environment proxy settings for a scanner run.
        "proxy": proxy,
    }
    if headers:
        kwargs["additional_headers"] = dict(headers)
    if origin:
        kwargs["origin"] = origin
    if subprotocols:
        kwargs["subprotocols"] = subprotocols

    return await websockets.connect(url, **kwargs)


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------


async def scan(
    url: str,
    timeout: float = 10.0,
    origin: str | None = None,
    evil_origin: str = DEFAULT_EVIL_ORIGIN,
    headers: dict | None = None,
    echo_payload: str = DEFAULT_ECHO_PAYLOAD,
    subprotocols: list[str] | None = None,
) -> WebSocketProfile:
    profile = WebSocketProfile(url=url)
    parsed = urlparse(url)
    profile.scheme = (parsed.scheme or "").lower()

    if is_plaintext(url):
        profile.findings.append(
            WebSocketFinding(
                category="plaintext",
                severity="medium",
                detail=f"plaintext ws:// on {parsed.hostname}",
            )
        )
    if profile.scheme not in ("ws", "wss"):
        profile.notes.append(f"unusual scheme: {profile.scheme!r}")

    # ------------------------------------------------------------------
    # Baseline connect
    # ------------------------------------------------------------------
    try:
        ws = await _connect(
            url,
            timeout=timeout,
            origin=origin,
            headers=headers,
            subprotocols=subprotocols,
        )
    except Exception as exc:
        profile.notes.append(f"baseline connect failed: {type(exc).__name__}: {exc}")
        return profile

    profile.reachable = True
    profile.subprotocol = getattr(ws, "subprotocol", "") or ""
    response = getattr(ws, "response", None)
    if response is not None:
        with contextlib.suppress(Exception):
            profile.server_header = str(response.headers.get("Server", ""))

    # ------------------------------------------------------------------
    # Echo probe
    # ------------------------------------------------------------------
    try:
        await ws.send(echo_payload)
        profile.messages_sent += 1
        reply = await asyncio.wait_for(ws.recv(), timeout=timeout)
        profile.messages_received += 1
        text = reply if isinstance(reply, str) else reply.decode("utf-8", "replace")
        if echo_payload in text:
            profile.findings.append(
                WebSocketFinding(
                    category="echo",
                    severity="medium",
                    detail=f"payload echoed verbatim: {text[:80]!r}",
                )
            )
    except asyncio.TimeoutError:
        profile.notes.append("no reply to echo payload within timeout")
    except Exception as exc:
        profile.notes.append(f"echo probe error: {type(exc).__name__}")
    finally:
        with contextlib.suppress(Exception):
            await ws.close()

    # ------------------------------------------------------------------
    # Origin check (cross-site WebSocket hijacking)
    # ------------------------------------------------------------------
    if evil_origin:
        try:
            ws2 = await _connect(
                url,
                timeout=timeout,
                origin=evil_origin,
                headers=headers,
                subprotocols=subprotocols,
            )
        except Exception as exc:
            profile.notes.append(f"origin check appears enforced: {type(exc).__name__}")
        else:
            profile.findings.append(
                WebSocketFinding(
                    category="missing-origin-check",
                    severity="high",
                    detail=f"server accepted connection with Origin: {evil_origin}",
                )
            )
            with contextlib.suppress(Exception):
                await ws2.close()

    return profile


# ---------------------------------------------------------------------------
# Sync wrapper
# ---------------------------------------------------------------------------


def scan_sync(url: str, **kwargs) -> WebSocketProfile:
    """Synchronous wrapper around ``scan`` for CLI and sync callers."""
    return asyncio.run(scan(url, **kwargs))


# ---------------------------------------------------------------------------
# JSON convenience
# ---------------------------------------------------------------------------


def profile_to_json(profile: WebSocketProfile) -> str:
    return json.dumps(profile.to_dict(), indent=2)
