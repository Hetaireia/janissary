"""Authentication helpers for JANISSARY (static v1).

Scope of v1: static credentials. Apply a cookie string and/or a bearer
token to a requests.Session before scanning. No refresh hooks; a token
that expires mid-scan will produce a run of 401s and that's a documented
limitation.

Public surface
--------------
    AuthConfig          - dataclass holding cookie/bearer
    apply_to_session    - install headers on a requests.Session
    add_auth_flags      - register --cookie/--bearer on a subparser
    auth_from_args      - build AuthConfig from parsed args
    redact_headers      - return a copy of a header dict with secrets swapped
"""

from __future__ import annotations

from dataclasses import dataclass

REDACTED = "[REDACTED]"
_SECRET_HEADERS = frozenset(
    {"authorization", "cookie", "set-cookie", "proxy-authorization"}
)


@dataclass(frozen=True)
class SessionSpec:
    """One auth credential set used by tri-session rotation (ADR-023).

    Mirrors AuthConfig's cookie/bearer shape but is frozen and excludes
    the sessions list (a SessionSpec cannot itself hold sessions).
    """

    cookie: str | None = None
    bearer: str | None = None

    def headers(self) -> dict:
        out: dict = {}
        if self.cookie:
            out["Cookie"] = self.cookie
        if self.bearer:
            out["Authorization"] = f"Bearer {self.bearer}"
        return out


@dataclass
class AuthConfig:
    cookie: str | None = None
    bearer: str | None = None
    sessions: list[SessionSpec] | None = None

    @property
    def is_empty(self) -> bool:
        if self.sessions:
            return False
        return not self.cookie and not self.bearer

    def headers(self) -> dict:
        if self.sessions:
            return self.sessions[0].headers()
        out: dict = {}
        if self.cookie:
            out["Cookie"] = self.cookie
        if self.bearer:
            out["Authorization"] = f"Bearer {self.bearer}"
        return out

    def to_dict(self) -> dict:
        return {
            "cookie": REDACTED if self.cookie else None,
            "bearer": REDACTED if self.bearer else None,
            "sessions": (
                [REDACTED] * len(self.sessions) if self.sessions else None
            ),
        }


def apply_to_session(session, config: AuthConfig) -> None:
    """Install the configured auth headers on a requests.Session.

    Idempotent: calling twice with the same config is a no-op after the first.
    Clears managed headers (Cookie, Authorization) before setting so that
    rotation between sessions with different header profiles does not leak
    stale values (ADR-023 D3).
    """
    if config is None or config.is_empty:
        return
    for h in ("Cookie", "Authorization"):
        session.headers.pop(h, None)
    for k, v in config.headers().items():
        session.headers[k] = v


def add_auth_flags(parser) -> None:
    parser.add_argument(
        "--cookie",
        default=None,
        metavar="STRING",
        help=(
            "Raw cookie header value (e.g. 'session=abc; csrf=xyz'). "
            "Sent verbatim on every request."
        ),
    )
    parser.add_argument(
        "--bearer",
        default=None,
        metavar="TOKEN",
        help="Bearer token; sets 'Authorization: Bearer TOKEN' on every request.",
    )
    parser.add_argument(
        "--sessions",
        default=None,
        metavar="PATH",
        help=(
            "JSON file with 2+ sessions for 401-triggered rotation (ADR-023). "
            "Array of {cookie, bearer} objects. Mutually exclusive with --cookie/--bearer."
        ),
    )
    parser.add_argument(
        "--redact-auth",
        action="store_true",
        help=(
            "Redact Authorization/Cookie header values in JSON/JSONL output. "
            "Wire-level raw_request/raw_response are NOT redacted so Burp "
            "Repeater still works. Use this before sharing scan output."
        ),
    )


def auth_from_args(args) -> AuthConfig:
    sessions_path = getattr(args, "sessions", None)
    if sessions_path:
        return AuthConfig(sessions=load_sessions_file(sessions_path))
    return AuthConfig(
        cookie=getattr(args, "cookie", None),
        bearer=getattr(args, "bearer", None),
    )


def redact_headers(headers) -> dict:
    """Return a copy of a header mapping with secret values replaced."""
    if not headers:
        return {}
    out: dict = {}
    for k, v in headers.items():
        if str(k).lower() in _SECRET_HEADERS:
            out[str(k)] = REDACTED
        else:
            out[str(k)] = v
    return out


def redact_raw_http(raw: str | None) -> str | None:
    """Replace secret header values inside a raw HTTP/1.1 blob.

    Only touches the header block (everything before the first blank line).
    Body bytes are left alone. Line endings preserved.
    """
    if not raw:
        return raw
    head, sep, body = raw.partition("\r\n\r\n")
    if not sep:
        head, sep, body = raw.partition("\n\n")
        newline = "\n"
    else:
        newline = "\r\n"
    lines = head.split(newline)
    if not lines:
        return raw
    out_lines = [lines[0]]
    for line in lines[1:]:
        if ":" not in line:
            out_lines.append(line)
            continue
        name, _, _ = line.partition(":")
        if name.strip().lower() in _SECRET_HEADERS:
            out_lines.append(f"{name}: {REDACTED}")
        else:
            out_lines.append(line)
    return newline.join(out_lines) + sep + body

def load_sessions_file(path: str) -> list[SessionSpec]:
    """Load a tri-session JSON file (ADR-023 D4).

    Format: JSON array of {"cookie": str|null, "bearer": str|null} objects.
    Raises ValueError on malformed input (empty array, missing both fields,
    non-list root, non-object elements).
    """
    import json

    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, list):
        raise ValueError(
            f"--sessions: expected JSON array, got {type(data).__name__}"
        )
    if len(data) < 2:
        raise ValueError(
            f"--sessions: need at least 2 entries, got {len(data)} "
            f"(use --cookie/--bearer for single session)"
        )
    out: list[SessionSpec] = []
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            raise ValueError(f"--sessions[{i}]: expected object, got {type(item).__name__}")
        cookie = item.get("cookie")
        bearer = item.get("bearer")
        if cookie is None and bearer is None:
            raise ValueError(f"--sessions[{i}]: needs at least one of cookie/bearer")
        if cookie is not None and not isinstance(cookie, str):
            raise ValueError(f"--sessions[{i}].cookie: expected string or null")
        if bearer is not None and not isinstance(bearer, str):
            raise ValueError(f"--sessions[{i}].bearer: expected string or null")
        out.append(SessionSpec(cookie=cookie, bearer=bearer))
    return out
