"""GraphQL reconnaissance and fuzzing harness.

GraphQL endpoints accept a single POST that carries an arbitrarily
complex query tree. That makes them attractive for abuse: one HTTP
request can nest thousands of fields, run thousands of aliased copies
of the same field, or batch many queries together. The usual per-
request rate limiting and WAF signatures struggle with a single,
well-formed JSON blob.

This module provides:

- ``GraphQLClient`` — thin JSON POST wrapper with per-request hooks
  for depth, aliases, and batching.
- ``detect()`` — probes an endpoint and reports whether GraphQL is
  present, whether introspection is allowed, and whether batched
  queries are accepted.
- ``introspect()`` — runs the standard introspection query and
  returns the schema dict when permitted.
- ``enumerate_fields()`` — extracts field-name suggestions from
  "Did you mean" error messages.
- ``depth_probe()`` — finds the depth at which the server refuses.
- ``alias_probe()`` — finds the alias count at which the server
  refuses.
- ``fuzz_arguments()`` — sends a small library of payloads into a
  known field/argument and returns the raw responses for offline
  analysis.

The module does not depend on the scanner, the WAF detector, or the
pacer. Callers wire those in.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any

import requests

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

DEFAULT_ENDPOINT_PATHS: tuple[str, ...] = (
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/query",
    "/gql",
)

# ---------------------------------------------------------------------------
# Standard introspection query
# ---------------------------------------------------------------------------

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      description
      fields {
        name
        description
        args {
          name
          type { kind name ofType { kind name } }
        }
        type { kind name ofType { kind name } }
      }
    }
  }
}
""".strip()

TYPENAME_QUERY = "{__typename}"

# Errors that suggest the field name is close but wrong.
SUGGESTION_RE = re.compile(
    r'Did you mean\s+["\']?([A-Za-z_][A-Za-z0-9_]*)["\']?', re.IGNORECASE
)

# Errors indicating a depth or complexity cap.
DEPTH_ERROR_RE = re.compile(
    r"(depth|complexity|too (?:deep|complex)|max(?:imum)? depth)",
    re.IGNORECASE,
)

# Errors indicating an alias cap.
ALIAS_ERROR_RE = re.compile(
    r"(too many aliases|alias.*(?:limit|exceed)|max.*alias)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Argument payload library
# ---------------------------------------------------------------------------

ARG_PAYLOADS: list[tuple[str, Any]] = [
    ("sqli_quote", "'"),
    ("sqli_or", "' OR '1'='1"),
    ("sqli_comment", "'--"),
    ("nosqli_ne", {"$ne": None}),
    ("nosqli_gt", {"$gt": ""}),
    ("ssrf_url", "http://169.254.169.254/latest/meta-data/"),
    ("traversal", "../../../etc/passwd"),
    ("null_byte", "\x00"),
    ("deep_object", {"a": {"b": {"c": {"d": {"e": 1}}}}}),
]

# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class GraphQLError:
    message: str
    path: list | None = None
    extensions: dict | None = None


@dataclass
class GraphQLResponse:
    status: int | None
    elapsed: float
    body: Any
    errors: list[GraphQLError] = field(default_factory=list)
    data: Any = None
    note: str = ""

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 300

    def error_messages(self) -> list[str]:
        return [e.message for e in self.errors]


@dataclass
class GraphQLProfile:
    endpoint: str
    reachable: bool = False
    introspection_enabled: bool = False
    schema: dict | None = None
    query_type: str | None = None
    mutation_type: str | None = None
    subscription_type: str | None = None
    type_count: int = 0
    batched_queries: bool = False
    max_depth: int | None = None
    max_aliases: int | None = None
    suggestions_supported: bool = False
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "endpoint": self.endpoint,
            "reachable": self.reachable,
            "introspection_enabled": self.introspection_enabled,
            "query_type": self.query_type,
            "mutation_type": self.mutation_type,
            "subscription_type": self.subscription_type,
            "type_count": self.type_count,
            "batched_queries": self.batched_queries,
            "max_depth": self.max_depth,
            "max_aliases": self.max_aliases,
            "suggestions_supported": self.suggestions_supported,
            "notes": list(self.notes),
        }


# ---------------------------------------------------------------------------
# Query builders
# ---------------------------------------------------------------------------


def build_nested_query(field: str, depth: int) -> str:
    """Build a query that nests ``field`` ``depth`` levels deep."""
    depth = max(1, int(depth))
    inner = field
    for _ in range(depth - 1):
        inner = f"{field} {{ {inner} }}"
    return "{ " + inner + " }"


def build_alias_query(field: str, count: int) -> str:
    """Build a query with ``count`` aliases of the same field."""
    count = max(1, int(count))
    parts = [f"a{i}: {field}" for i in range(count)]
    return "{ " + " ".join(parts) + " }"


def build_argument_query(field: str, arg: str, value: Any) -> str:
    """Build ``{ field(arg: <literal>) }`` with a JSON-ish literal."""
    return "{ " + f"{field}({arg}: {_gql_literal(value)})" + " }"


def _gql_literal(value: Any) -> str:
    """Serialise a Python value as a GraphQL literal (not JSON)."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        escaped = (
            value.replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\n", "\\n")
            .replace("\x00", "\\u0000")
        )
        return f'"{escaped}"'
    if isinstance(value, dict):
        inner = ", ".join(f"{k}: {_gql_literal(v)}" for k, v in value.items())
        return "{" + inner + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_gql_literal(v) for v in value) + "]"
    return f'"{value!s}"'


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class GraphQLClient:
    def __init__(
        self,
        endpoint: str,
        timeout: float = 10.0,
        proxies: dict | None = None,
        session: requests.Session | None = None,
        user_agent: str | None = None,
        extra_headers: dict | None = None,
    ) -> None:
        self.endpoint = endpoint
        self.timeout = timeout
        self.proxies = proxies
        self.session = session or requests.Session()
        self.user_agent = user_agent or DEFAULT_UA
        self.extra_headers = dict(extra_headers or {})

    def _headers(self) -> dict:
        h = {
            "User-Agent": self.user_agent,
            "Content-Type": "application/json",
            "Accept": "application/json, */*;q=0.8",
            "Accept-Encoding": "identity",
            "Connection": "close",
        }
        h.update(self.extra_headers)
        return h

    def post_raw(self, payload: Any) -> requests.Response:
        return self.session.post(
            self.endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers=self._headers(),
            timeout=self.timeout,
            allow_redirects=False,
            proxies=self.proxies,
        )

    def query(self, query: str, variables: dict | None = None) -> GraphQLResponse:
        payload: dict = {"query": query}
        if variables:
            payload["variables"] = variables
        return self._send(payload)

    def batch(self, queries: list[str]) -> GraphQLResponse:
        payload = [{"query": q} for q in queries]
        return self._send(payload)

    def _send(self, payload: Any) -> GraphQLResponse:
        start = time.perf_counter()
        try:
            r = self.post_raw(payload)
        except requests.RequestException as exc:
            return GraphQLResponse(
                status=None,
                elapsed=time.perf_counter() - start,
                body=None,
                note=f"transport error: {exc}",
            )
        elapsed = time.perf_counter() - start
        return _parse_response(r, elapsed)


def _parse_response(r: requests.Response, elapsed: float) -> GraphQLResponse:
    body: Any = None
    try:
        body = r.json()
    except ValueError:
        body = r.text

    errors: list[GraphQLError] = []
    data: Any = None

    if isinstance(body, dict):
        for err in body.get("errors") or []:
            if isinstance(err, dict):
                errors.append(
                    GraphQLError(
                        message=str(err.get("message", "")),
                        path=err.get("path"),
                        extensions=err.get("extensions"),
                    )
                )
        data = body.get("data")
    elif isinstance(body, list):
        # Batched response. Flatten errors/data.
        for entry in body:
            if isinstance(entry, dict):
                for err in entry.get("errors") or []:
                    if isinstance(err, dict):
                        errors.append(
                            GraphQLError(
                                message=str(err.get("message", "")),
                                path=err.get("path"),
                                extensions=err.get("extensions"),
                            )
                        )

    return GraphQLResponse(
        status=r.status_code,
        elapsed=elapsed,
        body=body,
        errors=errors,
        data=data,
    )


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def resolve_endpoint(base_url: str, explicit_path: str | None = None) -> list[str]:
    """Return candidate endpoints to probe, in priority order.

    If the URL already looks like a GraphQL path it is tried first,
    followed by the standard candidates.
    """
    base = (base_url or "").rstrip("/")
    candidates: list[str] = []
    if explicit_path:
        candidates.append(base + "/" + explicit_path.lstrip("/"))
    low = base.lower()
    if "/graphql" in low or low.endswith("/gql") or low.endswith("/query"):
        candidates.append(base)
    for path in DEFAULT_ENDPOINT_PATHS:
        candidates.append(base + path)
    # De-dupe while preserving order.
    seen: set[str] = set()
    out: list[str] = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def detect(
    base_url: str,
    client: GraphQLClient | None = None,
    timeout: float = 10.0,
    proxies: dict | None = None,
    session: requests.Session | None = None,
    explicit_path: str | None = None,
    probe_batching: bool = True,
) -> GraphQLProfile:
    """Probe candidate endpoints for GraphQL and return a profile."""
    if client is not None:
        # Caller supplied a client: probe that one endpoint and return
        # whatever we learn, reachable or not.
        return _probe_endpoint(client, client.endpoint, probe_batching=probe_batching)

    candidates = resolve_endpoint(base_url, explicit_path)
    last: GraphQLProfile | None = None
    for endpoint in candidates:
        cli = GraphQLClient(endpoint, timeout=timeout, proxies=proxies, session=session)
        profile = _probe_endpoint(cli, endpoint, probe_batching=probe_batching)
        last = profile
        if profile.reachable:
            return profile

    if last is not None:
        return last
    return GraphQLProfile(
        endpoint=base_url,
        reachable=False,
        notes=["no GraphQL endpoint responded"],
    )


def _probe_endpoint(
    client: GraphQLClient, endpoint: str, probe_batching: bool
) -> GraphQLProfile:
    profile = GraphQLProfile(endpoint=endpoint)

    # Step 1: minimal __typename probe.
    resp = client.query(TYPENAME_QUERY)
    if resp.status is None:
        profile.notes.append(resp.note or "transport error")
        return profile
    if not resp.ok:
        profile.notes.append(f"HTTP {resp.status}")
        return profile
    if not isinstance(resp.body, dict):
        profile.notes.append("response was not JSON object")
        return profile
    if resp.data is None and not resp.errors:
        profile.notes.append("no data or errors in response")
        return profile

    profile.reachable = True

    # Step 2: introspection.
    intro = client.query(INTROSPECTION_QUERY)
    if intro.ok and isinstance(intro.data, dict) and "__schema" in intro.data:
        schema = intro.data.get("__schema") or {}
        profile.introspection_enabled = True
        profile.schema = schema
        profile.query_type = _type_name(schema.get("queryType"))
        profile.mutation_type = _type_name(schema.get("mutationType"))
        profile.subscription_type = _type_name(schema.get("subscriptionType"))
        profile.type_count = len(schema.get("types") or [])
    else:
        # Introspection disabled is a valid finding.
        messages = intro.error_messages()
        if messages:
            profile.notes.append(f"introspection rejected: {messages[0][:80]}")
        else:
            profile.notes.append("introspection returned no schema")

    # Step 3: batching.
    if probe_batching:
        batch = client.batch([TYPENAME_QUERY, TYPENAME_QUERY])
        if batch.ok and isinstance(batch.body, list):
            profile.batched_queries = True

    # Step 4: field-suggestion support.
    sugg = client.query("{ __definitelyNotARealField_xyz }")
    for msg in sugg.error_messages():
        if SUGGESTION_RE.search(msg):
            profile.suggestions_supported = True
            break

    return profile


def _type_name(node: Any) -> str | None:
    if isinstance(node, dict):
        name = node.get("name")
        return str(name) if name else None
    return None


# ---------------------------------------------------------------------------
# Field enumeration via suggestions
# ---------------------------------------------------------------------------


def enumerate_fields(
    client: GraphQLClient,
    root_type: str = "Query",
    seed_chars: str = "abcdefghijklmnopqrstuvwxyz",
    max_rounds: int = 2,
) -> list[str]:
    """Recover field names using 'Did you mean' suggestions.

    Works only when the server emits suggestions. Each round probes
    with a near-miss per seed character and records every suggested
    name. Subsequent rounds seed from the discovered names.
    """
    found: set[str] = set()
    frontier = list(seed_chars)

    for _ in range(max(1, max_rounds)):
        new_names: set[str] = set()
        for seed in frontier:
            # Build a plausible-but-wrong field name.
            probe_name = f"__{seed}_notarealfield"
            resp = client.query("{ " + probe_name + " }")
            for msg in resp.error_messages():
                for m in SUGGESTION_RE.finditer(msg):
                    new_names.add(m.group(1))

        fresh = new_names - found
        if not fresh:
            break
        found |= fresh
        frontier = sorted(fresh)

    return sorted(found)


# ---------------------------------------------------------------------------
# Depth and alias probes
# ---------------------------------------------------------------------------


def depth_probe(
    client: GraphQLClient,
    field_name: str = "__typename",
    start: int = 1,
    ceiling: int = 32,
) -> tuple[int | None, str]:
    """Return the deepest accepted depth and the refusal message.

    Doubles the depth until a refusal, then binary-searches between the
    last success and first failure.
    """
    low = 0
    high: int | None = None
    refusal = ""

    d = start
    while d <= ceiling:
        resp = client.query(build_nested_query(field_name, d))
        if _refused(resp, DEPTH_ERROR_RE) or _is_error_only(resp):
            high = d
            refusal = (resp.error_messages() or [resp.note or ""])[0]
            break
        low = d
        d *= 2

    if high is None:
        # Never refused within ceiling.
        return low or None, ""

    # Binary search between low and high.
    while low + 1 < high:
        mid = (low + high) // 2
        resp = client.query(build_nested_query(field_name, mid))
        if _refused(resp, DEPTH_ERROR_RE) or _is_error_only(resp):
            high = mid
            refusal = (resp.error_messages() or [resp.note or ""])[0]
        else:
            low = mid

    return low or None, refusal


def alias_probe(
    client: GraphQLClient,
    field_name: str = "__typename",
    start: int = 10,
    ceiling: int = 10_000,
) -> tuple[int | None, str]:
    """Return the largest alias count accepted and the refusal message."""
    low = 0
    high: int | None = None
    refusal = ""

    n = start
    while n <= ceiling:
        resp = client.query(build_alias_query(field_name, n))
        if _refused(resp, ALIAS_ERROR_RE) or _is_error_only(resp):
            high = n
            refusal = (resp.error_messages() or [resp.note or ""])[0]
            break
        low = n
        n *= 4

    if high is None:
        return low or None, ""

    while low + 1 < high:
        mid = (low + high) // 2
        resp = client.query(build_alias_query(field_name, mid))
        if _refused(resp, ALIAS_ERROR_RE) or _is_error_only(resp):
            high = mid
            refusal = (resp.error_messages() or [resp.note or ""])[0]
        else:
            low = mid

    return low or None, refusal


def _refused(resp: GraphQLResponse, pattern: re.Pattern) -> bool:
    return any(pattern.search(msg) for msg in resp.error_messages())


def _is_error_only(resp: GraphQLResponse) -> bool:
    """A response with errors and no data usually means the server refused."""
    return bool(resp.errors) and resp.data in (None, {})


# ---------------------------------------------------------------------------
# Argument fuzzing
# ---------------------------------------------------------------------------


@dataclass
class FuzzResult:
    field: str
    arg: str
    payload_name: str
    payload_value: Any
    status: int | None
    elapsed: float
    errors: list[str]
    data: Any
    body: Any

    def to_dict(self) -> dict:
        return {
            "field": self.field,
            "arg": self.arg,
            "payload_name": self.payload_name,
            "payload_value": self.payload_value,
            "status": self.status,
            "elapsed": round(self.elapsed, 4),
            "errors": list(self.errors),
        }


def fuzz_arguments(
    client: GraphQLClient,
    field_name: str,
    arg_name: str,
    payloads: list[tuple[str, Any]] | None = None,
) -> list[FuzzResult]:
    """Send each payload into ``field_name(arg_name: <payload>)``."""
    payloads = payloads if payloads is not None else ARG_PAYLOADS
    results: list[FuzzResult] = []

    for name, value in payloads:
        query = build_argument_query(field_name, arg_name, value)
        resp = client.query(query)
        results.append(
            FuzzResult(
                field=field_name,
                arg=arg_name,
                payload_name=name,
                payload_value=value,
                status=resp.status,
                elapsed=resp.elapsed,
                errors=resp.error_messages(),
                data=resp.data,
                body=resp.body,
            )
        )

    return results
