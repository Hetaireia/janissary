"""Shared types for the heuristic (Track B) engine."""

from __future__ import annotations

from dataclasses import dataclass, field

#: Body size above which StaticFixtureProvider rejects a record.
#: Scanner-produced observations are not subject to this limit —
#: enforcement lives at the untrusted-input boundary only.
OBSERVATION_BODY_MAX_BYTES: int = 1_000_000

#: Fields a JSONL fixture record is allowed to supply.
OBSERVATION_FIXTURE_ALLOWED_FIELDS: frozenset[str] = frozenset(
    {
        "url",
        "body",
        "headers",
        "method",
        "response_status",
        "payload_name",
        "payload_value",
        "param",
    }
)

#: Pattern a provider's ``source_id`` must match.
OBSERVATION_PROVIDER_ID_PATTERN: str = r"^[a-z0-9](?:[a-z0-9:_-]*[a-z0-9])?$"


@dataclass(frozen=True)
class Observation:
    """An immutable observation collected by an observation provider.

    Contains the request/response context required for heuristic analysis,
    together with provider provenance and deterministic observation identity.

    Observations represent discovery evidence only; they are not verified
    findings.
    """

    url: str
    body: str
    headers: dict[str, str] = field(default_factory=dict)
    method: str = "GET"
    response_status: int | None = None
    payload_name: str = ""
    payload_value: str = ""
    param: str = ""

    # Provenance: which provider emitted this observation.
    # Supplied by the provider, never by a fixture record.
    # For ScannerProvider this embeds id(scanner) and is process-specific;
    # do not rely on it across executions.
    source_id: str = ""

    # Content-addressed probe identity: full SHA-256 hex of the canonical
    # (url, method, param, payload_name, payload_value) tuple. This is a
    # PROBE identity, not a complete observation identity. Body and headers
    # are excluded from the hash; two HTTP transactions that differ only in
    # response body or headers share the same value.
    # Rationale: M82 must be able to group repeated measurements of the
    # same probe, not treat each HTTP transaction as a distinct event.
    observation_id: str = ""
