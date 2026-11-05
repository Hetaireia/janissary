"""BaselineNormalizer interface (Phase 0.3).

See docs/ROADMAP.md Phase 0.3.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True)
class NormalizedResponse:
    """Output of BaselineNormalizer.normalize().

    `body` is the protocol-agnostic payload of interest (HTTP: response
    text; WebSocket: message sequence; gRPC: decoded Protobuf). `stripped`
    lists what was removed, so a finding can record "these were volatile
    and ignored" - the Phase 0.3 transparency requirement.
    """

    body: str
    length: int
    status: int | None
    headers: dict[str, str] = field(default_factory=dict)
    stripped: tuple[str, ...] = ()


@runtime_checkable
class BaselineNormalizer(Protocol):
    """Protocol-agnostic baseline normalizer.

    Implementations must be stateless (or thread-safe) - the engine may
    call normalize() concurrently for baseline and attack responses.
    """

    protocol_name: str

    def normalize(self, response: Any) -> NormalizedResponse: ...
