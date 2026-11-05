"""Shared types for the heuristic (Track B) engine."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Observation:
    """A response observation available for heuristic matching.

    Collected by the scanner's payload loop when --heuristic is set
    (ADR-022 D5). The heuristic engine never makes its own requests;
    it only matches against observations already fetched.
    """

    url: str
    body: str
    headers: dict[str, str] = field(default_factory=dict)
    method: str = "GET"
    response_status: int | None = None
    payload_name: str = ""
    payload_value: str = ""
    param: str = ""
