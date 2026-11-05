"""Session rotation state machine (ADR-023 D2).

Tracks which session from a tri-session list is currently active.
Rotation is one-way: once exhausted, stays exhausted. This prevents
ping-ponging between A and B when both are failing.

The rotator does not apply sessions to HTTP sessions -- that is
auth.apply_to_session's job. This module is pure state.
"""

from __future__ import annotations

from janissary.auth import SessionSpec


class SessionRotator:
    """Tracks current session index across a tri-session scan.

    Not thread-safe; each scan has one rotator.
    """

    def __init__(self, sessions: list[SessionSpec]) -> None:
        if len(sessions) < 2:
            raise ValueError(
                f"SessionRotator requires >= 2 sessions, got {len(sessions)}"
            )
        self._sessions = list(sessions)
        self._current_index = 0
        self._exhausted = False

    def current(self) -> SessionSpec:
        return self._sessions[self._current_index]

    def can_rotate(self) -> bool:
        return not self._exhausted

    def rotate(self) -> SessionSpec | None:
        """Advance to next session. Returns None if exhausted (no-op)."""
        if self._exhausted:
            return None
        self._current_index += 1
        if self._current_index >= len(self._sessions):
            self._exhausted = True
            return None
        return self._sessions[self._current_index]

    @property
    def current_index(self) -> int:
        return self._current_index

    @property
    def attempted_count(self) -> int:
        """Number of sessions tried so far (for abort message, ADR-023 D10)."""
        return self._current_index + 1

    @property
    def total(self) -> int:
        return len(self._sessions)

    @property
    def exhausted(self) -> bool:
        return self._exhausted
