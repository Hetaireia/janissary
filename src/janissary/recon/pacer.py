"""Adaptive request pacer for JANISSARY.

The pacer tracks how the target responds to a stream of requests and
adjusts the delay between them. If it sees block-style status codes,
repeated errors, or a WAF profile, it backs off. If responses stay
clean it gradually recovers toward a floor delay.

The scanner calls `wait()` before each request and
`record(status, elapsed)` after each response. The pacer owns its own
state; nothing else needs to know about the backoff curve.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BLOCK_STATUSES = frozenset({403, 406, 418, 429, 501, 503})


@dataclass
class PacerConfig:
    base_delay: float = 0.0
    min_delay: float = 0.0
    max_delay: float = 30.0
    backoff_factor: float = 2.0
    recovery_factor: float = 0.75
    clean_streak_before_recovery: int = 5
    block_streak_before_hard_backoff: int = 2
    jitter: float = 0.1


# ---------------------------------------------------------------------------
# Pacer
# ---------------------------------------------------------------------------


class AdaptivePacer:
    """Stateful adaptive delay between requests.

    Usage:
        pacer = AdaptivePacer(...)
        ...
        pacer.wait()
        r = session.get(...)
        pacer.record(r.status_code, elapsed)
    """

    def __init__(
        self,
        config: PacerConfig | None = None,
        waf_profile=None,
        sleep=time.sleep,
    ) -> None:
        self.config = config or PacerConfig()
        self.sleep = sleep

        # Starting delay: honours the user's --delay, then bumps it if a
        # WAF was detected so we begin stealthy rather than get banned.
        self.delay = max(self.config.base_delay, self.config.min_delay)
        if waf_profile is not None and getattr(waf_profile, "detected", False):
            bump = 1.0 + 2.0 * float(getattr(waf_profile, "confidence", 0.0) or 0.0)
            self.delay = max(self.delay, min(self.config.max_delay, bump))

        self._clean_streak = 0
        self._block_streak = 0
        self._events: list[dict] = []

    # ---------------------------------------------------------------

    def wait(self) -> None:
        if self.delay > 0:
            self.sleep(self.delay)

    # ---------------------------------------------------------------

    def record(self, status: int | None, elapsed: float = 0.0) -> None:
        event = {"status": status, "elapsed": elapsed, "delay": self.delay}

        if status is None:
            # Network error: treat like a soft block.
            self._block_streak += 1
            self._clean_streak = 0
            self._backoff()
            event["action"] = "backoff_error"
            self._events.append(event)
            return

        if status in BLOCK_STATUSES:
            self._block_streak += 1
            self._clean_streak = 0
            # Fast 403s are the classic WAF tell; escalate immediately.
            if self._block_streak >= self.config.block_streak_before_hard_backoff:
                self.delay = min(self.config.max_delay, max(self.delay, 1.0) * 2.0)
                event["action"] = "hard_backoff"
            else:
                self._backoff()
                event["action"] = "backoff_block"
            self._events.append(event)
            return

        if 500 <= status < 600 and status not in BLOCK_STATUSES:
            # Server-side error: not a block signal, not a success. The app
            # (or its upstream) failed to serve the request. Backing off here
            # does not help -- it just slows the scan on targets that return
            # 5xx for unknown input. Do not count it toward recovery either.
            self._clean_streak = 0
            event["action"] = "server_error_no_backoff"
            self._events.append(event)
            return

        # Success path.
        self._block_streak = 0
        self._clean_streak += 1
        if self._clean_streak >= self.config.clean_streak_before_recovery:
            before = self.delay
            self.delay = max(
                self.config.min_delay, self.delay * self.config.recovery_factor
            )
            if self.delay != before:
                event["action"] = "recover"
            self._clean_streak = 0
        self._events.append(event)

    # ---------------------------------------------------------------

    def _backoff(self) -> None:
        if self.delay <= 0:
            self.delay = max(self.config.min_delay, 0.5)
        else:
            self.delay = min(
                self.config.max_delay, self.delay * self.config.backoff_factor
            )

    # ---------------------------------------------------------------

    @property
    def events(self) -> list[dict]:
        return list(self._events)

    def stats(self) -> dict:
        return {
            "current_delay": round(self.delay, 4),
            "clean_streak": self._clean_streak,
            "block_streak": self._block_streak,
            "events": len(self._events),
        }
