"""Unit tests for the adaptive pacer."""

from __future__ import annotations

from janissary.recon.pacer import AdaptivePacer, PacerConfig


def _no_sleep(_):
    pass


def test_pacer_starts_at_base_delay():
    p = AdaptivePacer(
        config=PacerConfig(base_delay=0.5, min_delay=0.5),
        sleep=_no_sleep,
    )
    assert p.delay == 0.5


def test_pacer_waf_profile_raises_starting_delay():
    class FakeWAF:
        detected = True
        confidence = 0.9

    p = AdaptivePacer(
        config=PacerConfig(base_delay=0.0, min_delay=0.0, max_delay=30.0),
        waf_profile=FakeWAF(),
        sleep=_no_sleep,
    )
    assert p.delay > 0.5


def test_backoff_on_block():
    p = AdaptivePacer(
        config=PacerConfig(base_delay=0.5, min_delay=0.5), sleep=_no_sleep
    )
    start = p.delay
    p.record(403)
    assert p.delay > start


def test_hard_backoff_after_repeated_blocks():
    p = AdaptivePacer(
        config=PacerConfig(base_delay=0.1, min_delay=0.1), sleep=_no_sleep
    )
    p.record(403)
    mid = p.delay
    p.record(403)
    assert p.delay >= mid * 2


def test_recovery_after_clean_streak():
    p = AdaptivePacer(
        config=PacerConfig(
            base_delay=1.0,
            min_delay=0.0,
            recovery_factor=0.5,
            clean_streak_before_recovery=3,
        ),
        sleep=_no_sleep,
    )
    # Force a backoff
    p.record(403)
    high = p.delay
    # Now succeed several times
    for _ in range(3):
        p.record(200)
    assert p.delay < high


def test_network_error_is_treated_as_backoff():
    p = AdaptivePacer(
        config=PacerConfig(base_delay=0.5, min_delay=0.5), sleep=_no_sleep
    )
    before = p.delay
    p.record(None)
    assert p.delay > before


def test_delay_never_exceeds_max():
    p = AdaptivePacer(
        config=PacerConfig(base_delay=1.0, min_delay=1.0, max_delay=4.0),
        sleep=_no_sleep,
    )
    for _ in range(20):
        p.record(403)
    assert p.delay <= 4.0


def test_wait_calls_sleep():
    calls = []
    p = AdaptivePacer(
        config=PacerConfig(base_delay=0.25, min_delay=0.25),
        sleep=lambda s: calls.append(s),
    )
    p.wait()
    assert calls == [0.25]


def test_stats_reports_events():
    p = AdaptivePacer(
        config=PacerConfig(base_delay=0.1, min_delay=0.1), sleep=_no_sleep
    )
    p.record(200)
    p.record(403)
    stats = p.stats()
    assert stats["events"] == 2
    assert "current_delay" in stats




def test_application_error_does_not_backoff():
    """500 is an application error, not a block signal.

    Slowing down does not help an app that has no route for the input; it
    just wastes time. Backoff must be reserved for actual block responses.
    """
    p = AdaptivePacer(
        config=PacerConfig(base_delay=0.5, min_delay=0.5), sleep=_no_sleep
    )
    before = p.delay
    p.record(500)
    assert p.delay == before


def test_repeated_500s_do_not_escalate_delay():
    """The observed '~2.0s localhost floor' was this bug.

    500 -> 0.5s -> 1.0s -> 2.0s -> 4.0s ... on any target that 500s for
    unknown input. The floor was the third term of a doubling sequence.
    """
    p = AdaptivePacer(
        config=PacerConfig(base_delay=0.5, min_delay=0.5), sleep=_no_sleep
    )
    for _ in range(10):
        p.record(500)
    assert p.delay == 0.5


def test_500_resets_clean_streak():
    """A 500 is not a successful response; it must not count toward recovery."""
    p = AdaptivePacer(
        config=PacerConfig(
            base_delay=0.1,
            min_delay=0.0,
            recovery_factor=0.5,
            clean_streak_before_recovery=3,
        ),
        sleep=_no_sleep,
    )
    p.record(403)          # force a backoff
    high = p.delay
    p.record(200)
    p.record(200)
    p.record(500)          # resets the streak -- the next two 200s do NOT recover
    p.record(200)
    p.record(200)
    assert p.delay == high


def test_gateway_errors_do_not_backoff():
    """502/504 are upstream failures, not block signals.

    A 504 already cost the full request timeout; adding backoff on top
    compounds a penalty for a request that already failed slowly. If a
    CDN is genuinely throttling, it will show up as 403/429/503 next and
    BLOCK_STATUSES handles it then.
    """
    p = AdaptivePacer(
        config=PacerConfig(base_delay=0.5, min_delay=0.5), sleep=_no_sleep
    )
    for status in (500, 502, 504):
        before = p.delay
        p.record(status)
        assert p.delay == before, f"expected no backoff on {status}"
