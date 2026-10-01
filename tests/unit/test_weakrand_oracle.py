"""Unit tests for the weakrand RNG-class oracle.

The OWASP Benchmark weakrand cases leak the RNG class they used into
the response body. Vulnerable cases reference a weak class
(java.util.Random / java.lang.Math.random); non-vulnerable cases
reference java.security.SecureRandom. The oracle fires on the weak
marker alone, and is suppressed when:

  - the secure marker is also present (ambiguous response),
  - the baseline already leaks the weak marker (unconditional leak,
    not injection-driven),
  - no weak marker is present.

Negative tests are the point.
"""

from janissary.detection import Baseline, ResponseSnapshot
from janissary.detection.analyzer import check_weakrand_oracle


class FakeResponse:
    def __init__(self, status=200, text="", content_type="text/html", elapsed=0.1):
        self.status_code = status
        self.text = text
        self.headers = {"content-type": content_type}
        self._elapsed = elapsed

    @property
    def elapsed(self):
        outer = self

        class Elapsed:
            def total_seconds(self):
                return outer._elapsed

        return Elapsed()


def snap(**kwargs):
    return ResponseSnapshot.from_response(FakeResponse(**kwargs))


def make_baseline(bodies):
    b = Baseline()
    for body in bodies:
        b.add(snap(text=body))
    return b


BENIGN = "Welcome to the benchmark page."

VULN_RANDOM = (
    "Weak Randomness Test java.util.Random.nextFloat() executed"
)
VULN_MATH = (
    "Weak Randomness Test java.lang.Math.random() executed"
)
SAFE_SECURE = (
    "Weak Randomness Test java.security.SecureRandom.nextInt(int) executed"
)
BOTH = (
    "Weak Randomness Test java.util.Random.nextFloat() executed "
    "and java.security.SecureRandom.nextInt(int) executed"
)


def test_fires_on_java_util_random():
    baseline = make_baseline([BENIGN])
    findings = check_weakrand_oracle(baseline, snap(text=VULN_RANDOM))
    assert len(findings) == 1
    assert findings[0]["type"] == "weakrand_rng_oracle"
    assert findings[0]["severity"] == "high"


def test_fires_on_math_random():
    baseline = make_baseline([BENIGN])
    findings = check_weakrand_oracle(baseline, snap(text=VULN_MATH))
    assert len(findings) == 1
    assert findings[0]["type"] == "weakrand_rng_oracle"


def test_silent_on_secure_random():
    baseline = make_baseline([BENIGN])
    assert check_weakrand_oracle(baseline, snap(text=SAFE_SECURE)) == []


def test_silent_on_benign_body():
    baseline = make_baseline([BENIGN])
    assert check_weakrand_oracle(baseline, snap(text=BENIGN)) == []


def test_silent_when_both_markers_present():
    baseline = make_baseline([BENIGN])
    assert check_weakrand_oracle(baseline, snap(text=BOTH)) == []


def test_fires_when_baseline_also_leaks_weak_marker():
    # On the pinned target the weak marker is emitted unconditionally:
    # the benign baseline body contains it too. The vulnerability is
    # which RNG class runs, not whether the marker appears, so the
    # oracle must still fire. Baseline-leak suppression was removed
    # after Session 8 measured 0 weakrand findings against a target
    # whose baseline carries the marker.
    baseline = make_baseline([VULN_RANDOM])
    findings = check_weakrand_oracle(baseline, snap(text=VULN_RANDOM))
    assert len(findings) == 1
    assert findings[0]["type"] == "weakrand_rng_oracle"


def test_fires_when_baseline_is_empty():
    # The baseline check is a false-positive suppression, not a gate:
    # it exists to swallow unconditional leaks. With no baseline
    # samples there is nothing to suppress, so a strong body signature
    # fires. (The scanner always collects a baseline first; this
    # documents the empty-input branch.)
    baseline = Baseline()
    findings = check_weakrand_oracle(baseline, snap(text=VULN_RANDOM))
    assert len(findings) == 1
    assert findings[0]["type"] == "weakrand_rng_oracle"


def test_case_insensitive_marker_match():
    baseline = make_baseline([BENIGN])
    body = "weak randomness test JAVA.UTIL.RANDOM.nextBytes() executed"
    findings = check_weakrand_oracle(baseline, snap(text=body))
    assert len(findings) == 1
