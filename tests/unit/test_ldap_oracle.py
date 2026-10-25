"""LDAP injection oracle regression tests."""

from janissary.detection import Baseline, ResponseSnapshot, check_ldap_injection_oracle


class _FakeResponse:
    def __init__(self, body, status=200, content_type="text/html"):
        self.text = body
        self.status_code = status
        self.headers = {"content-type": content_type}
        self.elapsed = None


def _snap(body: str) -> ResponseSnapshot:
    return ResponseSnapshot.from_response(_FakeResponse(body))


def _baseline(bodies):
    b = Baseline()
    for body in bodies:
        b.add(_snap(body))
    return b


def test_ldap_oracle_fires_on_expansion():
    baseline = _baseline(
        [
            "LDAP query results:<br>Record found with name Ms Bar<br>"
            "Address: The streetz 4 Ms bar<br>"
        ]
        * 10
    )
    wild = _snap(
        "LDAP query results:<br>Record found with name Ms Bar<br>"
        "LDAP query results:<br>Record found with name foo<br>"
        "LDAP query results:<br>Record found with name Mr Unknown<br>"
    )
    findings = check_ldap_injection_oracle(baseline, wild)
    assert len(findings) == 1
    assert findings[0]["type"] == "ldap_injection"
    assert findings[0]["severity"] == "critical"


def test_ldap_oracle_silent_on_same_count():
    baseline = _baseline(
        ["LDAP query results:<br>Record found with name Ms Bar<br>"] * 10
    )
    wild = _snap("LDAP query results:<br>Record found with name Ms Bar<br>")
    findings = check_ldap_injection_oracle(baseline, wild)
    assert findings == []


def test_ldap_oracle_silent_on_empty_baseline():
    baseline = _baseline([])
    wild = _snap("LDAP query results:<br>Record found with name foo<br>")
    findings = check_ldap_injection_oracle(baseline, wild)
    assert findings == []
