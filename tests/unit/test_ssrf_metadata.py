"""Tests for SSRF cloud-metadata payloads and response-body markers (M39)."""

from __future__ import annotations

from janissary.engine.scanner import DEFAULT_PAYLOADS, SSRF_BODY_MARKERS


def test_metadata_payloads_present():
    """All four metadata payloads are registered as ssrf category."""
    names = {name for name, _, _, _ in DEFAULT_PAYLOADS}
    assert "ssrf_metadata_aws" in names
    assert "ssrf_metadata_aws_v6" in names
    assert "ssrf_metadata_gcp" in names
    assert "ssrf_metadata_azure" in names


def test_metadata_payloads_are_ssrf_category():
    """All metadata payloads classify as 'ssrf' with 'critical' severity."""
    ssrf = {name: sev for name, _, cat, sev in DEFAULT_PAYLOADS if cat == "ssrf"}
    assert ssrf["ssrf_metadata_aws"] == "critical"
    assert ssrf["ssrf_metadata_aws_v6"] == "critical"
    assert ssrf["ssrf_metadata_gcp"] == "critical"
    assert ssrf["ssrf_metadata_azure"] == "critical"


def test_metadata_payloads_have_markers():
    """Every metadata payload has at least one body marker defined."""
    for name in (
        "ssrf_metadata_aws",
        "ssrf_metadata_aws_v6",
        "ssrf_metadata_gcp",
        "ssrf_metadata_azure",
    ):
        assert name in SSRF_BODY_MARKERS, f"{name} missing from SSRF_BODY_MARKERS"
        assert len(SSRF_BODY_MARKERS[name]) >= 1, f"{name} has no markers"


def test_metadata_aws_payload_urls():
    """AWS metadata payloads target 169.254.169.254 (v4) and fd00:ec2::254 (v6)."""
    payloads = {name: value for name, value, _, _ in DEFAULT_PAYLOADS}
    assert "169.254.169.254" in payloads["ssrf_metadata_aws"]
    assert "fd00:ec2::254" in payloads["ssrf_metadata_aws_v6"]


def test_metadata_gcp_payload_url():
    """GCP metadata payload targets metadata.google.internal."""
    payloads = {name: value for name, value, _, _ in DEFAULT_PAYLOADS}
    assert "metadata.google.internal" in payloads["ssrf_metadata_gcp"]


def test_metadata_azure_payload_url():
    """Azure metadata payload targets 169.254.169.254/metadata/instance."""
    payloads = {name: value for name, value, _, _ in DEFAULT_PAYLOADS}
    assert "169.254.169.254/metadata/instance" in payloads["ssrf_metadata_azure"]


def test_aws_markers_are_distinctive():
    """AWS markers should not appear in GCP/Azure marker lists."""
    aws = set(SSRF_BODY_MARKERS["ssrf_metadata_aws"])
    gcp = set(SSRF_BODY_MARKERS["ssrf_metadata_gcp"])
    azure = set(SSRF_BODY_MARKERS["ssrf_metadata_azure"])
    assert aws.isdisjoint(gcp), f"AWS/GCP markers overlap: {aws & gcp}"
    assert aws.isdisjoint(azure), f"AWS/Azure markers overlap: {aws & azure}"


def test_marker_match_fires_on_aws_content():
    """Simulate AWS metadata response; verify at least one marker matches."""
    response_body = "ami-id\nami-launch-index\ninstance-id\nplacement/"
    markers = SSRF_BODY_MARKERS["ssrf_metadata_aws"]
    assert any(m in response_body for m in markers)


def test_marker_match_fires_on_gcp_content():
    """Simulate GCP metadata response."""
    response_body = "instance/\nproject/\nservice-accounts/"
    markers = SSRF_BODY_MARKERS["ssrf_metadata_gcp"]
    assert any(m in response_body for m in markers)


def test_marker_match_fires_on_azure_content():
    """Simulate Azure metadata response (JSON)."""
    response_body = '{"compute":{"vmId":"abc-123","subscriptionId":"s-456"}}'
    markers = SSRF_BODY_MARKERS["ssrf_metadata_azure"]
    assert any(m in response_body for m in markers)


def test_marker_no_false_positive_on_safe_content():
    """Ordinary page content should not match any metadata markers."""
    response_body = "<html><body>Welcome to example.com</body></html>"
    for name, markers in SSRF_BODY_MARKERS.items():
        assert not any(m in response_body for m in markers), (
            f"{name} FPs on safe content"
        )
