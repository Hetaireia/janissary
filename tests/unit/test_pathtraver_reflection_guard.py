"""Unit tests for pathtraver_reflection_guard (ADR-036 Phase 2)."""

from janissary.detection.pathtraver_reflection_guard import is_payload_reflected


def test_direct_payload_reflection_detected() -> None:
    assert (
        is_payload_reflected(
            "../../../etc/passwd", "Error: Could not retrieve ../../../etc/passwd"
        )
        is True
    )


def test_url_encoded_payload_reflected_as_decoded_detected() -> None:
    assert (
        is_payload_reflected(
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            '{"error": "File not found: ../../etc/passwd"}',
        )
        is True
    )


def test_double_url_encoded_payload_detected() -> None:
    assert (
        is_payload_reflected(
            "%252e%252e%252fconfig%252fsettings.yml",
            "Invalid path: ../../config/settings.yml",
        )
        is True
    )


def test_html_entity_escaped_reflection_detected() -> None:
    assert (
        is_payload_reflected(
            "../../secret/token", "<p>Failed: ..&#x2f;..&#x2f;secret&#x2f;token</p>"
        )
        is True
    )


def test_legitimate_passwd_content_not_flagged() -> None:
    body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    assert is_payload_reflected("../../../../etc/passwd", body) is False


def test_empty_inputs_return_false() -> None:
    assert is_payload_reflected("", "some body") is False
    assert is_payload_reflected("../../../etc/passwd", "") is False
