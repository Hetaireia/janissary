"""Unit tests for pathtraver_normalization_probe (ADR-036 Phase 3)."""

from janissary.detection.pathtraver_normalization_probe import (
    _compute_normalized_hash,
    _normalize_body_for_comparison,
    build_self_referential_probe,
    check_normalization_probe,
)


def test_normalization_strips_dynamic_tokens() -> None:
    body_with_token = 'var csrf_token="1234567890abcdef1234567890abcdef";'
    normalized = _normalize_body_for_comparison(body_with_token)
    assert "1234567890abcdef" not in normalized
    assert "<DYNAMIC_TOKEN>" in normalized


def test_normalization_probe_fires_on_valid_alias_traversal() -> None:
    assert (
        check_normalization_probe(
            probe_payload="/app/static../static/main.js",
            existing_asset_response={
                "status_code": 200,
                "body": 'var nonce="aaaa1111bbbb2222"; console.log(1);',
            },
            self_referential_response={
                "status_code": 200,
                "body": 'var nonce="cccc3333dddd4444"; console.log(1);',
            },
            nonexistent_canary_response={"status_code": 404, "body": "Not Found"},
            baseline_response={"status_code": 404, "body": "Not Found"},
        )
        is True
    )


def test_normalization_probe_rejects_reflected_payload() -> None:
    assert (
        check_normalization_probe(
            probe_payload="/app/static../static/main.js",
            existing_asset_response={"status_code": 200, "body": "asset-body"},
            self_referential_response={
                "status_code": 200,
                "body": "asset-body /app/static../static/main.js",
            },
            nonexistent_canary_response={"status_code": 404, "body": "Not Found"},
            baseline_response={"status_code": 404, "body": "Not Found"},
        )
        is False
    )


def test_normalization_probe_rejects_spa_catchall_canary() -> None:
    spa = {"status_code": 200, "body": "<html>SPA Shell</html>"}
    assert (
        check_normalization_probe(
            probe_payload="/app/static../static/main.js",
            existing_asset_response=spa,
            self_referential_response=spa,
            nonexistent_canary_response=spa,
            baseline_response=spa,
        )
        is False
    )


def test_hash_computation_deterministic() -> None:
    assert _compute_normalized_hash("test body") == _compute_normalized_hash(
        "test body"
    )
    assert _compute_normalized_hash("test body") != _compute_normalized_hash(
        "other body"
    )


def test_build_self_referential_probe_duplicates_last_segment() -> None:
    assert (
        build_self_referential_probe("../../../etc/passwd")
        == "../../../etc/passwd/../passwd"
    )


def test_build_self_referential_probe_absolute_path() -> None:
    assert build_self_referential_probe("/etc/passwd") == "/etc/passwd/../passwd"


def test_build_self_referential_probe_backslash() -> None:
    assert build_self_referential_probe(r"..\..\win.ini") == r"..\..\win.ini\..\win.ini"


def test_build_self_referential_probe_rejects_unusable_shapes() -> None:
    assert build_self_referential_probe("") is None
    assert build_self_referential_probe("passwd") is None
    assert build_self_referential_probe("etc/") is None
