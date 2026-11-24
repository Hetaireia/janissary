"""Unit tests for pathtraver_convergence_oracle (ADR-036 Phase 4)."""

from janissary.detection.pathtraver_convergence_oracle import check_convergence_oracle


def test_convergence_oracle_fires_on_root_clamp() -> None:
    assert (
        check_convergence_oracle(
            payload_n="../../../index",
            payload_n_plus_1="../../../../index",
            depth_n_minus_1_response={"status_code": 404, "body": "Not Found"},
            depth_n_response={"status_code": 200, "body": "root-index-content"},
            depth_n_plus_1_response={"status_code": 200, "body": "root-index-content"},
            nonexistent_canary_response={
                "status_code": 404,
                "body": "Canary Not Found",
            },
        )
        is True
    )


def test_convergence_oracle_rejects_uniform_generic_200() -> None:
    generic = {"status_code": 200, "body": "Default Landing Page"}
    assert (
        check_convergence_oracle(
            payload_n="../../../index",
            payload_n_plus_1="../../../../index",
            depth_n_minus_1_response=generic,
            depth_n_response=generic,
            depth_n_plus_1_response=generic,
            nonexistent_canary_response=generic,
        )
        is False
    )


def test_convergence_oracle_rejects_reflected_error_page() -> None:
    assert (
        check_convergence_oracle(
            payload_n="../../../index",
            payload_n_plus_1="../../../../index",
            depth_n_minus_1_response={"status_code": 404, "body": "Not Found"},
            depth_n_response={
                "status_code": 200,
                "body": "Error opening ../../../index",
            },
            depth_n_plus_1_response={
                "status_code": 200,
                "body": "Error opening ../../../../index",
            },
            nonexistent_canary_response={"status_code": 404, "body": "Not Found"},
        )
        is False
    )
