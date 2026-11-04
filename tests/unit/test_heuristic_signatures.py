"""Unit tests for src/janissary/heuristic/signatures.py (M37)."""

from __future__ import annotations

import dataclasses
from dataclasses import FrozenInstanceError

import pytest

from janissary.heuristic.signatures import (
    HEURISTIC_SIGNATURES,
    VALID_TARGET_LAYERS,
    HeuristicSignature,
)


def _valid_kwargs(**overrides):
    base = dict(
        id="HEUR-TEST",
        category="test:test",
        target_layer="body",
        patterns=(r"foo",),
        base_confidence=0.450,
    )
    base.update(overrides)
    return base


# --- construction -----------------------------------------------------


def test_valid_construction_succeeds():
    sig = HeuristicSignature(**_valid_kwargs())
    assert sig.id == "HEUR-TEST"
    assert sig.category == "test:test"
    assert sig.target_layer == "body"
    assert sig.patterns == (r"foo",)
    assert sig.base_confidence == 0.450


# --- regex validation -------------------------------------------------


@pytest.mark.parametrize(
    "bad_pattern",
    [
        r"(",
        r"[",
        r"(?P<x>a)(?P<x>b)",
    ],
)
def test_invalid_regex_rejected(bad_pattern):
    with pytest.raises(ValueError, match="invalid regex"):
        HeuristicSignature(**_valid_kwargs(patterns=(bad_pattern,)))


# --- base_confidence boundaries ---------------------------------------


def test_base_confidence_negative_rejected():
    with pytest.raises(ValueError, match="base_confidence"):
        HeuristicSignature(**_valid_kwargs(base_confidence=-0.1))


def test_base_confidence_zero_accepted():
    sig = HeuristicSignature(**_valid_kwargs(base_confidence=0.0))
    assert sig.base_confidence == 0.0


def test_base_confidence_one_rejected():
    with pytest.raises(ValueError, match="base_confidence"):
        HeuristicSignature(**_valid_kwargs(base_confidence=1.0))


def test_base_confidence_just_under_one_accepted():
    sig = HeuristicSignature(**_valid_kwargs(base_confidence=0.999))
    assert sig.base_confidence == 0.999


# --- frozen semantics -------------------------------------------------


def test_signature_is_frozen():
    sig = HeuristicSignature(**_valid_kwargs())
    with pytest.raises(FrozenInstanceError):
        sig.id = "HEUR-OTHER"


# --- registry invariants ----------------------------------------------


def test_no_duplicate_ids_in_registry():
    ids = [s.id for s in HEURISTIC_SIGNATURES]
    assert len(ids) == len(set(ids)), f"duplicate ids: {ids}"


def test_all_target_layers_valid():
    for sig in HEURISTIC_SIGNATURES:
        assert sig.target_layer in VALID_TARGET_LAYERS, (
            f"{sig.id} has invalid target_layer={sig.target_layer!r}"
        )


def test_registry_has_expected_seeds():
    ids = {s.id for s in HEURISTIC_SIGNATURES}
    assert {"HEUR-001", "HEUR-002", "HEUR-003"} <= ids


# --- asdict round-trip ------------------------------------------------


def test_asdict_round_trip():
    sig = HEURISTIC_SIGNATURES[0]
    d = dataclasses.asdict(sig)
    assert d == {
        "id": sig.id,
        "category": sig.category,
        "target_layer": sig.target_layer,
        "patterns": list(sig.patterns),
        "base_confidence": sig.base_confidence,
    }
    rebuilt = HeuristicSignature(
        id=d["id"],
        category=d["category"],
        target_layer=d["target_layer"],
        patterns=tuple(d["patterns"]),
        base_confidence=d["base_confidence"],
    )
    assert rebuilt == sig


# --- other validation -------------------------------------------------


def test_invalid_target_layer_rejected():
    with pytest.raises(ValueError, match="target_layer"):
        HeuristicSignature(**_valid_kwargs(target_layer="cookies"))


def test_empty_patterns_rejected():
    with pytest.raises(ValueError, match="patterns"):
        HeuristicSignature(**_valid_kwargs(patterns=()))
