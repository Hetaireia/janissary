"""Unit tests for the platform knowledge base."""

from __future__ import annotations

from janissary.agent import platform_kb as kb


def test_known_platforms_non_empty():
    assert len(kb.known_platforms()) > 5


def test_known_platforms_sorted():
    names = kb.known_platforms()
    assert names == sorted(names)


def test_surfaces_for_known():
    surfaces = kb.surfaces_for("wordpress")
    assert len(surfaces) > 0
    assert all(isinstance(s, kb.Surface) for s in surfaces)


def test_surfaces_for_unknown_returns_empty():
    assert kb.surfaces_for("nonesuch") == []
    assert kb.surfaces_for("") == []


def test_surfaces_case_insensitive():
    assert len(kb.surfaces_for("WordPress")) == len(kb.surfaces_for("wordpress"))


def test_modules_for_dedups():
    mods = kb.modules_for("wordpress")
    assert len(mods) == len(set(mods))
    assert "scan" in mods
    assert "xmlrpc" in mods


def test_modules_for_unknown_returns_empty():
    assert kb.modules_for("nonesuch") == []


def test_plan_for_stable_order():
    plan = kb.plan_for(["wordpress", "graphql"])
    assert plan == ["scan", "xmlrpc", "admin", "graphql"]


def test_plan_for_ignores_unknown():
    plan = kb.plan_for(["nonesuch", "wordpress"])
    assert "scan" in plan
    assert all("nonesuch" not in m for m in plan)


def test_plan_for_empty():
    assert kb.plan_for([]) == []


def test_surface_to_dict_roundtrip():
    s = kb.Surface(name="x", module="scan", params=["a"], paths=["/x"], notes="n")
    d = s.to_dict()
    assert d["name"] == "x"
    assert d["module"] == "scan"
    assert d["params"] == ["a"]
    assert d["paths"] == ["/x"]


def test_every_surface_has_module():
    for platform, surfaces in kb.PLATFORMS.items():
        for s in surfaces:
            assert s.module, f"{platform}:{s.name} has no module"
