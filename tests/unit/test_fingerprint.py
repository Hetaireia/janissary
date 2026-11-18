"""M109 / B-8: passive stack fingerprinting tests."""

from __future__ import annotations

import json
from pathlib import Path

from janissary.detection.analyzer import Baseline
from janissary.fingerprint import identify

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "fingerprint"


def _identify(name: str):
    headers = json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))[
        "headers"
    ]
    return identify([Baseline(headers=[headers])])


def test_apache_php():
    p = _identify("apache-php")
    assert p.server.value == "apache"
    assert p.framework.value == "php"
    assert p.language.value == "php"


def test_nginx_go():
    p = _identify("nginx-go")
    assert p.server.value == "nginx"
    assert p.framework.value is None
    assert p.language.value is None


def test_cloudflare_fronted():
    p = _identify("cloudflare-fronted")
    assert p.server.value == "cloudflare"
    assert p.waf.value == "cloudflare"


def test_aws_alb():
    p = _identify("aws-alb")
    assert p.server.value == "aws-alb"


def test_iis_aspnet():
    p = _identify("iis-aspnet")
    assert p.server.value == "iis"
    assert p.framework.value == "asp.net"
    assert p.language.value == "csharp"


def test_ambiguous_dual():
    p = _identify("ambiguous-dual")
    assert p.waf.value == "Ambiguous"
    assert p.waf.confidence == 0.50


def test_express_node():
    p = _identify("express-node")
    assert p.server.value is None
    assert p.framework.value == "express"
    assert p.language.value == "javascript"


def test_django_gunicorn():
    p = _identify("django-gunicorn")
    assert p.server.value == "gunicorn"
    assert p.framework.value == "django"
    assert p.language.value == "python"


def test_rails_puma():
    p = _identify("rails-puma")
    assert p.framework.value == "rails"


def test_fastly_cdn():
    p = _identify("fastly-cdn")
    assert p.cdn.value == "fastly"


def test_akamai_cdn():
    p = _identify("akamai-cdn")
    assert p.server.value == "akamai"
    assert p.waf.value == "akamai"


def test_unknown_minimal():
    p = _identify("unknown-minimal")
    assert p.server.value is None
    assert p.framework.value is None
    assert p.language.value is None
    assert p.waf.value is None
    assert p.cdn.value is None


def test_confidence_requires_evidence():
    for fixture in FIXTURES.glob("*.json"):
        headers = json.loads(fixture.read_text(encoding="utf-8"))["headers"]
        p = identify([Baseline(headers=[headers])])
        for f in (p.server, p.framework, p.language, p.waf, p.cdn):
            if f.confidence > 0.0:
                assert f.evidence, (
                    f"{fixture.stem}: confidence {f.confidence} without evidence"
                )


def test_determinism():
    headers = json.loads((FIXTURES / "apache-php.json").read_text(encoding="utf-8"))[
        "headers"
    ]
    a = identify([Baseline(headers=[headers])]).to_dict()
    b = identify([Baseline(headers=[headers])]).to_dict()
    assert a == b


def test_empty_baselines():
    p = identify([])
    assert p.server.value is None


def test_baseline_without_headers():
    p = identify([Baseline()])
    assert p.server.value is None
