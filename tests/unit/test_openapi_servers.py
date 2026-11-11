"""Stage 4: server URL resolution (ADR-030).

Red before the data-model change and resolver land: Operation has no
base_url field, and nothing reads servers/host/basePath/schemes.
"""

import json

from janissary.importers.openapi import parse_spec


def _write(tmp_path, spec):
    p = tmp_path / "spec.json"
    p.write_text(json.dumps(spec), encoding="utf8")
    return p


def test_v3_plain_server(tmp_path):
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "t", "version": "1.0"},
        "servers": [{"url": "https://api.example.com/v1"}],
        "paths": {
            "/ping": {
                "get": {
                    "operationId": "ping",
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }
    result = parse_spec(_write(tmp_path, spec))
    assert len(result.imported) == 1
    assert result.imported[0].base_url == "https://api.example.com/v1"


def test_v3_templated_server(tmp_path):
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "t", "version": "1.0"},
        "servers": [
            {
                "url": "https://{host}/v1",
                "variables": {"host": {"default": "api.example.com"}},
            }
        ],
        "paths": {
            "/ping": {
                "get": {
                    "operationId": "ping",
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }
    result = parse_spec(_write(tmp_path, spec))
    assert result.imported[0].base_url == "https://api.example.com/v1"


def test_v3_templated_server_no_default(tmp_path):
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "t", "version": "1.0"},
        "servers": [{"url": "https://{host}/v1", "variables": {}}],
        "paths": {
            "/ping": {
                "get": {
                    "operationId": "ping",
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }
    result = parse_spec(_write(tmp_path, spec))
    assert len(result.imported) == 1
    assert result.imported[0].base_url == ""
    assert len(result.notes) >= 1
    assert any("host" in n for n in result.notes)


def test_v2_host_basepath_schemes(tmp_path):
    spec = {
        "swagger": "2.0",
        "info": {"title": "t", "version": "1.0"},
        "host": "api.example.com",
        "basePath": "/v1",
        "schemes": ["https"],
        "paths": {
            "/ping": {
                "get": {
                    "operationId": "ping",
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }
    result = parse_spec(_write(tmp_path, spec))
    assert result.imported[0].base_url == "https://api.example.com/v1"
