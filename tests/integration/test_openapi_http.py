"""Real-HTTP integration coverage for the OpenAPI scan pipeline."""

import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import janissary.engine.scanner as scanner_module
from janissary.cli import _run_openapi_scan


def test_openapi_scan_sends_real_http_requests_to_local_target(
    tmp_path, monkeypatch, capsys
):
    requests_received = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urlsplit(self.path)
            requests_received.append(
                {
                    "method": self.command,
                    "path": parsed.path,
                    "query": parse_qs(parsed.query),
                }
            )
            body = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        spec = {
            "openapi": "3.0.3",
            "info": {"title": "Local HTTP integration", "version": "1.0.0"},
            "servers": [{"url": base_url}],
            "paths": {
                "/search": {
                    "get": {
                        "operationId": "search",
                        "parameters": [
                            {
                                "name": "q",
                                "in": "query",
                                "required": False,
                                "schema": {"type": "string"},
                            }
                        ],
                        "responses": {"200": {"description": "OK"}},
                    }
                }
            },
        }
        spec_path = tmp_path / "openapi.json"
        spec_path.write_text(json.dumps(spec), encoding="utf-8")

        monkeypatch.setattr(
            scanner_module,
            "DEFAULT_PAYLOADS",
            [
                (
                    "openapi_http_probe",
                    "JANISSARY_OPENAPI_HTTP_PROBE",
                    "xss",
                    "low",
                )
            ],
        )

        args = argparse.Namespace(
            openapi=str(spec_path),
            quiet=False,
            export=None,
            proxy=None,
            timeout=2.0,
            baseline_count=3,
            delay=0.0,
            stealth=False,
            no_waf=True,
            baseline_value="",
            cookie=None,
            bearer=None,
            sessions=None,
            idor=False,
            cookie_alt=None,
            bearer_alt=None,
            collaborator=None,
            interactsh=False,
            json_template=None,
        )

        rc = _run_openapi_scan(args)
        captured = capsys.readouterr()

        assert rc == 0, (
            f"OpenAPI scan returned {rc}; stdout={captured.out!r}; "
            f"stderr={captured.err!r}"
        )
        assert requests_received, "local HTTP target received no requests"
        assert all(r["method"] == "GET" for r in requests_received)
        assert all(r["path"] == "/search" for r in requests_received)

        query_values = [
            value
            for request in requests_received
            for value in request["query"].get("q", [])
        ]
        assert "1" in query_values
        assert "JANISSARY_OPENAPI_HTTP_PROBE" in query_values
        assert len(requests_received) >= 6
        assert "target failed" not in captured.err.lower()

    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
