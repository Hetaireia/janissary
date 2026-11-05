"""GraphQL fixture server for FN-15 live validation.

Not for production. Serves a small hand-authored schema with three
fields, accepts POST /graphql with standard GraphQL JSON body, and
supports array-batched queries (standard GraphQL batching extension).

Run: python scripts/graphql_fixture_server.py [--port 8765]

Deliberately:
- No depth limit (graphql-core default)
- No alias limit (graphql-core default)
- Introspection enabled
- Batch array support
- user(id) errors on quote injection (fuzz target)
- secret(key) errors on non-"admin" keys
"""

from __future__ import annotations

import argparse
import contextlib
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

from graphql import build_schema, graphql_sync

SCHEMA = build_schema(
    """
    type Query {
      user(id: String!): User
      currentUser: User
      posts(limit: Int, offset: Int): [Post]
      secret(key: String): String
    }
    type User {
      id: String
      email: String
      name: String
      friend: User
    }
    type Post {
      id: String
      title: String
    }
    """
)


def _resolve_user(root, info, id):
    if "'" in id or '"' in id or "--" in id:
        raise RuntimeError('Database error: unterminated quoted string at or near "\'"')
    return {
        "id": id,
        "email": f"user{id}@example.invalid",
        "name": "Test User",
        "friend": None,
    }


def _resolve_currentuser(root, info):
    return {
        "id": "me",
        "email": "me@example.invalid",
        "name": "Current User",
        "friend": None,
    }


def _resolve_posts(root, info, limit=None, offset=None):
    n = min(limit or 10, 100)
    return [{"id": str(i), "title": f"Post {i}"} for i in range(n)]


def _resolve_secret(root, info, key=None):
    if key == "admin":
        return "flag{s3cr3t_v4lu3}"
    raise RuntimeError("Access denied")


_q = SCHEMA.get_type("Query")
_q.fields["user"].resolve = _resolve_user
_q.fields["currentUser"].resolve = _resolve_currentuser
_q.fields["posts"].resolve = _resolve_posts
_q.fields["secret"].resolve = _resolve_secret


def _execute_one(payload):
    query = payload.get("query", "")
    variables = payload.get("variables")
    result = graphql_sync(SCHEMA, query, root_value=None, variable_values=variables)
    body = {}
    if result.data is not None:
        body["data"] = result.data
    if result.errors:
        body["errors"] = [{"message": e.message} for e in result.errors]
    return body


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, obj, status=200):
        data = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/health":
            self._send_json({"ok": True})
        else:
            self._send_json({"error": "POST /graphql only"}, status=404)

    def do_POST(self):
        if self.path != "/graphql":
            self._send_json({"error": "POST /graphql only"}, status=404)
            return
        try:
            n = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(n).decode("utf-8")
            payload = json.loads(body)
        except Exception as e:
            self._send_json({"errors": [{"message": f"bad request: {e}"}]}, status=400)
            return
        if isinstance(payload, list):
            self._send_json([_execute_one(p) for p in payload])
        else:
            self._send_json(_execute_one(payload))

    def log_message(self, *args):
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()
    server = HTTPServer((args.host, args.port), Handler)
    print(f"listening on http://{args.host}:{args.port}/graphql", flush=True)
    with contextlib.suppress(KeyboardInterrupt):
        server.serve_forever()


if __name__ == "__main__":
    main()
