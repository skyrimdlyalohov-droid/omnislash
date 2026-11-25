#!/usr/bin/env python3
"""Loopback-only structural skeleton service for Go's deception filter.

Why a service: computing JSON/HTML value-free skeletons in Python avoids
reimplementing the normalizer in Go, while calling a script with os/exec on
every HTTP response would cost 50-100 ms. This stdlib server answers in ~1 ms
and adds no third-party dependency (no FastAPI, no gRPC, no CDN).

It never opens an outbound socket and never performs an attack: it only
normalizes bodies that the Go caller already received from its own request.
"""

from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict

REPO_ROOT = __import__("os").path.dirname(__import__("os").path.dirname(__import__("os").path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

try:
    from research.semantic_analyzer import structural_skeleton
except ImportError:  # pragma: no cover - direct script execution
    from semantic_analyzer import structural_skeleton  # type: ignore

MAX_BODY = 1 << 20


def canonical(body: str, content_type: str = "") -> str:
    skeleton: Dict[str, Any] = structural_skeleton(body, content_type)
    return json.dumps(skeleton, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:  # quiet by default
        return

    def _send(self, status: int, payload: Dict[str, Any]) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        if self.path.split("?")[0] == "/healthz":
            self._send(200, {"status": "ok", "service": "semantic-skeleton"})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802 - http.server API
        if self.path.split("?")[0] != "/skeleton":
            self._send(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            self._send(400, {"error": "invalid content-length"})
            return
        if length <= 0 or length > MAX_BODY:
            self._send(413, {"error": "body too large"})
            return
        try:
            obj = json.loads(self.rfile.read(length).decode("utf-8", "replace"))
        except (ValueError, UnicodeError):
            self._send(400, {"error": "invalid json"})
            return
        if not isinstance(obj, dict):
            self._send(400, {"error": "expected json object"})
            return
        body = obj.get("body")
        if body is None:
            self._send(400, {"error": "body is required"})
            return
        try:
            self._send(200, {
                "status": "ok",
                "skeleton": canonical(str(body), str(obj.get("content_type") or "")),
            })
        except Exception as exc:  # pragma: no cover - stay total for the caller
            self._send(500, {"error": "skeleton failed", "detail": str(exc)[:200]})


def main() -> None:  # pragma: no cover - CLI glue
    ap = argparse.ArgumentParser(description="Loopback structural skeleton service")
    ap.add_argument("--addr", default="127.0.0.1:8000")
    ap.add_argument("--port", type=int, default=0, help="overrides the port in --addr")
    args = ap.parse_args()
    host, _, port = args.addr.rpartition(":")
    if not host:
        host, port = "127.0.0.1", "8000"
    if args.port:
        port = str(args.port)
    server = ThreadingHTTPServer((host, int(port)), Handler)
    server.daemon_threads = True
    server.serve_forever()


if __name__ == "__main__":  # pragma: no cover
    main()
