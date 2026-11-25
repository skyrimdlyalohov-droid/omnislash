#!/usr/bin/env python3
"""Deterministic localhost proxy/backend corpus for native calibration.

This helper starts two Python ``http.server`` instances bound to 127.0.0.1 on
ephemeral ports (port 0): a backend that varies CL/TE rules, header whitespace,
redirects and 400/502 errors, and a proxy that forwards requests to a local
backend. It also launches a self-contained Go ``net/http`` backend
(``lab/native_pair_go_backend/main.go``) serving redirect, strict-CL, 400/502,
CL+TE and literal header-whitespace variants. A raw-socket client drives a
fixed matrix of poison/victim requests through the proxy, classifies each
response with the production semantic analyzer, and emits
TrainingExample-compatible JSONL.

No Docker, no npm/Node, no external network, no downloads. Everything uses
localhost only; all Python servers and the Go process are shut down cleanly
before the helper exits.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import parse_qs, urlparse

try:
    from research.semantic_analyzer import (
        ResponseShape,
        TransitionTracker,
        classify_response_shape,
    )
    from research.self_learning import TrainingExample, extract_cl, feature_key
    from research.waf_negative_templates import (
        BASELINE_RESPONSE,
        waf_negative_jsonl_records,
    )
except ImportError:  # pragma: no cover - direct script execution
    from semantic_analyzer import (  # type: ignore
        ResponseShape,
        TransitionTracker,
        classify_response_shape,
    )
    from self_learning import TrainingExample, extract_cl, feature_key  # type: ignore
    from waf_negative_templates import (  # type: ignore
        BASELINE_RESPONSE,
        waf_negative_jsonl_records,
    )


CONTROL_HOST = "127.0.0.1"
CLEAN_BODY = "<html><body><h1>Lab</h1><p>ok</p></body></html>"
ERROR_BODY = '{"error":"Invalid request"}'

# name -> backend response specification. The matrix includes strict CL/TE
# rejection, queue-shift redirects, benign baselines, route misses, 400/502
# errors and WAF stub bodies.
BACKEND_SCENARIOS: Dict[str, Dict[str, Any]] = {
    "queue-shift": {
        "status": 302,
        "headers": [("Location", "https://exploit.invalid/resources/"), ("Content-Type", "text/plain")],
        "body": "",
    },
    "strict-cl": {
        "status": 400,
        "headers": [("Content-Type", "application/json")],
        "body": ERROR_BODY,
    },
    "backend-400": {
        "status": 400,
        "headers": [("Content-Type", "application/json")],
        "body": '{"error":"Bad request"}',
    },
    "backend-502": {
        "status": 502,
        "headers": [("Content-Type", "text/plain")],
        "body": "Bad Gateway",
    },
    "clean": {
        "status": 200,
        "headers": [("Server", "lab-backend"), ("Content-Type", "text/html")],
        "body": CLEAN_BODY,
    },
    "route-miss": {
        "status": 404,
        "headers": [("Server", "lab-backend"), ("Content-Type", "text/html")],
        "body": "<html><body><h1>404 Not Found</h1></body></html>",
    },
    "waf-cloudflare": {
        "status": 403,
        "headers": [("Server", "cloudflare"), ("Cf-Ray", "8f3a2b1c9d0e4f5a-SIN")],
        "body": "<html><body><h1>Attention Required!</h1><p>Blocked by Cloudflare.</p></body></html>",
    },
    "waf-akamai": {
        "status": 403,
        "headers": [("Server", "AkamaiGHost"), ("x-akamai-transaction", "4000000:0:stub")],
        "body": "<html><body><h1>Access Denied</h1><p>Akamai denied the request.</p></body></html>",
    },
    "waf-qrator": {
        "status": 403,
        "headers": [("Server", "qrator"), ("X-Qrator-Rule", "102")],
        "body": "<html><body><h1>Access denied</h1><p>Qrator filter blocked this request.</p></body></html>",
    },
}

VARIANTS: Tuple[str, ...] = (
    "plain",
    "cl-te",
    "dup-cl",
    "ws-before-colon",
    "ws-leading",
    "cl0",
)

ROLES: Tuple[str, ...] = ("poison", "victim")

# Self-contained Go net/http backend scenarios (served by
# lab/native_pair_go_backend/main.go on another 127.0.0.1 ephemeral port).
GO_SCENARIOS: Tuple[str, ...] = (
    "go-redirect",
    "go-strict-cl",
    "go-400",
    "go-502",
    "go-clean",
    "go-ws-before-colon",
    "go-ws-leading",
    "go-clte",
    "go-dup-cl",
)
GO_VARIANTS: Tuple[str, ...] = ("go-native",)
ALL_SCENARIOS: Tuple[str, ...] = tuple(sorted(set(BACKEND_SCENARIOS) | set(GO_SCENARIOS)))

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GO_BACKEND_DIR = os.path.join(REPO_ROOT, "lab", "native_pair_go_backend")
GO_BACKEND_FILE = os.path.join(GO_BACKEND_DIR, "main.go")


class _QuietHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, _format: str, *_args: Any) -> None:  # silence stderr
        return

    def send_response(self, code: int, message: Any = None) -> None:
        # BaseHTTPRequestHandler.send_response injects a Date header and a
        # version-specific Server header. Omit both so the emitted corpus is
        # byte-for-byte deterministic across runs and Python versions.
        self.log_request(code)
        self.send_response_only(code, message)


class BackendHandler(_QuietHandler):
    """Backend server: scenario selected by ``/scenario/<name>``."""

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._respond()

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._respond()

    def _respond(self) -> None:
        path = urlparse(self.path).path.strip("/").split("/")[-1]
        spec = BACKEND_SCENARIOS.get(path, BACKEND_SCENARIOS["clean"])
        body = str(spec["body"]).encode("utf-8")
        self.send_response(int(spec["status"]))
        for key, value in spec["headers"]:
            self.send_header(str(key), str(value))
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


class ProxyHandler(_QuietHandler):
    """Proxy server: forwards to backend, then applies a framing variant."""

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._handle()

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._handle()

    def _handle(self) -> None:
        parsed = urlparse(self.path)
        parts = [part for part in parsed.path.strip("/").split("/") if part]
        scenario = parts[1] if len(parts) >= 2 and parts[0] == "p" else "clean"
        if scenario not in ALL_SCENARIOS:
            scenario = "clean"
        params = parse_qs(parsed.query)
        role = (params.get("role") or ["victim"])[0]
        variant = (params.get("variant") or ["plain"])[0]
        allowed_variants = GO_VARIANTS if scenario.startswith("go-") else VARIANTS
        if variant not in allowed_variants:
            variant = allowed_variants[0]

        is_go = scenario.startswith("go-")
        port_name = "go_backend_port" if is_go else "backend_port"
        backend_port = int(getattr(self.server, port_name))
        forwarded = _exchange_with_backend(backend_port, scenario, role, variant)
        status, headers, body = _parse_http_response(forwarded)
        # Go net/http adds a wall-clock Date header; drop it so emitted JSONL
        # is byte-for-byte deterministic. The Go backend itself emits all
        # CL/TE/whitespace variants, so the Python proxy must not rewrite them.
        headers = [(key, value) for key, value in headers if key.strip().lower() != "date"]
        if not is_go:
            status, headers, body = _apply_variant(status, headers, body, variant)
        headers.extend([
            ("X-Pair-Scenario", scenario),
            ("X-Pair-Variant", variant),
            ("X-Pair-Role", role),
        ])
        self.wfile.write(_render_response(status, headers, body))


def _new_server(
    handler: Any, backend_port: int = 0, go_backend_port: int = 0
) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((CONTROL_HOST, 0), handler)
    server.daemon_threads = True
    server.backend_port = backend_port  # type: ignore[attr-defined]
    server.go_backend_port = go_backend_port  # type: ignore[attr-defined]
    return server


def _wait_ready(server: ThreadingHTTPServer) -> None:
    port = int(server.server_address[1])
    for _ in range(100):
        try:
            with socket.create_connection((CONTROL_HOST, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.01)
    raise RuntimeError("local native-pair server did not start on 127.0.0.1:%d" % port)


def _exchange_with_backend(port: int, scenario: str, role: str, variant: str) -> bytes:
    request_lines = [
        "GET /scenario/%s HTTP/1.0" % scenario,
        "Host: %s:%d" % (CONTROL_HOST, port),
        "User-Agent: native-pair-corpus/1.0",
        "Accept: */*",
        "X-Pair-Scenario: %s" % scenario,
        "X-Pair-Role: %s" % role,
        "X-Pair-Variant: %s" % variant,
        "Connection: close",
        "",
        "",
    ]
    request = ("\r\n".join(request_lines)).encode("latin1")
    with socket.create_connection((CONTROL_HOST, port), timeout=2.0) as sock:
        sock.sendall(request)
        chunks: List[bytes] = []
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks)


def _parse_http_response(raw: bytes) -> Tuple[int, List[Tuple[str, str]], bytes]:
    head, separator, body = raw.partition(b"\r\n\r\n")
    if not separator:
        head, body = raw, b""
    lines = head.split(b"\r\n")
    try:
        status = int(lines[0].split()[1])
    except (IndexError, ValueError):
        status = 200
    headers: List[Tuple[str, str]] = []
    for line in lines[1:]:
        if not line.strip():
            continue
        key, _sep, value = line.partition(b":")
        headers.append((key.decode("latin1").strip(), value.decode("latin1").strip()))
    return status, headers, body


def _apply_variant(
    status: int, headers: Sequence[Tuple[str, str]], body: bytes, variant: str
) -> Tuple[int, List[Tuple[str, str]], bytes]:
    skip = {"content-length", "transfer-encoding", "connection"}
    out = [(key, value) for key, value in headers if key.strip().lower() not in skip]

    if variant == "cl-te":
        body = ("%x\r\n" % len(body)).encode("ascii") + body + b"\r\n0\r\n\r\n"
        out.append(("Transfer-Encoding", "chunked"))
    elif variant == "dup-cl":
        status = 400
        body = ERROR_BODY.encode("utf-8")
        out.append(("Content-Type", "application/json"))
        out.append(("Content-Length", str(len(body))))
        out.append(("Content-Length", "0"))
    elif variant == "ws-before-colon":
        out.append(("Content-Length ", str(len(body))))
        out.append(("Transfer-Encoding ", "chunked"))
    elif variant == "ws-leading":
        out.append((" Content-Length", str(len(body))))
        out.append((" Transfer-Encoding", "chunked"))
    elif variant == "cl0":
        out.append(("Content-Length", "0"))
    else:
        out.append(("Content-Length", str(len(body))))
    out.append(("Connection", "close"))
    return status, out, body


def _render_response(status: int, headers: Sequence[Tuple[str, str]], body: bytes) -> bytes:
    reasons = {
        200: "OK",
        302: "Found",
        400: "Bad Request",
        403: "Forbidden",
        404: "Not Found",
        502: "Bad Gateway",
    }
    lines = ["HTTP/1.0 %d %s" % (status, reasons.get(status, "OK"))]
    lines.extend("%s: %s" % (key, value) for key, value in headers)
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin1") + body


def _probe(proxy_port: int, scenario: str, role: str, variant: str) -> Tuple[str, Dict[str, Any], Any]:
    request = "\r\n".join([
        "GET /p/%s?role=%s&variant=%s HTTP/1.0" % (scenario, role, variant),
        "Host: %s:%d" % (CONTROL_HOST, proxy_port),
        "User-Agent: native-pair-corpus/1.0",
        "X-Omni-Role: %s" % role,
        "X-Omni-Variant: %s" % variant,
        "Connection: close",
        "",
        "",
    ]).encode("latin1")
    with socket.create_connection((CONTROL_HOST, proxy_port), timeout=2.0) as sock:
        sock.sendall(request)
        chunks: List[bytes] = []
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
    raw = b"".join(chunks)
    status, header_pairs, body = _parse_http_response(raw)
    response = {
        "status": status,
        "headers": [{"key": key, "value": value} for key, value in header_pairs],
        "body": body.decode("utf-8", "replace"),
    }
    shape = classify_response_shape(
        response, role=role, target_host=CONTROL_HOST, baseline=BASELINE_RESPONSE
    )
    return raw.decode("latin1", "replace"), response, shape


def _location_path(response: Dict[str, Any]) -> str:
    for header in response.get("headers") or []:
        if str(header.get("key", "")).strip().lower() == "location":
            return urlparse(str(header.get("value") or "")).path or "/"
    return ""


def _negative_reason(
    scenario: str, role: str, variant: str, status: int, shape: Any
) -> str:
    if shape.shape is ResponseShape.WAF_OR_DECEPTION or scenario.startswith("waf-"):
        return "waf_stub"
    if shape.shape is ResponseShape.PARSER_REJECT_STRICT:
        return "parser_reject"
    if scenario in {"go-ws-before-colon", "go-ws-leading", "go-clte"}:
        return "framing_variant"
    if status >= 500:
        return "backend_error"
    if variant == "dup-cl":
        return "duplicate_cl"
    if variant == "cl0":
        return "cl_zero"
    if variant in {"ws-before-colon", "ws-leading", "cl-te"}:
        return "framing_variant"
    if shape.shape is ResponseShape.APP_ROUTE_MISS:
        return "route_miss"
    if role == "poison":
        return "poison_stream_only"
    return "no_shift"


def _record_for_response(
    *,
    scenario: str,
    variant: str,
    role: str,
    raw: str,
    response: Dict[str, Any],
    shape: Any,
    confirmed: bool,
) -> Dict[str, Any]:
    status = int(response["status"])
    label = 1.0 if confirmed else 0.0
    reason = "" if label > 0 else _negative_reason(scenario, role, variant, status, shape)
    is_go = scenario.startswith("go-")

    if is_go:
        framing = "cl+te" if scenario in {"go-clte", "go-ws-before-colon", "go-ws-leading"} else "cl"
    else:
        framing = "cl+te" if variant in {"cl-te", "ws-before-colon", "ws-leading"} else "cl"

    features: Dict[str, str] = {
        "probe": "native-pair",
        "tls": "h1",
        "shape": shape.shape.value,
        "scenario:" + scenario: "1",
        "variant:" + variant: "1",
        "role:" + role: "1",
        "status:" + str(status): "1",
        "framing:" + framing: "1",
        "backend:" + ("go-net-http" if is_go else "python-http-server"): "1",
    }
    cl = extract_cl(raw)
    if cl:
        features[feature_key("cl", cl)] = "1"
    if variant == "cl0":
        features["cl_zero:1"] = "1"
    if variant == "dup-cl":
        features["duplicate_cl:1"] = "1"
    if variant in {"ws-before-colon", "ws-leading"}:
        features["header_whitespace:1"] = "1"
    if variant == "cl-te":
        features["te:chunked:1"] = "1"
    if is_go and scenario in {"go-ws-before-colon", "go-ws-leading"}:
        features["header_whitespace:1"] = "1"
    if is_go and scenario == "go-clte":
        features["te:chunked:1"] = "1"
    if is_go and scenario == "go-dup-cl":
        features["duplicate_cl:1"] = "1"
    if reason:
        features["negative_reason"] = reason
    if scenario.startswith("waf-") or shape.shape is ResponseShape.WAF_OR_DECEPTION:
        features[feature_key("waf_vendor", scenario.replace("waf-", "", 1))] = "1"
    if label <= 0:
        features["confirmed_finding"] = "0"
        features["not_finding"] = "1"

    if confirmed and shape.shape is ResponseShape.QUEUE_SHIFTED_REDIRECT:
        features[feature_key("finding", "queue_shift_confirmed")] = "1"
        location_path = _location_path(response)
        if location_path:
            features[feature_key("path", location_path)] = "1"

    tags: List[str] = ["native-pair", "proxy-backend"]
    tags.append("go-net-http" if is_go else "python-http-server")
    if label <= 0:
        tags.append("negative")
    if scenario.startswith("waf-") or shape.shape is ResponseShape.WAF_OR_DECEPTION:
        tags.extend(["waf-stub", "negative-template"])

    example = TrainingExample(
        host=("pair-go-" if is_go else "pair-backend-") + scenario,
        tech="nginx+h1.1",
        features=features,
        label=label,
        source="native-pair:proxy-backend",
        confidence=1.0,
    )
    record = example.as_dict()
    record["tags"] = tags
    record["metadata"] = {
        "scenario": scenario,
        "variant": variant,
        "role": role,
        "proxy": "127.0.0.1:<ephemeral>",
        "backend": (
            "go-net/http:127.0.0.1:<ephemeral>" if is_go
            else "python-http.server:127.0.0.1:<ephemeral>"
        ),
        "response": response,
    }
    return record


def _start_go_backend() -> Tuple[subprocess.Popen, int]:
    """Start the stdlib-only Go net/http backend on a 127.0.0.1 ephemeral port."""
    if shutil.which("go") is None:
        raise RuntimeError("go toolchain is required for native_pair_corpus.py")
    if not os.path.isfile(GO_BACKEND_FILE):
        raise RuntimeError("missing Go backend helper: %s" % GO_BACKEND_FILE)
    env = dict(os.environ)
    # Stdlib-only module: forbid module downloads and toolchain switching.
    env["GOTOOLCHAIN"] = "local"
    env["GOPROXY"] = "off"
    process = subprocess.Popen(
        ["go", "run", "."],
        cwd=GO_BACKEND_DIR,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    address = (process.stdout.readline() if process.stdout else "").strip()
    if not address or ":" not in address:
        details = process.stderr.read()[:1000] if process.stderr else ""
        _stop_go_backend(process)
        raise RuntimeError("Go backend did not report its address: %s" % details)
    host, port_text = address.rsplit(":", 1)
    if host not in {"127.0.0.1", "localhost", "[::1]"}:
        _stop_go_backend(process)
        raise RuntimeError("Go backend bound to non-local address: %s" % address)
    return process, int(port_text)


def _stop_go_backend(process: Optional[subprocess.Popen]) -> None:
    """Terminate the whole go-run process group (wrapper plus compiled child)."""
    if process is None or process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:  # pragma: no cover - already exited
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:  # pragma: no cover - stubborn child
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=2)
    finally:
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                stream.close()


def build_native_pair_records() -> List[Dict[str, Any]]:
    """Drive both local Python servers, the Go backend and the proxy."""
    go_process: Optional[subprocess.Popen] = None
    backend: Optional[ThreadingHTTPServer] = None
    proxy: Optional[ThreadingHTTPServer] = None
    threads: List[threading.Thread] = []
    try:
        go_process, go_port = _start_go_backend()
        backend = _new_server(BackendHandler)
        proxy = _new_server(
            ProxyHandler,
            backend_port=int(backend.server_address[1]),
            go_backend_port=go_port,
        )
        threads = [
            threading.Thread(target=backend.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True),
            threading.Thread(target=proxy.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True),
        ]
        for thread in threads:
            thread.start()
        _wait_ready(backend)
        _wait_ready(proxy)
        proxy_port = int(proxy.server_address[1])
        records: List[Dict[str, Any]] = []
        for scenario in ALL_SCENARIOS:
            variants = GO_VARIANTS if scenario.startswith("go-") else VARIANTS
            for variant in variants:
                session = "%s:%s" % (scenario, variant)
                tracker = TransitionTracker()
                for role in ROLES:
                    raw, response, shape = _probe(proxy_port, scenario, role, variant)
                    if role == "poison":
                        tracker.add(session, "poison_sent", detail="native proxy poison request")
                    else:
                        tracker.add(session, "response_queued", detail="native proxy cascade queued")
                    tracker.add(
                        session,
                        "victim_response",
                        response=response,
                        role=role,
                        target_host=CONTROL_HOST,
                        baseline=BASELINE_RESPONSE,
                        detail="%s/%s %s" % (scenario, variant, shape.shape.value),
                    )
                    records.append(_record_for_response(
                        scenario=scenario,
                        variant=variant,
                        role=role,
                        raw=raw,
                        response=response,
                        shape=shape,
                        confirmed=tracker.has_confirmed(),
                    ))
        records.extend(waf_negative_jsonl_records())
        return records
    finally:
        for server in (proxy, backend):
            if server is not None:
                server.shutdown()
                server.server_close()
        for thread in threads:
            thread.join(timeout=1.0)
        _stop_go_backend(go_process)


def write_jsonl(records: Sequence[Dict[str, Any]], path: str) -> None:
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def main() -> None:  # pragma: no cover - CLI glue
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="state/native_pair_corpus.jsonl")
    args = parser.parse_args()
    records = build_native_pair_records()
    write_jsonl(records, args.out)
    positives = sum(1 for record in records if float(record.get("label", 0.0)) > 0)
    print(json.dumps({
        "out": args.out,
        "examples": len(records),
        "positives": positives,
        "negatives": len(records) - positives,
        "hosts": len({record["host"] for record in records}),
        "backends": {
            "python-http-server": sorted(BACKEND_SCENARIOS),
            "go-net-http": list(GO_SCENARIOS),
        },
        "variants": list(VARIANTS) + list(GO_VARIANTS),
    }, indent=2, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":  # pragma: no cover
    main()
