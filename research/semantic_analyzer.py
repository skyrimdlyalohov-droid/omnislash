#!/usr/bin/env python3
"""Semantic response-shape and desync-transition analyzer.

This module deliberately does not decide that a probe succeeded because bytes
were written to a socket. It classifies what the cascade *did*: did the parser
reject the framing, did the route miss, did a WAF/deception layer answer, or did
a victim request receive a redirect that belongs to a smuggled response?

Stdlib only, no network, no Docker. The analyzer is a pure function layer so it
can be used both by online learning and by offline calibration.
"""

from __future__ import annotations

import html
import json
import math
import re
import zlib
from dataclasses import dataclass, field
from enum import Enum
from html.parser import HTMLParser
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlparse


class ResponseShape(str, Enum):
    QUEUE_SHIFTED_REDIRECT = "QUEUE_SHIFTED_REDIRECT"
    PARSER_REJECT_STRICT = "PARSER_REJECT_STRICT"
    APP_ROUTE_MISS = "APP_ROUTE_MISS"
    WAF_OR_DECEPTION = "WAF_OR_DECEPTION"
    CLEAN_BASELINE = "CLEAN_BASELINE"


@dataclass
class ShapeResult:
    shape: ResponseShape
    confidence: float
    signals: List[str] = field(default_factory=list)
    skeleton: Dict[str, Any] = field(default_factory=dict)
    location_host: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "shape": self.shape.value,
            "confidence": round(float(self.confidence), 4),
            "signals": list(self.signals),
            "skeleton": self.skeleton,
            "location_host": self.location_host,
        }


@dataclass
class DesyncTransition:
    session: str
    confirmed: bool
    chain: List[str]
    shape: str = ""
    detail: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "session": self.session,
            "confirmed": self.confirmed,
            "chain": list(self.chain),
            "shape": self.shape,
            "detail": self.detail,
        }


_PARSER_REJECT_RE = re.compile(
    r"invalid request|bad request|unrecognized method|protocol error|"
    r"malformed|illegal request|invalid framing|invalid header",
    re.I,
)
_WAF_RE = re.compile(
    r"blocked|blocking|captcha|challenge|access denied|forbidden|"
    r"tarpit|robot|bot detected|rate limit|too many requests",
    re.I,
)
_DYNAMIC_ATTRS = {
    "nonce", "csrf", "csrf-token", "xsrf", "token", "session", "sessionid",
    "sid", "requestid", "request-id", "build", "version", "cache-bust",
}
_DYNAMIC_JSON_KEYS = {
    "nonce", "csrf", "csrf_token", "xsrf", "token", "session", "session_id",
    "sid", "request_id", "requestid", "timestamp", "expires", "etag",
}


class _TagCollector(HTMLParser):
    """Collects tag names only; attributes with dynamic values are ignored."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: Set[str] = set()
        self.counts: Dict[str, int] = {}
        self.dynamic_attrs_ignored = 0

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        name = tag.lower()
        self.tags.add(name)
        self.counts[name] = self.counts.get(name, 0) + 1
        for key, value in attrs:
            k = (key or "").lower()
            if k in _DYNAMIC_ATTRS or (value and re.search(r"\b(?:nonce|csrf|token|session)\b", value, re.I)):
                self.dynamic_attrs_ignored += 1

    def handle_startendtag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        self.handle_starttag(tag, attrs)


def _as_dict(response: Any) -> Dict[str, Any]:
    if isinstance(response, dict):
        return response
    out: Dict[str, Any] = {}
    for key in ("status", "reason", "body", "raw", "framing", "headers", "seq"):
        if hasattr(response, key):
            out[key] = getattr(response, key)
    return out


def _headers(response: Dict[str, Any]) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    raw = response.get("headers") or {}
    if isinstance(raw, dict):
        items = raw.items()
    elif isinstance(raw, (list, tuple)):
        pairs = []
        for item in raw:
            if isinstance(item, dict):
                key = item.get("key", item.get("name", ""))
                value = item.get("value", "")
            else:
                key, value = (list(item) + ["", ""])[:2]
            pairs.append((str(key), str(value)))
        items = pairs
    else:
        items = []
    for key, value in items:
        k = str(key).lower()
        out.setdefault(k, []).append(str(value))
    return out


def _header(headers: Dict[str, List[str]], key: str) -> str:
    values = headers.get(key.lower()) or []
    return values[0] if values else ""


def _body(response: Dict[str, Any]) -> str:
    return str(response.get("body") or response.get("raw") or "")


def _status(response: Dict[str, Any]) -> int:
    try:
        return int(response.get("status") or 0)
    except (TypeError, ValueError):
        return 0


def location_host(location: str) -> str:
    """Return the authority of an absolute Location value, else empty string."""
    if not location:
        return ""
    parsed = urlparse(location)
    return (parsed.netloc or parsed.hostname or "").lower().split("@")[-1]


def _is_external_location(host: str, target_host: str, external_hosts: Iterable[str]) -> bool:
    if not host:
        return False
    norm_target = target_host.lower().split(":")[0]
    norm_host = host.lower().split(":")[0]
    if norm_target and (norm_host == norm_target or norm_host.endswith("." + norm_target)):
        return False
    for known in external_hosts:
        norm_known = str(known).lower().split(":")[0]
        if norm_known and (norm_host == norm_known or norm_host.endswith("." + norm_known)):
            return True
    return bool(norm_target)  # any authority other than the target is external


def _json_skeleton(value: Any, depth: int = 0) -> Any:
    if depth >= 6:
        return "deep"
    if isinstance(value, dict):
        out: Dict[str, Any] = {}
        for key in sorted(str(k) for k in value.keys()):
            if key.lower() in _DYNAMIC_JSON_KEYS:
                out[key] = "dynamic"
            else:
                out[key] = _json_skeleton(value[key], depth + 1)
        return {"type": "object", "keys": out}
    if isinstance(value, list):
        return {"type": "array", "items": [_json_skeleton(v, depth + 1) for v in value[:3]]}
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, (int, float)):
        return "num"
    if value is None:
        return "null"
    return "str"


def structural_skeleton(body: str, content_type: str = "") -> Dict[str, Any]:
    """Build a dynamic-value-free skeleton of JSON or HTML/text bodies."""
    text = html.unescape(body or "")
    stripped = text.strip()
    lowered_type = (content_type or "").lower()
    if stripped.startswith(("{", "[")):
        try:
            return _json_skeleton(json.loads(stripped))
        except (ValueError, TypeError):
            pass
    if "<" in stripped and ">" in stripped or "html" in lowered_type:
        collector = _TagCollector()
        try:
            collector.feed(text[:200_000])
            collector.close()
        except Exception:  # pragma: no cover - HTMLParser is forgiving, but stay total
            pass
        return {
            "kind": "html",
            "tags": sorted(collector.tags),
            "tag_counts": {k: collector.counts[k] for k in sorted(collector.counts)},
            "dynamic_attrs_ignored": collector.dynamic_attrs_ignored,
        }
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_.-]{2,}", text.lower())
    shapes = sorted({re.sub(r"\d+", "N", token) for token in tokens if token not in _DYNAMIC_JSON_KEYS})
    return {"kind": "text", "token_shape": shapes[:128]}


def _skeleton_sets(skeleton: Dict[str, Any]) -> Tuple[Set[str], Set[str]]:
    keys: Set[str] = set()
    tags: Set[str] = set()
    if skeleton.get("type") == "object":
        def walk(node: Any, prefix: str = "") -> None:
            if isinstance(node, dict) and "keys" in node:
                for key, child in sorted(node["keys"].items()):
                    path = prefix + "." + key if prefix else key
                    keys.add(path)
                    walk(child, path)
            elif isinstance(node, list):
                for child in node[:3]:
                    walk(child, prefix)
        walk(skeleton)
    if skeleton.get("kind") == "html":
        tags = set(skeleton.get("tags") or [])
    if skeleton.get("kind") == "text":
        keys = set(skeleton.get("token_shape") or [])
    return keys, tags


def skeleton_shift(left: Dict[str, Any], right: Dict[str, Any]) -> float:
    """Jaccard-style semantic distance between two value-free skeletons."""
    lk, lt = _skeleton_sets(left)
    rk, rt = _skeleton_sets(right)
    if not (lk or lt or rk or rt):
        return 0.0
    union = (lk | rk) | (lt | rt)
    intersection = (lk & rk) | (lt & rt)
    return round(1.0 - (len(intersection) / float(len(union))), 4)


def normalized_compression_distance(left: str, right: str) -> float:
    a, b = (left or "").encode("utf-8", "replace"), (right or "").encode("utf-8", "replace")
    if not a and not b:
        return 0.0
    ca, cb, cab = len(zlib.compress(a, 6)), len(zlib.compress(b, 6)), len(zlib.compress(a + b, 6))
    denom = max(ca, cb)
    return 0.0 if denom == 0 else max(0.0, min(1.0, (cab - min(ca, cb)) / float(denom)))


def _token_entropy(text: str) -> float:
    tokens = re.findall(r"[A-Za-z0-9_.-]{3,}", text.lower())
    if not tokens:
        return 0.0
    counts: Dict[str, int] = {}
    for token in tokens[:2000]:
        counts[token] = counts.get(token, 0) + 1
    total = float(sum(counts.values()))
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def classify_response_shape(
    response: Any,
    *,
    role: str = "",
    target_host: str = "",
    external_hosts: Optional[Iterable[str]] = None,
    baseline: Any = None,
) -> ShapeResult:
    """Classify one response into a semantic cascade class.

    ``role`` is the request role in the experiment: ``poison``, ``victim`` or
    ``baseline``. A redirect only becomes QUEUE_SHIFTED_REDIRECT when it is
    observed on a non-poison request and points to an authority other than the
    target, which is the signature of another client's smuggled response.
    """
    resp = _as_dict(response)
    status = _status(resp)
    body = _body(resp)
    headers = _headers(resp)
    base = _as_dict(baseline) if baseline is not None else {}
    base_headers = _headers(base)
    base_body = _body(base)
    ctype = _header(headers, "content-type")
    skeleton = structural_skeleton(body, ctype)
    signals: List[str] = []
    ext = set(external_hosts or [])

    loc = _header(headers, "location")
    host = location_host(loc)
    if host and _is_external_location(host, target_host, ext):
        if role.lower() not in {"poison", "baseline"}:
            signals.append("external_location_on_victim")
            signals.append("h2_cl_queue_shifted")
            return ShapeResult(
                ResponseShape.QUEUE_SHIFTED_REDIRECT, 0.95, signals, skeleton, host
            )
        signals.append("external_location_on_poison_stream")

    if status in {400, 411, 413, 431} or _PARSER_REJECT_RE.search(body):
        signals.append("parser_rejected_framing")
        return ShapeResult(ResponseShape.PARSER_REJECT_STRICT, 0.9, signals, skeleton)

    if status in {403, 406, 418, 429, 503} or _WAF_RE.search(body):
        signals.append("waf_or_limit_signature")
        return ShapeResult(ResponseShape.WAF_OR_DECEPTION, 0.8, signals, skeleton)

    if base:
        server = _header(headers, "server")
        base_server = _header(base_headers, "server")
        ray = _header(headers, "cf-ray")
        base_ray = _header(base_headers, "cf-ray")
        if (server and base_server and server.lower() != base_server.lower()) or (
            ray and base_ray and ray.lower() != base_ray.lower()
        ):
            signals.append("infrastructure_signature_changed")
            return ShapeResult(ResponseShape.WAF_OR_DECEPTION, 0.65, signals, skeleton)
        ncd = normalized_compression_distance(body, base_body)
        entropy = _token_entropy(body)
        if entropy > 4.0 and ncd < 0.35 and len(body) > max(64, len(base_body) * 2):
            signals.append("high_entropy_low_ncd_tarpit")
            return ShapeResult(ResponseShape.WAF_OR_DECEPTION, 0.7, signals, skeleton)

    if status in {404, 405}:
        signals.append("route_miss")
        return ShapeResult(ResponseShape.APP_ROUTE_MISS, 0.85, signals, skeleton)

    signals.append("no_shift_signature")
    return ShapeResult(ResponseShape.CLEAN_BASELINE, 0.6, signals, skeleton)


class TransitionTracker:
    """Tracks poison -> queued -> victim sequences per logical session.

    Only a victim-side shift confirms learning. A poison send by itself is a
    low-value event and never produces a confirmed transition.
    """

    def __init__(self) -> None:
        self._sessions: Dict[str, List[str]] = {}
        self._transitions: List[DesyncTransition] = []

    def add(
        self,
        session: str,
        kind: str,
        *,
        response: Any = None,
        role: str = "",
        target_host: str = "",
        external_hosts: Optional[Iterable[str]] = None,
        baseline: Any = None,
        detail: str = "",
    ) -> Optional[DesyncTransition]:
        chain = self._sessions.setdefault(session, [])
        kind = kind.lower()
        if kind in {"poison_sent", "poison"}:
            chain.append("poison_sent")
            return None
        if kind in {"response_queued", "queued"}:
            chain.append("response_queued")
            return None

        shape = ""
        confirmed = False
        if kind in {"victim_response", "victim_shifted", "victim"}:
            chain.append("victim_shifted" if kind == "victim_shifted" else "victim_response")
            result = classify_response_shape(
                response or {},
                role=role or "victim",
                target_host=target_host,
                external_hosts=external_hosts,
                baseline=baseline,
            )
            shape = result.shape.value
            confirmed = result.shape is ResponseShape.QUEUE_SHIFTED_REDIRECT
            if confirmed:
                chain[-1] = "victim_shifted"
        else:
            chain.append(kind)
            return None

        required = ["poison_sent", "response_queued", "victim_shifted"]
        positions = [chain.index(item) if item in chain else -1 for item in required]
        has_full_chain = all(p >= 0 for p in positions) and positions == sorted(positions)
        confirmed = bool(confirmed and has_full_chain)
        if confirmed:
            detail = detail or "confirmed victim-side queue shift"
        elif not has_full_chain:
            detail = detail or "victim response observed without the full poison -> queued -> victim chain"
        else:
            detail = detail or "no victim-side shift"
        transition = DesyncTransition(
            session=session,
            confirmed=confirmed,
            chain=list(chain),
            shape=shape,
            detail=detail,
        )
        self._transitions.append(transition)
        return transition

    def transitions(self) -> List[DesyncTransition]:
        return list(self._transitions)

    def confirmed(self) -> List[DesyncTransition]:
        return [t for t in self._transitions if t.confirmed]

    def has_confirmed(self) -> bool:
        return any(t.confirmed for t in self._transitions)

    def reset(self, session: Optional[str] = None) -> None:
        if session is None:
            self._sessions.clear()
        else:
            self._sessions.pop(session, None)


def main() -> None:  # pragma: no cover - manual CLI helper
    import argparse

    ap = argparse.ArgumentParser(description="Classify one response from a JSON file")
    ap.add_argument("file")
    ap.add_argument("--role", default="victim")
    ap.add_argument("--target-host", default="")
    args = ap.parse_args()
    with open(args.file, "r", encoding="utf-8") as f:
        response = json.load(f)
    print(json.dumps(classify_response_shape(response, role=args.role, target_host=args.target_host).as_dict(), indent=2))


if __name__ == "__main__":  # pragma: no cover
    main()
