"""Game-theoretic prioritisation and minimal reproducible artifacts.

* :class:`WeibullArbitrageScorer` ranks findings by

      S = V_impact * exp(-(age / scale) ** shape) * f_Kelly

  where the Kelly fraction is computed with risk odds degraded as the
  ``SniperTier`` reserve approaches (or falls below) ``min_sniper_pool``.
* :func:`ddmin` is the classic Zeller delta-debugging minimiser.  It is used
  before any confirmed finding reaches ``osint/caido_bridge.py`` or
  ``osint/notifier.py`` so alerts carry the smallest reproducing bytes/headers.
* :func:`build_minimal_artifact` emits a deterministic JSON technical report
  (schema, minimal request, response diff, proxy attribution, replay steps,
  sha256 checksum) with no generative prose.

Standard library only.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple, Union

try:  # package import
    from research.meta_controller import kelly_allocation
except Exception:  # direct script execution / flat sys.path
    try:
        from meta_controller import kelly_allocation  # type: ignore
    except Exception:  # pragma: no cover - very defensive
        def kelly_allocation(p: float, b: float) -> float:  # type: ignore
            p = min(max(float(p), 0.0), 1.0)
            if b <= 0:
                return 0.0
            return min(1.0, max(0.0, (p * b - (1.0 - p)) / b))


Payload = Union[bytes, bytearray, str, List[Any], Tuple[Any, ...]]
TestFn = Callable[[Any], bool]


# ---------------------------------------------------------------------------
# Weibull survival + Kelly arbitrage
# ---------------------------------------------------------------------------


@dataclass
class ArbitrageScore:
    task_id: str
    impact: float
    age_seconds: float
    survival: float
    probability: float
    odds: float
    effective_odds: float
    kelly: float
    sniper_pool: int
    scarcity: float
    penalty: float
    score: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "impact": round(self.impact, 6),
            "age_seconds": round(self.age_seconds, 3),
            "survival": round(self.survival, 6),
            "probability": round(self.probability, 6),
            "odds": round(self.odds, 6),
            "effective_odds": round(self.effective_odds, 6),
            "kelly": round(self.kelly, 6),
            "sniper_pool": self.sniper_pool,
            "scarcity": round(self.scarcity, 6),
            "penalty": round(self.penalty, 6),
            "score": round(self.score, 6),
        }


class WeibullArbitrageScorer:
    """Time-decayed, Kelly-weighted task priority with sniper-pool risk."""

    def __init__(
        self,
        shape: float = 1.5,
        scale_seconds: float = 86400.0,
        min_sniper_pool: int = 2,
        sniper_penalty_weight: float = 0.75,
    ):
        self.shape = float(max(shape, 0.1))
        self.scale_seconds = float(max(scale_seconds, 1.0))
        self.min_sniper_pool = max(int(min_sniper_pool), 0)
        self.sniper_penalty_weight = max(0.0, float(sniper_penalty_weight))

    def survival(self, age_seconds: float) -> float:
        age = max(float(age_seconds or 0.0), 0.0)
        if age <= 0:
            return 1.0
        return math.exp(-((age / self.scale_seconds) ** self.shape))

    def scarcity(self, sniper_pool: int) -> float:
        if self.min_sniper_pool <= 0:
            return 0.0
        pool = max(int(sniper_pool), 0)
        if pool >= self.min_sniper_pool:
            return 0.0
        return min(1.0, (self.min_sniper_pool - pool) / float(self.min_sniper_pool))

    def score(
        self,
        impact: float,
        age_seconds: float,
        probability: float,
        odds: float,
        sniper_pool: Optional[int] = None,
        task_id: str = "",
    ) -> ArbitrageScore:
        impact = max(float(impact), 0.0)
        age = max(float(age_seconds), 0.0)
        p = min(max(float(probability), 0.0), 1.0)
        b = max(float(odds), 0.0)
        pool = self.min_sniper_pool if sniper_pool is None else max(int(sniper_pool), 0)
        sur = self.survival(age)
        scarce = self.scarcity(pool)
        penalty = 1.0 + self.sniper_penalty_weight * scarce
        b_eff = b / penalty if b > 0 else 0.0
        kelly = kelly_allocation(p, b_eff)
        value = impact * sur * kelly
        return ArbitrageScore(
            task_id=task_id,
            impact=impact,
            age_seconds=age,
            survival=sur,
            probability=p,
            odds=b,
            effective_odds=b_eff,
            kelly=kelly,
            sniper_pool=pool,
            scarcity=scarce,
            penalty=penalty,
            score=value,
        )

    def score_task(self, task: Dict[str, Any], sniper_pool: Optional[int] = None, now: Optional[float] = None) -> ArbitrageScore:
        task_id = str(task.get("id") or task.get("task_id") or task.get("kind") or "task")
        impact = float(task.get("impact", task.get("v_impact", task.get("severity_score", 1.0))) or 0.0)
        p = float(task.get("p_success", task.get("probability", task.get("confidence", 0.5))) or 0.0)
        if p > 1.0:
            p /= 100.0
        odds = float(task.get("odds", task.get("b", 1.0)) or 0.0)
        age = task.get("age_seconds")
        if age is None:
            age = _age_from_discovery(task, now)
        pool = sniper_pool
        if pool is None:
            pool = task.get("sniper_pool", task.get("sniper_count"))
        return self.score(impact, float(age), p, odds, sniper_pool=pool, task_id=task_id)

    def rank(self, tasks: Iterable[Dict[str, Any]], sniper_pool: Optional[int] = None, now: Optional[float] = None) -> List[Dict[str, Any]]:
        scored: List[Tuple[ArbitrageScore, Dict[str, Any]]] = []
        for task in tasks:
            if not isinstance(task, dict):
                continue
            s = self.score_task(task, sniper_pool=sniper_pool, now=now)
            scored.append((s, task))
        scored.sort(key=lambda pair: (-pair[0].score, pair[0].task_id))
        return [
            {"task_id": s.task_id, "score": s.to_dict(), "task": task}
            for s, task in scored
        ]


def _age_from_discovery(task: Dict[str, Any], now: Optional[float]) -> float:
    raw = task.get("discovered_at", task.get("first_seen", task.get("age")))
    if raw is None:
        return 0.0
    if isinstance(raw, (int, float)):
        return max(0.0, (time.time() if now is None else now) - float(raw))
    if isinstance(raw, str):
        try:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            base = now if now is not None else time.time()
            return max(0.0, base - dt.timestamp())
        except Exception:
            return 0.0
    return 0.0


# ---------------------------------------------------------------------------
# Delta debugging (ddmin)
# ---------------------------------------------------------------------------


def _join_parts(parts: Sequence[Any], template: Any) -> Any:
    if isinstance(template, bytes):
        return b"".join(parts)
    if isinstance(template, bytearray):
        return bytearray(b"".join(parts))
    if isinstance(template, str):
        return "".join(parts)
    if isinstance(template, tuple):
        out: List[Any] = []
        for p in parts:
            out.extend(p)
        return tuple(out)
    out2: List[Any] = []
    for p in parts:
        out2.extend(p)
    return out2


def _split_parts(data: Any, n: int) -> List[Any]:
    if n <= 0:
        return [data]
    size = max(1, (len(data) + n - 1) // n)
    return [data[i:i + size] for i in range(0, len(data), size)]


def _safe_test(test_fn: TestFn, candidate: Any) -> bool:
    try:
        return bool(test_fn(candidate))
    except Exception:
        return False


def ddmin(payload: Payload, test_fn: TestFn, max_rounds: int = 10_000) -> Any:
    """Zeller's delta debugging: return a 1-minimal reproducing payload.

    ``test_fn(candidate)`` must return ``True`` while the target anomaly still
    reproduces.  If the full payload does not reproduce, it is returned
    unchanged so callers never "minimise" an unconfirmed finding.  Exceptions
    from ``test_fn`` are treated as non-reproduction.
    """
    if payload is None or len(payload) == 0:
        return payload
    data: Any = bytes(payload) if isinstance(payload, bytearray) else payload
    if not _safe_test(test_fn, data):
        return data
    n = 2
    rounds = 0
    while len(data) >= 2 and rounds < max_rounds:
        rounds += 1
        chunks = _split_parts(data, n)
        if len(chunks) < 2:
            break
        reduced = False
        for i in range(len(chunks)):
            candidate = _join_parts(chunks[:i] + chunks[i + 1:], data)
            if len(candidate) == 0:
                continue
            if _safe_test(test_fn, candidate):
                data = candidate
                n = max(2, n - 1)
                reduced = True
                break
        if reduced:
            continue
        if n >= len(data):
            break
        n = min(len(data), n * 2)
    return data


def is_one_minimal(payload: Payload, test_fn: TestFn) -> bool:
    """Check that deleting any single element breaks reproduction."""
    if payload is None or len(payload) == 0:
        return True
    for i in range(len(payload)):
        candidate = payload[:i] + payload[i + 1:]
        if len(candidate) > 0 and _safe_test(test_fn, candidate):
            return False
    return True


# ---------------------------------------------------------------------------
# Minimal deterministic artifact
# ---------------------------------------------------------------------------


@dataclass
class MinimalRequest:
    method: str = "GET"
    host: str = ""
    path: str = "/"
    headers: List[Tuple[str, str]] = field(default_factory=list)
    body: bytes = b""

    def header_dict(self) -> Dict[str, str]:
        return {k: v for k, v in self.headers}


def _headers_to_list(headers: Any) -> List[Tuple[str, str]]:
    if isinstance(headers, dict):
        return [(str(k), str(v)) for k, v in headers.items()]
    out: List[Tuple[str, str]] = []
    if isinstance(headers, (list, tuple)):
        for item in headers:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                out.append((str(item[0]), str(item[1])))
    return out


def _body_bytes(body: Any) -> bytes:
    if body is None:
        return b""
    if isinstance(body, bytes):
        return body
    if isinstance(body, bytearray):
        return bytes(body)
    return str(body).encode("utf-8", "replace")


def minimize_request(request: Dict[str, Any], test_fn: TestFn) -> MinimalRequest:
    """Minimise headers and body while ``test_fn(request_dict)`` stays true."""
    headers = _headers_to_list(request.get("headers") or request.get("request_headers") or [])
    body = _body_bytes(request.get("body") or request.get("raw_body") or b"")
    base = {
        "method": str(request.get("method") or "GET").upper(),
        "host": str(request.get("host") or ""),
        "path": str(request.get("path") or "/"),
    }
    if body:
        body = ddmin(body, lambda b: _safe_test(test_fn, {**base, "headers": headers, "body": b}))
    if headers:
        headers = ddmin(headers, lambda hs: _safe_test(test_fn, {**base, "headers": list(hs), "body": body}))
    return MinimalRequest(method=base["method"], host=base["host"], path=base["path"], headers=list(headers), body=body)


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def build_minimal_artifact(
    finding: Dict[str, Any],
    request: Optional[Dict[str, Any]] = None,
    test_fn: Optional[TestFn] = None,
    response_diff: Optional[Any] = None,
    evidence: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build the deterministic technical artifact forwarded to Caido/Telegram.

    The artifact contains only the minimal request, the response diff, proxy
    attribution and literal replay steps.  No generated prose is included.
    """
    req = dict(request or finding.get("request") or {})
    if not req and isinstance(finding.get("raw_request"), str):
        try:
            from research.state_and_chains import parse_raw_request
        except Exception:  # direct script execution
            from state_and_chains import parse_raw_request  # type: ignore

        parsed = parse_raw_request(finding["raw_request"])
        req = {
            "method": parsed.get("method", ""),
            "path": parsed.get("path", "/"),
            "host": parsed.get("host", ""),
            "headers": parsed.get("headers", {}),
        }
    if test_fn is not None:
        minimal = minimize_request(req, test_fn)
    else:
        minimal = MinimalRequest(
            method=str(req.get("method") or "GET").upper(),
            host=str(req.get("host") or ""),
            path=str(req.get("path") or "/"),
            headers=_headers_to_list(req.get("headers") or []),
            body=_body_bytes(req.get("body") or b""),
        )
    diff = response_diff if response_diff is not None else finding.get("response_diff", [])
    if diff is None:
        diff = []
    attribution = finding.get("attribution") if isinstance(finding.get("attribution"), dict) else {}
    label = str(finding.get("proxy_label") or attribution.get("proxy", "") or "")
    kind = str(finding.get("kind") or "finding")
    checksum_source = {
        "schema": "omnislash.minimal-artifact/v1",
        "kind": kind,
        "host": minimal.host or str(finding.get("host") or finding.get("target") or ""),
        "method": minimal.method,
        "path": minimal.path,
        "headers": sorted([list(h) for h in minimal.headers]),
        "body_b64": base64.b64encode(minimal.body).decode("ascii"),
        "response_diff": diff,
        "proxy_label": label,
    }
    checksum = hashlib.sha256(_canonical_json(checksum_source).encode("utf-8")).hexdigest()
    host = checksum_source["host"]
    artifact: Dict[str, Any] = {
        "schema": "omnislash.minimal-artifact/v1",
        "kind": kind,
        "title": f"omnislash:{kind}:{minimal.method} {minimal.path}",
        "host": host,
        "request": {
            "request_line": f"{minimal.method} {minimal.path} HTTP/1.1",
            "headers": [list(h) for h in minimal.headers],
            "body_b64": checksum_source["body_b64"],
            "body_len": len(minimal.body),
        },
        "response_diff": diff,
        "attribution": {
            "proxy_label": label,
            "source": str(finding.get("source") or "omnislash"),
            "job": str(finding.get("job") or ""),
        },
        "reproduction": {
            "tool": "caido_replay",
            "proxy_pin_header": "X-Omnislash-Proxy",
            "steps": [
                f"Pin egress: X-Omnislash-Proxy: {label}" if label else "Pin egress to the attributed proxy",
                f"Replay exactly: {minimal.method} {minimal.path} HTTP/1.1",
                "Send only the listed headers/body bytes; preserve order and duplicates",
                "Compare observed response headers/body with response_diff",
            ],
        },
        "evidence": dict(sorted((evidence or {}).items())),
        "checksum_sha256": checksum,
    }
    return artifact


def artifact_to_finding(
    artifact: Dict[str, Any],
    confidence_score: float = 0.0,
    cross_proxy_verifications: int = 0,
) -> Dict[str, Any]:
    """Adapt an artifact to the shape consumed by ``osint/notifier.py``."""
    return {
        "kind": artifact.get("kind", "finding"),
        "target": artifact.get("host", ""),
        "host": artifact.get("host", ""),
        "path": (artifact.get("request") or {}).get("request_line", "").split(" ")[1]
        if (artifact.get("request") or {}).get("request_line")
        else "/",
        "confidence_score": confidence_score,
        "cross_proxy_verifications": cross_proxy_verifications,
        "proxy_label": (artifact.get("attribution") or {}).get("proxy_label", ""),
        "detail": "minimal artifact {} ({} body bytes)".format(
            artifact.get("checksum_sha256", "")[:16],
            (artifact.get("request") or {}).get("body_len", 0),
        ),
        "minimal_artifact": artifact,
    }


def minimal_artifact_for_finding(
    finding: Dict[str, Any],
    test_fn: Optional[TestFn] = None,
    request: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Distill a finding immediately before handing it to Caido/Telegram."""
    return build_minimal_artifact(finding, request=request, test_fn=test_fn)
