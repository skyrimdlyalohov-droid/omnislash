"""Adaptive probe reduction: group testing, syndrome decoding, ID3 planning.

This module replaces linear enumeration of known vectors with three deterministic
math mechanisms:

* :class:`GroupTestSplitter` performs Dorfman/binary group testing over up to 64
  candidates.  A clean multiplexed batch costs exactly one request; one active
  candidate is localised in ``ceil(log2(N)) + 1`` requests (7 for N=64).
* :class:`SyndromeDecoder` maps observable parser failure features
  (status, error signature, FIN/RST, TTFB residual, NCD delta) to reference
  parser cascades using Hamming distance and cosine similarity.
* :class:`AdaptiveProbePlanner` builds a minimal ID3-style probe plan from
  Shannon information gain and emits ``omnislashd`` jobs only for hypotheses
  whose posterior probability crosses the configured threshold.

Standard library only.  No network I/O happens here: callers provide oracle
functions or feed telemetry exported by ``omnislashd``.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

# ---------------------------------------------------------------------------
# Observations and thresholds
# ---------------------------------------------------------------------------

CLOSE_TYPES = ("FIN", "RST", "KEEPALIVE")


def normalize_close_type(value: Any) -> str:
    text = str(value or "KEEPALIVE").strip().upper().replace("-", "").replace("_", "")
    if "RESET" in text or text == "RST":
        return "RST"
    if "FIN" in text or "EOF" in text or "CLOSE" in text:
        return "FIN"
    return "KEEPALIVE"


def _float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


@dataclass
class ProbeObservation:
    """One batch/probe result used by all three mechanisms."""

    status: int = 0
    error_signature: str = ""
    close_type: str = "KEEPALIVE"
    ttfb_residual_ms: float = 0.0
    ncd_delta: float = 0.0
    headers: Dict[str, str] = field(default_factory=dict)
    header_changes: Dict[str, Any] = field(default_factory=dict)
    body: str = ""
    triggered: Optional[bool] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        try:
            self.status = int(self.status or 0)
        except (TypeError, ValueError):
            self.status = 0
        self.close_type = normalize_close_type(self.close_type)
        self.ttfb_residual_ms = _float(self.ttfb_residual_ms)
        self.ncd_delta = _float(self.ncd_delta)
        self.headers = {str(k): str(v) for k, v in (self.headers or {}).items()}
        self.header_changes = dict(self.header_changes or {})
        self.error_signature = str(self.error_signature or "")
        self.body = str(self.body or "")

    @property
    def error_header_signature(self) -> str:
        return " ".join([self.error_signature] + [f"{k}: {v}" for k, v in sorted(self.headers.items())]).strip()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "error_signature": self.error_signature,
            "close_type": self.close_type,
            "ttfb_residual_ms": self.ttfb_residual_ms,
            "ncd_delta": self.ncd_delta,
            "headers": dict(sorted(self.headers.items())),
            "header_changes": dict(sorted(self.header_changes.items())),
            "body": self.body[:2000],
            "triggered": self.triggered,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProbeObservation":
        data = data or {}
        return cls(
            status=data.get("status", data.get("status_code", 0)),
            error_signature=data.get("error_signature", data.get("error_header_signature", "")),
            close_type=data.get("close_type", data.get("tcp_close_type", "KEEPALIVE")),
            ttfb_residual_ms=data.get("ttfb_residual_ms", 0.0),
            ncd_delta=data.get("ncd_delta", 0.0),
            headers=data.get("headers", {}),
            header_changes=data.get("header_changes", {}),
            body=data.get("body", ""),
            triggered=data.get("triggered"),
            metadata=data.get("metadata", {}),
        )

    @classmethod
    def from_audit_record(cls, record: Dict[str, Any]) -> "ProbeObservation":
        """Normalise one ``omnislashd`` JSONL record into an observation."""
        record = record or {}
        result = record.get("result") or {}
        responses = result.get("responses") or []
        status = 0
        headers: Dict[str, str] = {}
        body = ""
        reason = ""
        if isinstance(responses, list) and responses:
            last = responses[-1] if isinstance(responses[-1], dict) else {}
            status = int(last.get("status", 0) or 0)
            reason = str(last.get("reason", "") or "")
            body = str(last.get("body", "") or "")
            for h in last.get("headers") or []:
                if isinstance(h, dict) and h.get("key"):
                    headers[str(h["key"]).lower()] = str(h.get("value", ""))
        if not status:
            statuses = record.get("statuses") or []
            if isinstance(statuses, list) and statuses:
                status = int(statuses[-1] or 0)
        err = str(record.get("error", "") or "")
        detail = " ".join(str(f.get("detail", "")) for f in (record.get("findings") or []) if isinstance(f, dict))
        blob = " ".join([err, reason, detail, body]).lower()
        ttfb = record.get("ttfb_residual_ms")
        if ttfb is None:
            m = re.search(r"(?:residual|ttfb)[_ =:]+(-?\d+(?:\.\d+)?)", blob)
            ttfb = _float(m.group(1)) if m else 0.0
        ncd = record.get("ncd_delta")
        if ncd is None:
            m = re.search(r"ncd[_ =:]+(\d+(?:\.\d+)?)", blob)
            ncd = _float(m.group(1)) if m else (0.7 if "neighbor_shift" in blob else 0.0)
        if "reset by peer" in blob or "connection reset" in blob or " rst" in blob:
            close = "RST"
        elif "unexpected eof" in blob or " eof" in blob or "closed" in blob:
            close = "FIN"
        else:
            close = "KEEPALIVE"
        return cls(
            status=status,
            error_signature=(err + " " + reason + " " + detail)[:2000],
            close_type=close,
            ttfb_residual_ms=_float(ttfb),
            ncd_delta=_float(ncd),
            headers=headers,
            body=body,
            metadata={"job": record.get("job", ""), "target": record.get("target", ""), "probe": record.get("probe", "")},
        )


@dataclass(frozen=True)
class ProbeThresholds:
    ncd_threshold: float = 0.05
    ttfb_threshold_ms: float = 25.0
    anomaly_statuses: Tuple[int, ...] = (400, 403, 405, 413, 422, 429, 500, 501, 502, 503, 504)
    trigger_on_rst: bool = False


def observation_triggered(obs: ProbeObservation, thresholds: Optional[ProbeThresholds] = None) -> bool:
    """Return True when a batch shows a telemetry/metadata shift."""
    thresholds = thresholds or ProbeThresholds()
    if obs.triggered is not None:
        return bool(obs.triggered)
    if abs(obs.ncd_delta) >= thresholds.ncd_threshold:
        return True
    if abs(obs.ttfb_residual_ms) >= thresholds.ttfb_threshold_ms:
        return True
    if obs.header_changes:
        return True
    if obs.status in thresholds.anomaly_statuses:
        return True
    if thresholds.trigger_on_rst and obs.close_type == "RST":
        return True
    return False


def _coerce_observation(value: Any) -> ProbeObservation:
    if isinstance(value, ProbeObservation):
        return value
    if isinstance(value, dict):
        return ProbeObservation.from_dict(value)
    if isinstance(value, bool):
        return ProbeObservation(triggered=value)
    if isinstance(value, tuple) and len(value) == 2:
        obs = _coerce_observation(value[1])
        obs.triggered = bool(value[0])
        return obs
    raise TypeError(f"unsupported probe observation: {type(value)!r}")


# ---------------------------------------------------------------------------
# Group testing
# ---------------------------------------------------------------------------


@dataclass
class GroupTestResult:
    active: List[Any]
    requests: int
    batches: List[Dict[str, Any]] = field(default_factory=list)
    exhaustive: bool = False
    unresolved: List[Any] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "active": list(self.active),
            "requests": self.requests,
            "batches": list(self.batches),
            "exhaustive": self.exhaustive,
            "unresolved": list(self.unresolved),
        }


class GroupTestSplitter:
    """Dorfman group testing with binary splitting.

    ``probe_batch_fn(candidates)`` must multiplex the candidates into one probe
    and return a :class:`ProbeObservation` (or bool/dict).  With
    ``exhaustive=False`` (default) it finds one active trigger in
    ``1 + ceil(log2 N)`` requests.  ``exhaustive=True`` finds every active
    trigger and is intended for small ``k``.
    """

    def __init__(
        self,
        probe_batch_fn: Callable[[List[Any]], Any],
        thresholds: Optional[ProbeThresholds] = None,
        max_requests: int = 128,
        max_group_size: int = 64,
        exhaustive: bool = False,
    ):
        self.probe_batch_fn = probe_batch_fn
        self.thresholds = thresholds or ProbeThresholds()
        self.max_requests = max(1, int(max_requests))
        self.max_group_size = max(1, int(max_group_size))
        self.exhaustive = bool(exhaustive)
        self.requests = 0
        self.batches: List[Dict[str, Any]] = []
        self.unresolved: List[Any] = []
        self.last_result: Optional[GroupTestResult] = None

    @property
    def requests_used(self) -> int:
        return self.requests

    def _probe(self, group: List[Any]) -> bool:
        self.requests += 1
        obs: ProbeObservation
        try:
            obs = _coerce_observation(self.probe_batch_fn(list(group)))
        except Exception as exc:  # a failed batch is not evidence of a trigger
            obs = ProbeObservation(error_signature=str(exc), triggered=False)
        triggered = observation_triggered(obs, self.thresholds)
        self.batches.append({
            "size": len(group),
            "triggered": triggered,
            "status": obs.status,
            "close_type": obs.close_type,
            "ncd_delta": obs.ncd_delta,
            "ttfb_residual_ms": obs.ttfb_residual_ms,
            "changed_headers": sorted(obs.header_changes),
        })
        return triggered

    def _binary_search_known_positive(self, group: List[Any]) -> Optional[Any]:
        """Localise one active inside a group already proven positive."""
        while len(group) > 1:
            if self.requests >= self.max_requests:
                self.unresolved.extend(group)
                return None
            mid = len(group) // 2
            left = group[:mid]
            if self._probe(left):
                group = left
            else:
                group = group[mid:]
        return group[0] if group else None

    def _exhaustive_known_positive(self, group: List[Any]) -> List[Any]:
        """Find every active candidate in a group already proven positive."""
        if len(group) == 1:
            return list(group)
        if self.requests >= self.max_requests:
            self.unresolved.extend(group)
            return []
        mid = len(group) // 2
        left = group[:mid]
        right = group[mid:]
        active: List[Any] = []
        if self._probe(left):
            active.extend(self._exhaustive_known_positive(left))
            if self.requests < self.max_requests and self._probe(right):
                active.extend(self._exhaustive_known_positive(right))
        else:
            # The parent was positive and the left half is clean, so the right
            # half must contain at least one active candidate.
            active.extend(self._exhaustive_known_positive(right))
        return active

    def _run_group(self, group: List[Any]) -> List[Any]:
        if not group or self.requests >= self.max_requests:
            return []
        if not self._probe(group):
            return []
        if len(group) == 1:
            return list(group)
        if self.exhaustive:
            return self._exhaustive_known_positive(group)
        one = self._binary_search_known_positive(group)
        return [one] if one is not None else []

    def run(self, candidates: Optional[Iterable[Any]] = None) -> GroupTestResult:
        if candidates is None:
            candidates = []
        items = list(candidates)
        self.requests = 0
        self.batches = []
        self.unresolved = []
        active: List[Any] = []
        for start in range(0, len(items), self.max_group_size):
            chunk = items[start:start + self.max_group_size]
            found = self._run_group(chunk)
            active.extend(found)
            if found and not self.exhaustive:
                break
        self.last_result = GroupTestResult(
            active=active,
            requests=self.requests,
            batches=list(self.batches),
            exhaustive=self.exhaustive,
            unresolved=list(self.unresolved),
        )
        return self.last_result

    def binary_split(self, candidates: Optional[Iterable[Any]] = None) -> List[Any]:
        return self.run(candidates).active

    localize = binary_split


# ---------------------------------------------------------------------------
# Parser syndrome decoding
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ParserSyndrome:
    name: str
    frontend_parser: str
    backend_parser: str
    vector: str
    statuses: Tuple[int, ...]
    close_types: Tuple[str, ...]
    tokens: Tuple[str, ...]
    ttfb_bands: Tuple[str, ...] = ("0", "low", "mid")
    ncd_bands: Tuple[str, ...] = ("0", "low")
    weight: float = 1.0


DEFAULT_SYNDROMES: Tuple[ParserSyndrome, ...] = (
    ParserSyndrome(
        "nginx-gunicorn-clte", "nginx", "gunicorn", "CL.TE",
        statuses=(400,), close_types=("FIN",),
        tokens=("bad", "request", "content-length", "transfer-encoding", "upstream"),
        ttfb_bands=("0", "low", "mid"), ncd_bands=("0", "low"),
    ),
    ParserSyndrome(
        "haproxy-nginx-tecl", "haproxy", "nginx", "TE.CL",
        statuses=(400,), close_types=("RST",),
        tokens=("invalid", "header", "transfer-encoding", "connection", "reset"),
        ttfb_bands=("0", "low", "mid"), ncd_bands=("0", "low", "struct"),
    ),
    ParserSyndrome(
        "akamai-nginx-tete", "akamai", "nginx", "TE.TE",
        statuses=(400, 501), close_types=("FIN",),
        tokens=("akamai", "akamaighost", "server", "transfer-encoding", "bad", "request"),
        ttfb_bands=("low", "mid", "high"), ncd_bands=("0", "low", "struct"),
    ),
    ParserSyndrome(
        "cloudflare-nginx-h2", "cloudflare", "nginx", "H2_DOWNGRADE",
        statuses=(400, 502), close_types=("RST",),
        tokens=("cf-ray", "x-cache", "bad", "gateway", "upstream", "timeout", "cloudflare"),
        ttfb_bands=("mid", "high"), ncd_bands=("low", "struct", "high"),
    ),
    ParserSyndrome(
        "envoy-go-upgrade", "envoy", "go", "UPGRADE_DESYNC",
        statuses=(101, 400, 502), close_types=("FIN",),
        tokens=("upgrade", "x-envoy", "connection", "bad", "request", "envoy"),
        ttfb_bands=("0", "low", "mid", "high"), ncd_bands=("0", "low", "struct"),
    ),
    ParserSyndrome(
        "cloudflare-nginx-cache", "cloudflare", "nginx", "CACHE_UNKEYED",
        statuses=(200, 201, 304), close_types=("KEEPALIVE",),
        tokens=("x-cache", "etag", "age", "cf-ray", "vary", "via", "cache-control"),
        ttfb_bands=("0", "low", "mid", "high"), ncd_bands=("struct", "high"),
    ),
)

TOKEN_RE = re.compile(r"[a-z0-9]+(?:[-_.][a-z0-9]+)*")
ANOMALY_STATUSES = {400, 403, 405, 413, 422, 429, 500, 501, 502, 503, 504}


def _tokens(text: str) -> Set[str]:
    out: Set[str] = set()
    for token in TOKEN_RE.findall(str(text or "").lower()):
        out.add(token)
        for part in re.split(r"[-_.]", token):
            if len(part) >= 2:
                out.add(part)
    return out


def _ttfb_band(value: float) -> str:
    v = abs(_float(value))
    if v < 5:
        return "0"
    if v < 50:
        return "low"
    if v < 250:
        return "mid"
    return "high"


def _ncd_band(value: float) -> str:
    v = abs(_float(value))
    if v < 0.01:
        return "0"
    if v < 0.2:
        return "low"
    if v < 0.6:
        return "struct"
    return "high"


def observation_features(obs: ProbeObservation) -> Set[str]:
    f: Set[str] = set()
    if obs.status:
        f.add(f"status:{obs.status}")
        f.add(f"status:{obs.status // 100}xx")
        if obs.status in ANOMALY_STATUSES:
            f.add("status:anomaly")
        if 200 <= obs.status < 300:
            f.add("status:ok")
    f.add(f"close:{obs.close_type}")
    f.add(f"ttfb:{_ttfb_band(obs.ttfb_residual_ms)}")
    f.add(f"ncd:{_ncd_band(obs.ncd_delta)}")
    for token in _tokens(obs.error_signature):
        f.add("sig:" + token)
    for token in _tokens(obs.body):
        f.add("sig:" + token)
    for key, value in obs.headers.items():
        lk = str(key).lower()
        f.add("hdr:" + lk)
        for token in _tokens(lk):
            f.add("sig:" + token)
        for token in _tokens(value):
            f.add("sig:" + token)
    for key in obs.header_changes:
        f.add("hdr:" + str(key).lower())
    return f


def syndrome_features(s: ParserSyndrome) -> Set[str]:
    f: Set[str] = set()
    for status in s.statuses:
        f.add(f"status:{status}")
        f.add(f"status:{status // 100}xx")
        if status in ANOMALY_STATUSES:
            f.add("status:anomaly")
        if 200 <= status < 300:
            f.add("status:ok")
    for close in s.close_types:
        f.add("close:" + normalize_close_type(close))
    for band in s.ttfb_bands:
        f.add("ttfb:" + band)
    for band in s.ncd_bands:
        f.add("ncd:" + band)
    for token in s.tokens:
        f.add("sig:" + token.lower())
        if "-" in token:
            f.add("hdr:" + token.lower())
    return f


@dataclass
class SyndromeMatch:
    syndrome: ParserSyndrome
    frontend_parser: str
    backend_parser: str
    vector: str
    hamming_distance: int
    cosine_similarity: float
    score: float
    confidence: float = 0.0

    @property
    def frontend(self) -> str:
        return self.frontend_parser

    @property
    def backend(self) -> str:
        return self.backend_parser

    @property
    def recommended_vector(self) -> str:
        return self.vector

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.syndrome.name,
            "frontend_parser": self.frontend_parser,
            "backend_parser": self.backend_parser,
            "recommended_vector": self.vector,
            "hamming_distance": self.hamming_distance,
            "cosine_similarity": round(self.cosine_similarity, 6),
            "score": round(self.score, 6),
            "confidence": round(self.confidence, 6),
        }


class SyndromeDecoder:
    """Reference parser-cascade classifier using Hamming + cosine similarity."""

    def __init__(self, syndromes: Optional[Sequence[ParserSyndrome]] = None):
        self.syndromes: List[ParserSyndrome] = list(syndromes or DEFAULT_SYNDROMES)
        self._features = {s.name: syndrome_features(s) for s in self.syndromes}
        # Distinguishing tokens (akamai, envoy, cf-ray, ...) carry more weight
        # than generic parser words (bad, request). Without IDF, a 400/FIN
        # observation dominated by "bad request" can outvote an explicit
        # "AkamaiGHost" signature.
        df: Dict[str, int] = {}
        for feats in self._features.values():
            for feature in feats:
                df[feature] = df.get(feature, 0) + 1
        n = max(1, len(self._features))
        self._weights: Dict[str, float] = {}
        for feature, count in df.items():
            if feature.startswith("sig:"):
                self._weights[feature] = 1.0 + 1.1 * math.log((n + 1.0) / (count + 1.0))
            else:
                self._weights[feature] = 1.0

    def _weight(self, feature: str) -> float:
        return self._weights.get(feature, 1.0)

    def _score(self, obs_features: Set[str], syndrome: ParserSyndrome, obs: ProbeObservation) -> Tuple[int, float, float, float]:
        ref = self._features[syndrome.name]
        if not obs_features or not ref:
            return 0, 0.0, 0.0, 0.0
        # Status/close/latency are scored directly. Content similarity uses only
        # parser signature tokens, so generic response headers cannot drown out
        # a distinguishing token such as AkamaiGHost or CF-Ray.
        obs_sig = {f for f in obs_features if f.startswith("sig:")}
        ref_sig = {f for f in ref if f.startswith("sig:")}
        shared = obs_sig & ref_sig
        intersection = sum(self._weight(f) for f in shared)
        obs_total = sum(self._weight(f) for f in obs_sig)
        ref_total = sum(self._weight(f) for f in ref_sig)
        cosine = intersection / math.sqrt(obs_total * ref_total) if obs_total and ref_total else 0.0
        hamming = len(obs_features ^ ref)
        coverage = intersection / ref_total if ref_total else 0.0
        status_match = 1.0 if obs.status in syndrome.statuses else 0.0
        close_match = 1.0 if obs.close_type in {normalize_close_type(c) for c in syndrome.close_types} else 0.0
        ttfb_match = 1.0 if f"ttfb:{_ttfb_band(obs.ttfb_residual_ms)}" in ref else 0.0
        ncd_match = 1.0 if f"ncd:{_ncd_band(obs.ncd_delta)}" in ref else 0.0
        feature = (
            0.45 * cosine
            + 0.22 * coverage
            + 0.17 * status_match
            + 0.08 * close_match
            + 0.04 * ttfb_match
            + 0.04 * ncd_match
        )
        return hamming, cosine, feature, status_match + close_match

    def rank(self, observation: Any) -> List[SyndromeMatch]:
        obs = _coerce_observation(observation)
        feats = observation_features(obs)
        raw: List[Tuple[ParserSyndrome, int, float, float]] = []
        for syndrome in self.syndromes:
            hamming, cosine, score, _ = self._score(feats, syndrome, obs)
            raw.append((syndrome, hamming, cosine, score))
        if not raw:
            return []
        best = max(item[3] for item in raw)
        denom = sum(math.exp((item[3] - best) * 8.0) for item in raw)
        matches: List[SyndromeMatch] = []
        for syndrome, hamming, cosine, score in raw:
            confidence = math.exp((score - best) * 8.0) / denom if denom else 0.0
            matches.append(SyndromeMatch(
                syndrome=syndrome,
                frontend_parser=syndrome.frontend_parser,
                backend_parser=syndrome.backend_parser,
                vector=syndrome.vector,
                hamming_distance=hamming,
                cosine_similarity=cosine,
                score=score,
                confidence=confidence,
            ))
        matches.sort(key=lambda m: (-m.score, m.vector, m.frontend_parser, m.backend_parser))
        return matches

    def decode(self, observation: Any) -> SyndromeMatch:
        matches = self.rank(observation)
        if not matches:
            raise ValueError("SyndromeDecoder has no reference syndromes")
        return matches[0]

    classify = decode

    def decode_dict(self, observation: Any) -> Dict[str, Any]:
        return self.decode(observation).to_dict()


# ---------------------------------------------------------------------------
# ID3 / information-gain planner
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProbeAction:
    name: str
    probe: str
    tls: str = "h1"
    description: str = ""
    candidates: Tuple[str, ...] = ()
    variant: str = ""
    upgrade_type: str = ""
    expected_requests: int = 1


@dataclass(frozen=True)
class ArchitectureHypothesis:
    vector: str
    prior: float
    frontend: str
    backend: str
    likelihoods: Dict[str, float]


def default_actions(unkeyed_candidates: Optional[Sequence[str]] = None) -> Tuple[ProbeAction, ...]:
    return (
        ProbeAction("framing", "differential-fuzz", "h1", "CL/TE framing mutations"),
        ProbeAction("h2", "smuggle", "h2", "HTTP/2 to HTTP/1.1 downgrade", variant="h2.downgrade"),
        ProbeAction("upgrade", "upgrade-desync", "h1", "WebSocket/gRPC upgrade desync"),
        ProbeAction("cache", "h2-tunnel", "h2", "cache key confusion/tunnelling"),
        ProbeAction("unkeyed", "raw-replay", "h1", "batched unkeyed-header group test",
                   candidates=tuple(unkeyed_candidates or DEFAULT_UNKEYED_CANDIDATES)),
    )


def default_hypotheses() -> Tuple[ArchitectureHypothesis, ...]:
    # Priors sum to 1.0.  Likelihoods are P(trigger | hypothesis, action).
    return (
        ArchitectureHypothesis("CL.TE", 0.24, "nginx", "gunicorn", {
            "framing": 0.90, "h2": 0.20, "upgrade": 0.08, "cache": 0.10, "unkeyed": 0.10,
        }),
        ArchitectureHypothesis("TE.CL", 0.18, "haproxy", "nginx", {
            "framing": 0.85, "h2": 0.15, "upgrade": 0.08, "cache": 0.08, "unkeyed": 0.10,
        }),
        ArchitectureHypothesis("TE.TE", 0.12, "akamai", "nginx", {
            "framing": 0.70, "h2": 0.20, "upgrade": 0.10, "cache": 0.10, "unkeyed": 0.12,
        }),
        ArchitectureHypothesis("H2_DOWNGRADE", 0.20, "cloudflare", "nginx", {
            "framing": 0.25, "h2": 0.95, "upgrade": 0.20, "cache": 0.20, "unkeyed": 0.20,
        }),
        ArchitectureHypothesis("UPGRADE_DESYNC", 0.14, "envoy", "go", {
            "framing": 0.10, "h2": 0.30, "upgrade": 0.95, "cache": 0.10, "unkeyed": 0.10,
        }),
        ArchitectureHypothesis("CACHE_UNKEYED", 0.12, "cloudflare", "nginx", {
            "framing": 0.15, "h2": 0.25, "upgrade": 0.10, "cache": 0.95, "unkeyed": 0.85,
        }),
    )


def _entropy(probabilities: Iterable[float]) -> float:
    return -sum(p * math.log2(p) for p in probabilities if p > 0)


def _normalize(weights: Dict[str, float]) -> Dict[str, float]:
    total = sum(max(0.0, v) for v in weights.values())
    if total <= 0:
        n = max(1, len(weights))
        return {k: 1.0 / n for k in weights}
    return {k: max(0.0, v) / total for k, v in weights.items()}


DEFAULT_UNKEYED_CANDIDATES: Tuple[str, ...] = (
    "X-Forwarded-Host", "X-Forwarded-Scheme", "X-Forwarded-Proto", "X-Forwarded-Port",
    "X-Forwarded-Prefix", "X-Original-URL", "X-Rewrite-URL", "X-Original-Host",
    "X-HTTP-Method-Override", "X-Method-Override", "X-Override-URL", "X-Host",
    "X-Forwarded-Server", "X-Forwarded-For", "X-Real-IP", "X-Client-IP",
    "X-Cache-Key", "X-Cache-Tags", "X-Cache-Vary", "X-Cache-Status",
    "X-Proxy-Host", "X-Proxy-Path", "X-Proxy-Prefix", "X-Proxy-Cache",
    "X-Origin-URL", "X-Origin-Host", "X-Origin-Path", "X-Origin-Scheme",
    "X-Request-URI", "X-Request-Uri", "X-Request-Path", "X-Request-Host",
    "X-Forwarded-Uri", "X-Forwarded-URL", "X-Forwarded-Path", "X-Forwarded-Query",
    "X-Envoy-Original-Path", "X-Envoy-Original-URL", "X-Envoy-Internal", "X-Envoy-External-Address",
    "X-Amz-Cf-Id", "X-Amz-Cf-Pop", "CF-Connecting-IP", "CF-IPCountry",
    "True-Client-IP", "CDN-Loop", "Akamai-Origin-Hop", "X-Akamai-Config-Log",
    "X-Original-Forwarded-For", "X-Original-Client-IP", "X-Cluster-Client-IP", "X-Edge-IP",
    "X-Varnish", "X-Varnish-Host", "X-Varnish-URL", "X-Cache-Hits",
    "X-Served-By", "X-Cacheable", "X-Cache-Lookup", "X-Cache-Proxy",
    "X-Omnislash-Probe-01", "X-Omnislash-Probe-02", "X-Omnislash-Probe-03", "X-Omnislash-Probe-04",
)


@dataclass
class AdaptivePlan:
    target: str
    steps: List[Dict[str, Any]]
    observations: Dict[str, bool]
    posterior: Dict[str, float]
    entropy_before: float
    entropy_after: float
    syndrome: Optional[Dict[str, Any]]
    jobs: List[Dict[str, Any]]
    requested_probes: int
    pruned: List[str]
    priority: Optional[Dict[str, Any]] = None
    group_test: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": "omnislash.adaptive-probe/v1",
            "target": self.target,
            "steps": self.steps,
            "observations": dict(sorted(self.observations.items())),
            "posterior": {k: round(v, 6) for k, v in sorted(self.posterior.items(), key=lambda kv: (-kv[1], kv[0]))},
            "entropy_before": round(self.entropy_before, 6),
            "entropy_after": round(self.entropy_after, 6),
            "syndrome": self.syndrome,
            "jobs": self.jobs,
            "requested_probes": self.requested_probes,
            "pruned": self.pruned,
            "priority": self.priority,
            "group_test": self.group_test,
        }


class AdaptiveProbePlanner:
    """ID3-style minimal probe planner on top of the syndrome decoder."""

    def __init__(
        self,
        actions: Optional[Sequence[ProbeAction]] = None,
        hypotheses: Optional[Sequence[ArchitectureHypothesis]] = None,
        decoder: Optional[SyndromeDecoder] = None,
        prune_threshold: float = 0.02,
        max_diagnostic_actions: int = 5,
        unkeyed_candidates: Optional[Sequence[str]] = None,
    ):
        self.actions: List[ProbeAction] = list(actions or default_actions(unkeyed_candidates))
        self.hypotheses: List[ArchitectureHypothesis] = list(hypotheses or default_hypotheses())
        self.action_by_name = {a.name: a for a in self.actions}
        self.decoder = decoder or SyndromeDecoder()
        self.prune_threshold = max(0.0, float(prune_threshold))
        self.max_diagnostic_actions = max(1, int(max_diagnostic_actions))
        self.observations: List[Tuple[str, bool]] = []
        self.pruned: List[str] = []
        self.entropy_history: List[float] = []
        self.posterior: Dict[str, float] = {}
        self.reset()

    def reset(self) -> None:
        self.observations = []
        self.pruned = []
        self.posterior = _normalize({h.vector: h.prior for h in self.hypotheses})
        self.entropy_history = [self.entropy()]

    def entropy(self, posterior: Optional[Dict[str, float]] = None) -> float:
        return _entropy((posterior or self.posterior).values())

    def top_hypothesis(self) -> str:
        return max(self.posterior, key=lambda k: (self.posterior[k], k))

    def _likelihood(self, hypothesis: ArchitectureHypothesis, action: ProbeAction, triggered: bool) -> float:
        p = float(hypothesis.likelihoods.get(action.name, 0.5))
        p = min(max(p, 0.0), 1.0)
        return p if triggered else 1.0 - p

    def _posterior_after(self, action: ProbeAction, triggered: bool) -> Dict[str, float]:
        weights = {
            h.vector: self.posterior.get(h.vector, 0.0) * self._likelihood(h, action, triggered)
            for h in self.hypotheses
        }
        return _normalize(weights)

    def information_gain(self, action: Any) -> float:
        act = action if isinstance(action, ProbeAction) else self.action_by_name.get(str(action))
        if act is None:
            return 0.0
        before = self.entropy()
        p_trigger = sum(self.posterior.get(h.vector, 0.0) * self._likelihood(h, act, True) for h in self.hypotheses)
        p_clean = 1.0 - p_trigger
        after = 0.0
        if p_trigger > 0:
            after += p_trigger * self.entropy(self._posterior_after(act, True))
        if p_clean > 0:
            after += p_clean * self.entropy(self._posterior_after(act, False))
        return max(0.0, before - after)

    def next_action(self, exclude: Optional[Iterable[str]] = None) -> Optional[ProbeAction]:
        excluded = set(exclude or [])
        excluded.update(name for name, _ in self.observations)
        candidates = [a for a in self.actions if a.name not in excluded]
        if not candidates:
            return None
        return max(candidates, key=lambda a: (self.information_gain(a), a.name))

    def _prune(self) -> None:
        if not self.posterior:
            return
        kept = {k: v for k, v in self.posterior.items() if v >= self.prune_threshold}
        if not kept:
            top = self.top_hypothesis()
            kept = {top: 1.0}
        for k in sorted(self.posterior):
            if k not in kept:
                self.pruned.append(k)
        self.posterior = _normalize(kept)

    def observe(self, action: Any, triggered: bool) -> float:
        act = action if isinstance(action, ProbeAction) else self.action_by_name.get(str(action))
        if act is None:
            raise ValueError(f"unknown adaptive action: {action!r}")
        self.posterior = self._posterior_after(act, bool(triggered))
        self._prune()
        self.observations.append((act.name, bool(triggered)))
        self.entropy_history.append(self.entropy())
        return self.entropy()

    def apply_observations(self, observations: Any) -> List[Tuple[str, bool]]:
        if not observations:
            return []
        items: List[Tuple[str, bool]] = []
        if isinstance(observations, dict):
            items = [(str(k), bool(v)) for k, v in observations.items()]
        else:
            for item in observations:
                if isinstance(item, dict):
                    items.append((str(item.get("action", "")), bool(item.get("triggered"))))
                elif isinstance(item, (list, tuple)) and len(item) == 2:
                    items.append((str(item[0]), bool(item[1])))
                elif isinstance(item, str):
                    items.append((item, True))
        applied = []
        for action, triggered in items:
            if action in self.action_by_name:
                self.observe(action, triggered)
                applied.append((action, triggered))
        return applied

    def observe_syndrome(self, match: SyndromeMatch) -> None:
        if match.vector not in self.posterior:
            return
        n = len(self.posterior)
        confidence = min(max(match.confidence, 0.55), 0.98)
        if n <= 1:
            return
        other = (1.0 - confidence) / (n - 1)
        self.posterior = _normalize({
            k: v * (confidence if k == match.vector else other) for k, v in self.posterior.items()
        })
        self._prune()

    def run_group_test(
        self,
        probe_batch_fn: Callable[[List[Any]], Any],
        candidates: Optional[Sequence[Any]] = None,
        exhaustive: bool = False,
    ) -> GroupTestResult:
        """Localise unkeyed inputs with the planner's candidate set.

        ``probe_batch_fn`` is supplied by the caller (for example a daemon-backed
        oracle); this keeps the planner pure and preserves the safety boundary:
        every batch still runs through the normal probe pipeline.
        """
        pool = list(candidates if candidates is not None else (self.action_by_name.get("unkeyed").candidates
                                                               if "unkeyed" in self.action_by_name else DEFAULT_UNKEYED_CANDIDATES))
        splitter = GroupTestSplitter(
            probe_batch_fn,
            thresholds=ProbeThresholds(),
            max_requests=max(8, 1 + math.ceil(math.log2(max(1, len(pool)))) * 3),
            exhaustive=exhaustive,
        )
        return splitter.run(pool)

    def _priority(self, target: Dict[str, Any], probability: float, sniper_pool: Optional[int]) -> Optional[Dict[str, Any]]:
        try:
            try:
                from research.game_arbitrage import WeibullArbitrageScorer
                from research.meta_controller import compute_gittins_index
            except Exception:
                from game_arbitrage import WeibullArbitrageScorer  # type: ignore
                from meta_controller import compute_gittins_index  # type: ignore
            impact = float(target.get("impact", 0) or 0)
            if impact <= 0:
                impact = max(1.0, float(target.get("confidence_score", 50) or 50) / 10.0)
            age = target.get("age_seconds", target.get("first_seen_age_seconds", 0)) or 0
            odds = float(target.get("odds", 2.0) or 2.0)
            scorer = WeibullArbitrageScorer()
            score = scorer.score(impact, float(age), probability, odds, sniper_pool=sniper_pool)
            gittins = compute_gittins_index(
                successes=max(1.0, probability * 10.0),
                failures=max(1.0, (1.0 - probability) * 10.0),
                reward=impact,
                cost=1.0,
            )
            return {"weibull_kelly": score.to_dict(), "gittins_index": round(gittins, 6)}
        except Exception:
            return None

    def _job_shell(
        self,
        target: Dict[str, Any],
        name: str,
        probe: str,
        tls: str,
        action: str,
        posterior: Dict[str, float],
        step: Optional[Dict[str, Any]] = None,
        vector: str = "",
        syndrome: Optional[Dict[str, Any]] = None,
        priority: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        host = str(target.get("target") or target.get("host") or "").strip()
        ports = [int(p) for p in (target.get("known_ports") or []) if str(p).isdigit()]
        port = 443 if 443 in ports or not ports else (80 if 80 in ports else ports[0])
        metadata = {
            "adaptive": {
                "action": action,
                "step": step,
                "posterior": {k: round(v, 6) for k, v in sorted(posterior.items(), key=lambda kv: (-kv[1], kv[0]))},
                "target_vector": vector,
                "syndrome": syndrome,
                "priority": priority,
            }
        }
        return {
            "name": name,
            "enabled": True,
            "target": {"addr": f"{host}:{port}", "host": host, "path": "/"},
            "tls": tls,
            "probe": probe,
            "attempts": 1,
            "until_success": False,
            "interval": "10s",
            "timeout": "15s",
            "idle": "2s",
            "retry_delay": "1s",
            "metadata": metadata,
        }

    def _diagnostic_job(
        self,
        target: Dict[str, Any],
        action: ProbeAction,
        step: Dict[str, Any],
        posterior: Dict[str, float],
        priority: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        host = str(target.get("target") or target.get("host") or "").strip()
        job = self._job_shell(
            target, f"{host}-adaptive-{action.name}", action.probe, action.tls,
            action.name, posterior, step=step, priority=priority,
        )
        meta = job["metadata"]["adaptive"]
        meta["expected_requests"] = action.expected_requests
        if action.name == "framing":
            job["mutations"] = ["cl_te_duplicate", "te_obfuscation", "unpaired_cr", "unpaired_lf"]
            job["pairs"] = 1
            job["tech_stack"] = [str(t) for t in (target.get("tech") or [])]
        elif action.name == "h2":
            job["variant"] = action.variant or "h2.downgrade"
            job["victim_method"] = "GET"
            job["victim_path"] = "/"
        elif action.name == "upgrade":
            job["upgrade_type"] = action.upgrade_type or _target_upgrade_type(target)
        elif action.name == "cache":
            job["poison_path"] = "/"
            job["gadget_path"] = "/resources?cb=omnislash"
            job["success_contains"] = "omnislash"
            job["success_finding"] = "cache_poisoned"
        elif action.name == "unkeyed":
            candidates = list(action.candidates or DEFAULT_UNKEYED_CANDIDATES)
            job["raw_payload_hex"] = build_unkeyed_payload(host, candidates).hex()
            job["success_finding"] = "cache_poisoned"
            meta["group_candidates"] = candidates
            meta["group_test"] = {"strategy": "binary-split", "max_requests": 7, "candidates": len(candidates)}
        return job

    def _targeted_job(
        self,
        target: Dict[str, Any],
        vector: str,
        posterior: Dict[str, float],
        syndrome: Optional[Dict[str, Any]],
        priority: Optional[Dict[str, Any]],
        observation: Optional[ProbeObservation],
    ) -> Optional[Dict[str, Any]]:
        host = str(target.get("target") or target.get("host") or "").strip()
        mapping = {
            "CL.TE": ("smuggle", "h1", "cl.te"),
            "TE.CL": ("smuggle", "h1", "te.cl"),
            "TE.TE": ("smuggle", "h1", "te.te"),
            "H2_DOWNGRADE": ("smuggle", "h2", "h2.downgrade"),
            "UPGRADE_DESYNC": ("upgrade-desync", "h1", ""),
            "CACHE_UNKEYED": ("h2-tunnel", "h2", ""),
        }
        spec = mapping.get(vector)
        if spec is None:
            return None
        probe, tls, variant = spec
        job = self._job_shell(
            target, f"{host}-adaptive-strike-{vector.lower().replace('_', '-')}",
            probe, tls, "strike", posterior, vector=vector, syndrome=syndrome, priority=priority,
        )
        job["attempts"] = 1
        job["until_success"] = True
        if variant:
            job["variant"] = variant
        if vector in ("CL.TE", "TE.CL", "TE.TE"):
            job["victim_method"] = "GET"
            job["victim_path"] = "/"
        elif vector == "H2_DOWNGRADE":
            job["victim_method"] = "GET"
            job["victim_path"] = "/"
        elif vector == "UPGRADE_DESYNC":
            job["upgrade_type"] = _target_upgrade_type(target)
        elif vector == "CACHE_UNKEYED":
            job["poison_path"] = "/"
            job["gadget_path"] = "/resources?cb=omnislash"
            job["success_contains"] = "omnislash"
            job["success_finding"] = "cache_poisoned"
        if observation is not None:
            job["metadata"]["adaptive"]["observation"] = observation.to_dict()
        return job

    def plan(
        self,
        target: Dict[str, Any],
        observations: Optional[Any] = None,
        observation: Optional[Any] = None,
        max_probes: int = 7,
        min_posterior: float = 0.55,
        sniper_pool: Optional[int] = None,
    ) -> AdaptivePlan:
        if observations is not None:
            self.reset()
            applied = self.apply_observations(observations)
        else:
            applied = list(self.observations)
        entropy_before = self.entropy_history[0] if self.entropy_history else self.entropy()
        obs = observation if observation is not None else target.get("adaptive_observation")
        match: Optional[SyndromeMatch] = None
        if obs is not None:
            try:
                match = self.decoder.decode(obs)
                self.observe_syndrome(match)
            except Exception:
                match = None
        entropy_after = self.entropy()
        top = self.top_hypothesis()
        top_p = self.posterior.get(top, 0.0)
        syndrome_dict = match.to_dict() if match else None
        priority = self._priority(target, top_p, sniper_pool)
        jobs: List[Dict[str, Any]] = []
        steps: List[Dict[str, Any]] = []
        group_test: Optional[Dict[str, Any]] = None
        if top_p >= float(min_posterior):
            job = self._targeted_job(target, top, self.posterior, syndrome_dict, priority, match and _coerce_observation(obs))
            if job:
                jobs.append(job)
        else:
            budget = max(0, int(max_probes) - len(applied))
            limit = min(self.max_diagnostic_actions, budget)
            selected: Set[str] = set(name for name, _ in applied)
            for i in range(limit):
                action = self.next_action(exclude=selected)
                if action is None:
                    break
                ig = self.information_gain(action)
                if ig <= 1e-9:
                    break
                selected.add(action.name)
                pos = self._posterior_after(action, True)
                neg = self._posterior_after(action, False)
                p_trigger = sum(self.posterior.get(h.vector, 0.0) * self._likelihood(h, action, True) for h in self.hypotheses)
                step = {
                    "step": len(steps) + 1,
                    "action": action.name,
                    "probe": action.probe,
                    "tls": action.tls,
                    "expected_requests": action.expected_requests,
                    "expected_information_gain": round(ig, 6),
                    "p_trigger": round(p_trigger, 6),
                    "posterior_before": {k: round(v, 6) for k, v in sorted(self.posterior.items(), key=lambda kv: (-kv[1], kv[0]))},
                    "posterior_after_trigger": {k: round(v, 6) for k, v in sorted(pos.items(), key=lambda kv: (-kv[1], kv[0]))},
                    "posterior_after_clean": {k: round(v, 6) for k, v in sorted(neg.items(), key=lambda kv: (-kv[1], kv[0]))},
                }
                steps.append(step)
                jobs.append(self._diagnostic_job(target, action, step, self.posterior, priority))
                if action.name == "unkeyed":
                    candidate_count = len(action.candidates or DEFAULT_UNKEYED_CANDIDATES)
                    group_test = {
                        "strategy": "binary-split",
                        "oracle": "probe_batch_fn",
                        "candidates": candidate_count,
                        "max_requests": 1 + math.ceil(math.log2(max(1, candidate_count))),
                        "request_budget": min(7, 1 + math.ceil(math.log2(max(1, candidate_count)))),
                        "exhaustive": False,
                    }
                    jobs[-1]["metadata"]["adaptive"]["group_test"] = group_test
        requested = len(applied) + len(steps) + (1 if jobs and jobs[0].get("metadata", {}).get("adaptive", {}).get("action") == "strike" else 0)
        if requested > max_probes:
            jobs = jobs[:max(0, max_probes)]
            steps = steps[:max(0, max_probes - len(applied))]
            requested = len(applied) + len(steps)
        return AdaptivePlan(
            target=str(target.get("target") or target.get("host") or ""),
            steps=steps,
            observations={name: bool(value) for name, value in applied},
            posterior=dict(self.posterior),
            entropy_before=entropy_before,
            entropy_after=entropy_after,
            syndrome=syndrome_dict,
            jobs=jobs,
            requested_probes=requested,
            pruned=sorted(set(self.pruned)),
            priority=priority,
            group_test=group_test,
        )


def _target_upgrade_type(target: Dict[str, Any]) -> str:
    tech = " ".join(str(t) for t in (target.get("tech") or [])).lower()
    if "grpc" in tech or "h2c" in tech:
        return "grpc"
    ports = [int(p) for p in (target.get("known_ports") or []) if str(p).isdigit()]
    if 9000 in ports or 50051 in ports:
        return "grpc"
    return "websocket"


def build_unkeyed_payload(host: str, candidates: Sequence[str], path: str = "/") -> bytes:
    """Build one multiplexed request carrying a group of candidate headers."""
    safe: List[str] = []
    for raw in candidates:
        name = str(raw).strip()
        if re.fullmatch(r"[A-Za-z0-9!#$%&'*+.^_`|~-]{1,128}", name):
            safe.append(name)
    lines = [f"GET {path or '/'} HTTP/1.1", f"Host: {host}"]
    for i, name in enumerate(safe):
        lines.append(f"{name}: omnislash-{i:02d}")
    lines += ["Connection: close", "", ""]
    return "\r\n".join(lines).encode("utf-8", "replace")


def observation_from_audit(record: Dict[str, Any]) -> ProbeObservation:
    return ProbeObservation.from_audit_record(record)


def adaptive_observations_from_records(records: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Map ``omnislashd`` audit records to per-host action triggers.

    Adaptive diagnostic jobs are named ``<host>-adaptive-<action>``; the action
    suffix selects the ID3 branch to update.  The last observation is retained
    for syndrome decoding.
    """
    out: Dict[str, Dict[str, Any]] = {}
    for rec in records:
        if not isinstance(rec, dict):
            continue
        host = str(rec.get("target") or "").strip()
        if host.count(":") == 1:
            host = host.rsplit(":", 1)[0]
        job = str(rec.get("job") or "")
        marker = "-adaptive-"
        if marker not in job or not host:
            continue
        action = job.rsplit(marker, 1)[-1]
        if action.startswith("strike-"):
            continue
        obs = observation_from_audit(rec)
        entry = out.setdefault(host, {"actions": {}, "observations": {}, "observation": None})
        triggered = observation_triggered(obs)
        entry["actions"][action] = bool(entry["actions"].get(action, False) or triggered)
        entry["observations"][action] = obs.to_dict()
        # Prefer the anomalous record for syndrome decoding; a later clean
        # action must not erase the evidence that actually fired.
        if triggered or entry["observation"] is None:
            entry["observation"] = obs.to_dict()
    return out


def distill_trigger(
    candidates: Sequence[Any],
    probe_batch_fn: Callable[[List[Any]], Any],
    finding: Dict[str, Any],
    request: Optional[Dict[str, Any]] = None,
    test_fn: Optional[Callable[[Dict[str, Any]], bool]] = None,
) -> Dict[str, Any]:
    """Localise one trigger and hand its minimal form to ``ddmin``/Caido.

    Returns the confirmed trigger, request count, and the deterministic minimal
    artifact produced by :mod:`research.game_arbitrage`.
    """
    splitter = GroupTestSplitter(probe_batch_fn, exhaustive=False)
    result = splitter.run(candidates)
    if not result.active:
        return {"active": [], "requests": result.requests, "trigger": None, "artifact": None, "finding": None}
    trigger = result.active[0]
    req = dict(request or {})
    headers = req.get("headers") or {}
    if isinstance(headers, dict):
        headers = dict(headers)
    else:
        headers = {str(k): str(v) for k, v in headers}
    headers[str(trigger)] = "omnislash"
    req["headers"] = headers
    try:
        try:
            from research.game_arbitrage import artifact_to_finding, build_minimal_artifact
        except Exception:
            from game_arbitrage import artifact_to_finding, build_minimal_artifact  # type: ignore

        if test_fn is None:
            trigger_name = str(trigger).lower()

            def test_fn(candidate: Dict[str, Any]) -> bool:  # type: ignore
                headers = candidate.get("headers") or {}
                if isinstance(headers, dict):
                    names = {str(k).lower() for k in headers}
                else:
                    names = {str(item[0]).lower() for item in headers
                             if isinstance(item, (list, tuple)) and len(item) == 2}
                return trigger_name in names

        artifact = build_minimal_artifact(finding, req, test_fn=test_fn)
        adapted = artifact_to_finding(
            artifact,
            confidence_score=float(finding.get("confidence_score", 0) or 0),
            cross_proxy_verifications=int(finding.get("cross_proxy_verifications", 0) or 0),
        )
        return {
            "active": result.active,
            "requests": result.requests,
            "trigger": trigger,
            "artifact": artifact,
            "finding": adapted,
        }
    except Exception as exc:
        return {
            "active": result.active,
            "requests": result.requests,
            "trigger": trigger,
            "artifact": None,
            "finding": None,
            "error": str(exc),
        }
