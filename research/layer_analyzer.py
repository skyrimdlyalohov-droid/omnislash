"""Differential layer/normalization analysis for Echelon 3.

Stdlib only. Provides LayerSpectrometer, MetadataDDT and NormalizationSynthesizer.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple


@dataclass
class MarkerObservation:
    marker: str
    status: int
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""


def _norm_headers(headers: Dict[str, str]) -> Dict[str, str]:
    return {str(k).lower(): str(v) for k, v in (headers or {}).items()}


def _entropy(probs: Sequence[float]) -> float:
    return -sum(p * math.log2(p) for p in probs if p > 0)


class LayerSpectrometer:
    """Infers the likely layer stack behind a balancer from orthogonal markers."""

    LAYERS = ["cdn", "envoy", "nginx", "haproxy", "backend"]

    def __init__(self) -> None:
        self.observations: List[MarkerObservation] = []

    def observe(self, marker: str, status: int, headers: Dict[str, str], body: str = "") -> None:
        self.observations.append(MarkerObservation(marker, status, _norm_headers(headers), body))

    def _layer_signals(self, obs: MarkerObservation) -> Dict[str, float]:
        h = obs.headers
        blob = " ".join(f"{k}:{v}" for k, v in h.items()).lower()
        signals = {layer: 0.0 for layer in self.LAYERS}
        if "cf-ray" in h or "cloudflare" in blob:
            signals["cdn"] += 2.0
        if "x-cache" in h or "age" in h or "via" in h:
            signals["cdn"] += 1.0
        if "x-envoy" in blob or "envoy" in blob:
            signals["envoy"] += 2.0
        if h.get("server", "").lower().startswith("nginx"):
            signals["nginx"] += 2.0
        if h.get("server", "").lower().startswith("haproxy"):
            signals["haproxy"] += 2.0
        if "x-powered-by" in h or "x-backend" in h or "gunicorn" in blob:
            signals["backend"] += 1.5
        if obs.status in (400, 403, 429, 502, 503):
            # A rejection at the edge is weak evidence of a filtering layer.
            signals["cdn"] += 0.5
        if obs.status in (200, 201, 404):
            signals["backend"] += 0.3
        return signals

    def classify(self) -> Dict[str, float]:
        if not self.observations:
            return {}
        scores = {layer: 0.0 for layer in self.LAYERS}
        for obs in self.observations:
            for layer, v in self._layer_signals(obs).items():
                scores[layer] += v
        # softmax
        mx = max(scores.values())
        exps = {k: math.exp(v - mx) for k, v in scores.items()}
        total = sum(exps.values())
        probs = {k: v / total for k, v in exps.items()}
        return dict(sorted(probs.items(), key=lambda kv: kv[1], reverse=True))

    def information_gain(self, observations: Optional[List[MarkerObservation]] = None) -> float:
        obs = observations if observations is not None else self.observations
        if not obs:
            return 0.0
        # Gain = entropy of statuses before split - weighted entropy after marker split.
        statuses = [o.status for o in obs]
        def ent(vals: List[int]) -> float:
            if not vals:
                return 0.0
            counts: Dict[int, int] = {}
            for v in vals:
                counts[v] = counts.get(v, 0) + 1
            return _entropy([c / len(vals) for c in counts.values()])
        base = ent(statuses)
        after = 0.0
        groups: Dict[str, List[int]] = {}
        for o in obs:
            groups.setdefault(o.marker, []).append(o.status)
        for vals in groups.values():
            after += (len(vals) / len(obs)) * ent(vals)
        return max(0.0, base - after)


class MetadataDDT:
    """Compares tracing/cache metadata across request variants."""

    TRACKED = ("x-request-id", "etag", "vary", "age", "x-cache", "cf-ray", "x-envoy-upstream-service-time")

    def compare(self, baseline: Dict[str, str], variant: Dict[str, str]) -> Dict[str, Any]:
        b = _norm_headers(baseline)
        v = _norm_headers(variant)
        changed = {}
        for k in self.TRACKED:
            if k in b or k in v:
                if b.get(k) != v.get(k):
                    changed[k] = {"baseline": b.get(k), "variant": v.get(k)}
        added = {k: v[k] for k in v if k not in b}
        removed = {k: b[k] for k in b if k not in v}
        # Headers that vary while the request body/query does not should have
        # been keyed; their variance is an unkeyed-input signal.
        unkeyed = [k for k in changed if k in {"x-request-id", "etag", "age", "x-cache", "cf-ray"}]
        return {"changed": changed, "added": added, "removed": removed, "unkeyed_candidates": unkeyed}

    def analyze_sequence(self, headers_seq: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        out = []
        for i in range(1, len(headers_seq)):
            out.append(self.compare(headers_seq[i - 1], headers_seq[i]))
        return out

    def unkeyed_inputs(self, headers_seq: List[Dict[str, str]]) -> List[str]:
        seen = set()
        for d in self.analyze_sequence(headers_seq):
            for k in d.get("unkeyed_candidates", []):
                seen.add(k)
        return sorted(seen)


class NormalizationSynthesizer:
    """Synthesizes parser-divergence probes from a WAFProfile."""

    def __init__(self, profile: Any) -> None:
        self.profile = profile
        if isinstance(profile, dict):
            self.blocked_tokens: Dict[str, Any] = dict(profile.get("blocked_tokens", {}) or {})
            self.allowed_tokens: Dict[str, Any] = dict(profile.get("allowed_tokens", {}) or {})
            self.allowed_alt_whitespace: List[str] = list(profile.get("allowed_alt_whitespace", []) or [])
        else:
            self.blocked_tokens = dict(getattr(profile, "blocked_tokens", {}) or {})
            self.allowed_tokens = dict(getattr(profile, "allowed_tokens", {}) or {})
            self.allowed_alt_whitespace = list(getattr(profile, "allowed_alt_whitespace", []) or [])

    def synthesize(self) -> List[Dict[str, Any]]:
        blocked = self.blocked_tokens
        tests: List[Dict[str, Any]] = []
        if blocked.get("space_before_colon"):
            tests.append({"name": "colon_no_space", "header": "X-Omni: value", "rationale": "backend may accept while WAF rejects spaced colon"})
            tests.append({"name": "colon_tab", "header": "X-Omni\t: value", "rationale": "tab is an alternative OWS"})
        if blocked.get("tab"):
            tests.append({"name": "tab_to_space", "header": "X-Omni: a b", "rationale": "space is accepted by WAF; parser equivalence check"})
        if blocked.get("nul"):
            tests.append({"name": "nul_removed", "header": "X-Omni: ab", "rationale": "WAF strips NUL, backend may not"})
        if blocked.get("chunk_ext"):
            tests.append({"name": "chunk_ext_alt", "header": "Transfer-Encoding: chunked", "body": "5;ext=1\r\nhello\r\n0\r\n\r\n", "rationale": "chunk extension parser divergence"})
        if not tests:
            tests.append({"name": "baseline_identity", "header": "X-Omni: value", "rationale": "no blocked token observed"})
        return tests

    def equivalent_whitespace(self) -> List[str]:
        alts = list(self.allowed_alt_whitespace)
        if not alts and not self.blocked_tokens.get("space"):
            alts = [" "]
        return alts
