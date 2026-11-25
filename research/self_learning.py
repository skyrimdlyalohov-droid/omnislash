#!/usr/bin/env python3
"""Autonomous parameter inference and online experience learning.

The module learns from response shapes, desync transitions and negative
examples. It never reads the curated ``solution-derived`` playbook: the
``/resources`` gadget and framing boundaries are inferred from observed data,
local cascade simulations and Caido feedback. Curated priors that happen to be
present in a weights file are filtered out of inference.

Stdlib only; no network and no Docker are required.
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import math
import os
import re
import tempfile
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

try:
    from research.semantic_analyzer import (
        ResponseShape,
        TransitionTracker,
        classify_response_shape,
        location_host,
    )
except ImportError:  # pragma: no cover - direct script execution
    from semantic_analyzer import (  # type: ignore
        ResponseShape,
        TransitionTracker,
        classify_response_shape,
        location_host,
    )


DEFAULT_WEIGHTS_PATH = os.path.join("state", "learned_weights.json")
WEIGHTS_SCHEMA = "omnislash.learned-weights/v1"

DEFAULT_CANDIDATE_PATHS = [
    "/", "/resources", "/static", "/assets", "/login", "/api/status",
    "/api/health", "/api/*", "/favicon.ico",
]
TIMING_DEFAULTS = {
    "timing.hold_after_poison": "0s",
    "timing.victim_delay": "0s",
    "connection_mode": "fresh",
}
SOLUTION_DERIVED_MARKERS = ("solution-derived", "playbook:")

# JSONL tags that force a record to remain negative. WAF stub templates and
# manual false positives use these so they can never be promoted into a
# confirmed finding by feature aggregation or a later audit merge.
FORCED_NEGATIVE_TAGS = frozenset({
    "waf-stub", "waf_stub", "false-positive", "false_positive",
    "negative-template", "negative_template", "not-finding", "not_finding",
})

_CL_RE = re.compile(r"content-length\s*:\s*(\d+)", re.I)
_PATH_RE = re.compile(r"\b(?:GET|POST|PUT|HEAD|PATCH|DELETE)\s+(\S+)\s+HTTP/", re.I)
_LOG_PATH_RE = re.compile(r"\"(?:GET|POST|HEAD)\s+(\S+)\s+HTTP/[\d.]+\"")


@dataclass
class TrainingExample:
    host: str
    tech: str
    features: Dict[str, str]
    label: float
    source: str
    confidence: float = 1.0

    def as_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "tech": self.tech,
            "features": dict(self.features),
            "label": self.label,
            "source": self.source,
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, obj: Dict[str, Any]) -> "TrainingExample":
        return cls(
            host=str(obj.get("host") or "*"),
            tech=str(obj.get("tech") or ""),
            features={str(k): str(v) for k, v in (obj.get("features") or {}).items()},
            label=float(obj.get("label", 0.0)),
            source=str(obj.get("source") or "manual"),
            confidence=float(obj.get("confidence", 1.0)),
        )


def normalize_tech(values: Iterable[str]) -> str:
    seen: List[str] = []
    for value in values or []:
        token = str(value).strip().lower()
        aliases = {"http2": "h2", "http/2": "h2", "node.js": "node", "nodejs": "node"}
        token = aliases.get(token, token)
        if token and token not in seen:
            seen.append(token)
    return "+".join(seen)


def feature_key(name: str, value: Any) -> str:
    return "%s:%s" % (name, str(value))


def extract_cl(text: str) -> int:
    match = _CL_RE.search(text or "")
    return int(match.group(1)) if match else 0


def extract_path(text: str) -> str:
    match = _PATH_RE.search(text or "")
    return match.group(1) if match else ""


def _read_jsonish(path: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read().strip()
    if not text:
        return out
    if text.startswith("["):
        try:
            obj = json.loads(text)
            return [x for x in obj if isinstance(x, dict)]
        except ValueError:
            pass
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict):
            out.append(rec)
    return out


def _audit_identity(rec: Dict[str, Any], fallback_host: str = "*") -> Tuple[str, str]:
    learning = rec.get("learning") or {}
    host = str(learning.get("host") or fallback_host or "*")
    tech = str(learning.get("tech_stack") or "")
    if not tech:
        result = rec.get("result") or {}
        tech = str(result.get("tech_stack") or "")
    return host, tech


def _raw_request_text(rec: Dict[str, Any]) -> str:
    result = rec.get("result") or {}
    chunks: List[str] = []
    for exchange in result.get("exchanges") or []:
        raw = str(exchange.get("raw") or "")
        if "HTTP/" in raw:
            chunks.append(raw)
    return "\n".join(chunks)


def examples_from_audit(path: str, fallback_host: str = "*") -> List[TrainingExample]:
    """Turn daemon JSONL records into (features -> real outcome) examples.

    A record only becomes positive when the semantic tracker sees the complete
    poison -> queued -> victim chain, or when the daemon recorded an independent
    high-confidence finding. Sending bytes is never enough.
    """
    out: List[TrainingExample] = []
    for rec in _read_jsonish(path):
        result = rec.get("result") or {}
        responses = result.get("responses") or []
        host, tech = _audit_identity(rec, fallback_host)
        findings = [str(f.get("kind") or "") for f in (rec.get("findings") or result.get("findings") or [])]
        independently_confirmed = any(
            k in {"h2_cl_confirmed", "smuggle_confirmed", "universal_key_confirmed"}
            for k in findings
        )
        raw = _raw_request_text(rec)
        cl = extract_cl(raw)
        path_value = extract_path(raw) or str((rec.get("learning") or {}).get("mutation") or "")
        baseline = responses[0] if responses else {}
        session = "%s:%s" % (rec.get("job", "audit"), rec.get("attempt", 0))
        tracker = TransitionTracker()
        if cl:
            tracker.add(session, "poison_sent", detail="smuggled framing observed")
        if len(responses) > 1:
            tracker.add(session, "response_queued", detail="multiple cascade responses recorded")
        for index, response in enumerate(responses):
            role = "poison" if index == 0 else "victim"
            shape = classify_response_shape(
                response, role=role, target_host=host, baseline=baseline
            )
            tracker.add(
                session,
                "victim_response",
                response=response,
                role=role,
                target_host=host,
                baseline=baseline,
                detail="response[%d] %s" % (index, shape.shape.value),
            )
        for index, response in enumerate(responses):
            role = "poison" if index == 0 else "victim"
            shape = classify_response_shape(
                response, role=role, target_host=host, baseline=baseline
            )
            features: Dict[str, str] = {
                "probe": str(rec.get("probe") or ""),
                "tls": str(rec.get("tls") or ""),
                "shape": shape.shape.value,
            }
            if cl:
                features[feature_key("cl", cl)] = "1"
            if path_value:
                features[feature_key("path", path_value)] = "1"
            for kind in findings:
                features[feature_key("finding", kind)] = "1"
            label = 1.0 if (independently_confirmed or tracker.has_confirmed()) else 0.0
            if label <= 0.0 and cl in {1, 2, 3}:
                features["negative_reason"] = "cl_too_short"
            out.append(TrainingExample(
                host=host,
                tech=tech,
                features=features,
                label=label,
                source="audit:" + os.path.basename(path),
            ))
    return out


def examples_from_exploit_log(path: str, default_host: str = "*") -> List[TrainingExample]:
    out: List[TrainingExample] = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            match = _LOG_PATH_RE.search(line)
            if not match:
                continue
            path_value = match.group(1).split("?")[0] or "/"
            out.append(TrainingExample(
                host=default_host,
                tech="h2",
                features={
                    "shape": ResponseShape.QUEUE_SHIFTED_REDIRECT.value,
                    feature_key("path", path_value): "1",
                    "source_of_truth": "victim_browser",
                },
                label=1.0,
                source="exploit-log:" + os.path.basename(path),
            ))
    return out


def examples_from_feedback(path: str, confirmed: bool) -> List[TrainingExample]:
    out: List[TrainingExample] = []
    for rec in _read_jsonish(path):
        features = {str(k): str(v) for k, v in (rec.get("features") or {}).items()}
        if rec.get("cl"):
            features[feature_key("cl", rec["cl"])] = "1"
        if rec.get("path"):
            features[feature_key("path", rec["path"])] = "1"
        if not features:
            continue
        out.append(TrainingExample.from_dict({
            "host": rec.get("host") or "*",
            "tech": rec.get("tech") or "",
            "features": features,
            "label": 1.0 if confirmed else 0.0,
            "source": "caido-confirmed" if confirmed else "caido-false-positive",
        }))
    return out


def _normalise_tag(value: Any) -> str:
    return str(value).strip().lower().replace("_", "-")


def enforce_negative_tags(example: TrainingExample, tags: Sequence[Any] = ()) -> TrainingExample:
    """Force a tagged example to remain a negative, non-finding sample.

    WAF stubs, clean-noise templates and human false positives are tagged at
    generation time. This function is the ingestion-side guarantee: even a
    positive label in the JSONL cannot survive these tags.
    """
    normalized = {_normalise_tag(tag) for tag in tags}
    normalized.update(
        _normalise_tag(key[4:]) for key in example.features if key.startswith("tag:")
    )
    waf_vendor = any(key.startswith("waf_vendor:") for key in example.features)
    waf_stub = "waf-stub" in normalized or waf_vendor
    forced = bool(normalized & FORCED_NEGATIVE_TAGS) or waf_stub
    if not forced:
        return example

    example.label = 0.0
    example.features["confirmed_finding"] = "0"
    example.features["not_finding"] = "1"
    example.features["enforced_negative"] = "1"
    reasons = [r for r in str(example.features.get("negative_reason", "")).split("+") if r]
    if waf_stub and "waf_stub" not in reasons:
        reasons.append("waf_stub")
    if not reasons:
        reasons.append("forced_negative")
    example.features["negative_reason"] = "+".join(reasons)
    return example


def examples_from_training_jsonl(path: str) -> List[TrainingExample]:
    """Read TrainingExample-compatible JSONL emitted by native pair helpers."""
    out: List[TrainingExample] = []
    for obj in _read_jsonish(path):
        if not isinstance(obj.get("features"), dict):
            continue
        example = TrainingExample.from_dict(obj)
        out.append(enforce_negative_tags(example, obj.get("tags") or ()))
    return out


def local_simulations(hosts: Optional[Sequence[str]] = None) -> List[TrainingExample]:
    """Deterministic native cascade simulator: no sockets, no containers.

    Several synthetic hosts are generated by default so calibration has a real
    holdout split. The framing boundary (CL 4-8 works, CL 1-3 is rejected) is a
    property of the simulated parser, not a copy of any curated playbook.
    """
    sim_hosts = list(hosts or ["sim-h2-a", "sim-h2-b", "sim-h2-c"])
    baseline = {
        "status": 200,
        "headers": [{"key": "content-type", "value": "text/html"}],
        "body": "<html><body><h1>Lab</h1><p>ok</p></body></html>",
    }
    out: List[TrainingExample] = []
    for host in sim_hosts:
        for cl in range(1, 17):
            if cl <= 3:
                response = {
                    "status": 400,
                    "headers": [{"key": "content-type", "value": "application/json"}],
                    "body": '{"error":"Invalid request"}',
                }
                label = 0.0
            elif cl <= 8:
                response = {
                    "status": 302,
                    "headers": [{"key": "location", "value": "https://exploit.example.test/resources/"}],
                    "body": "",
                }
                label = 1.0
            else:
                response = dict(baseline)
                label = 0.0
            shape = classify_response_shape(
                response, role="victim", target_host="lab.example.test", baseline=baseline
            )
            features = {
                "probe": "h2-cl",
                "tls": "h2",
                "shape": shape.shape.value,
                feature_key("cl", cl): "1",
            }
            if 4 <= cl <= 8:
                # The gadget path is only evidence when the framing boundary
                # produced a real queue shift, not on parser-reject/no-shift.
                features[feature_key("path", "/resources")] = "1"
            if cl <= 3:
                features["negative_reason"] = "cl_too_short"
            out.append(TrainingExample(
                host=host,
                tech="h2",
                features=features,
                label=label,
                source="local-simulator:h2-cl",
            ))

        out.append(TrainingExample(
            host=host,
            tech="h2",
            features={
                "probe": "h2-cl",
                "tls": "h2",
                "shape": ResponseShape.QUEUE_SHIFTED_REDIRECT.value,
                feature_key("cl", 5): "1",
                feature_key("path", "/resources"): "1",
                "timing.hold_after_poison:2s": "1",
                "timing.victim_delay:0s": "1",
                "connection_mode:fresh": "1",
            },
            label=1.0,
            source="local-simulator:timing-window",
        ))
        out.append(TrainingExample(
            host=host,
            tech="h2",
            features={
                "probe": "h2-cl",
                "tls": "h2",
                "shape": ResponseShape.PARSER_REJECT_STRICT.value,
                "duplicate_cl:1": "1",
                "negative_reason": "duplicate_cl",
            },
            label=0.0,
            source="local-simulator:duplicate-cl",
        ))
        out.append(TrainingExample(
            host=host,
            tech="h2",
            features={
                "probe": "h2-cl",
                "tls": "h2",
                "shape": ResponseShape.CLEAN_BASELINE.value,
                "timing.hold_after_poison:0s": "1",
                "timing.victim_delay:5s": "1",
                "connection_mode:same": "1",
                "negative_reason": "timing_window",
            },
            label=0.0,
            source="local-simulator:bad-timing",
        ))
        out.append(TrainingExample(
            host=host,
            tech="nginx+h1.1",
            features={
                "probe": "smuggle-chain",
                "tls": "h1",
                "shape": ResponseShape.PARSER_REJECT_STRICT.value,
                feature_key("finding", "smuggle_confirmed"): "1",
            },
            label=1.0,
            source="local-simulator:cl.te",
        ))
        out.append(TrainingExample(
            host=host,
            tech="waf",
            features={
                "probe": "raw-replay",
                "tls": "h1",
                "shape": ResponseShape.WAF_OR_DECEPTION.value,
                feature_key("path", "/login"): "1",
            },
            label=0.0,
            source="local-simulator:waf",
        ))
    return out


def split_by_host(examples: Sequence[TrainingExample], holdout_fraction: float = 0.2) -> Tuple[List[TrainingExample], List[TrainingExample], List[str]]:
    """Strict host/lab-ID holdout. A host never appears in train and validation."""
    hosts = sorted({e.host for e in examples if e.host and e.host != "*"})
    if len(hosts) < 2 or holdout_fraction <= 0:
        return list(examples), [], []
    count = max(1, int(math.ceil(len(hosts) * holdout_fraction)))
    ranked = sorted(hosts, key=lambda h: hashlib.sha256(h.encode("utf-8")).hexdigest())
    holdout = ranked[:count]
    train = [e for e in examples if e.host in {"*", ""} or e.host not in holdout]
    validation = [e for e in examples if e.host in holdout]
    train_hosts = {e.host for e in train if e.host and e.host != "*"}
    validation_hosts = {e.host for e in validation if e.host and e.host != "*"}
    overlap = train_hosts & validation_hosts
    leaked_holdout = set(holdout) & train_hosts
    uncovered = set(hosts) - (train_hosts | validation_hosts)
    if overlap or leaked_holdout or uncovered:  # pragma: no cover - defensive invariant
        raise RuntimeError(
            "holdout leaked hosts: %s; leaked validation stands: %s; unassigned hosts: %s"
            % (sorted(overlap), sorted(leaked_holdout), sorted(uncovered))
        )
    return train, validation, holdout


def _blank_cell() -> Dict[str, Any]:
    return {"attempts": 0, "successes": 0.0, "ema": 0.0, "sources": []}


def _aggregate(examples: Sequence[TrainingExample], alpha: float) -> Dict[str, Dict[str, Any]]:
    cells: Dict[str, Dict[str, Any]] = defaultdict(_blank_cell)
    for ex in examples:
        for feature in ex.features:
            cell = cells[feature]
            cell["attempts"] += 1
            cell["successes"] += float(ex.label)
            cell["ema"] = alpha * float(ex.label) + (1.0 - alpha) * float(cell["ema"])
            source = ex.source.split(":")[0]
            if source not in cell["sources"]:
                cell["sources"].append(source)
    return dict(cells)


def _cell_score(cell: Optional[Dict[str, Any]]) -> float:
    if not cell or not cell.get("attempts"):
        return 0.5
    ema = float(cell.get("ema", 0.0))
    rate = float(cell.get("successes", 0.0)) / float(cell["attempts"])
    return round(0.5 * ema + 0.5 * rate, 4)


class ExperienceLearner:
    """EMA learner with strict host/tech isolation and a global prior."""

    def __init__(self, alpha: float = 0.3, exact_weight: float = 0.8, min_exact_attempts: int = 2) -> None:
        self.alpha = float(alpha)
        self.exact_weight = float(exact_weight)
        self.min_exact_attempts = int(min_exact_attempts)

    def fit(self, examples: Sequence[TrainingExample], holdout_fraction: float = 0.2) -> Dict[str, Any]:
        train, validation, holdout_hosts = split_by_host(examples, holdout_fraction)
        global_cells = _aggregate(train, self.alpha)
        by_host: Dict[str, List[TrainingExample]] = {}
        by_tech: Dict[str, List[TrainingExample]] = {}
        for ex in train:
            if ex.host and ex.host != "*":
                by_host.setdefault(ex.host, []).append(ex)
            if ex.tech:
                by_tech.setdefault(ex.tech, []).append(ex)
        host_cells = {host: _aggregate(items, self.alpha) for host, items in sorted(by_host.items())}
        tech_cells = {tech: _aggregate(items, self.alpha) for tech, items in sorted(by_tech.items())}

        negative_cl: List[int] = []
        negative_timing: List[str] = []
        negative_features: List[Dict[str, str]] = []
        for ex in train:
            if ex.label > 0.0:
                continue
            reasons = [r for r in str(ex.features.get("negative_reason", "")).split("+") if r]
            for key in ex.features:
                match = re.fullmatch(r"cl:(\d+)", key)
                if match and (
                    "cl_too_short" in reasons
                    or (not reasons and ex.source.startswith("local-simulator:h2-cl"))
                ):
                    value = int(match.group(1))
                    if value not in negative_cl:
                        negative_cl.append(value)
                if key.startswith(("timing.", "timing_hold_", "connection_mode:")) or key == "duplicate_cl:1":
                    if key not in negative_timing:
                        negative_timing.append(key)
            if reasons and len(negative_features) < 200:
                negative_features.append(dict(ex.features))

        weights: Dict[str, Any] = {
            "schema": WEIGHTS_SCHEMA,
            "version": 1,
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "examples": len(train),
            "algorithm": "ema",
            "alpha": self.alpha,
            "exact_weight": self.exact_weight,
            "min_exact_attempts": self.min_exact_attempts,
            "global": global_cells,
            "hosts": host_cells,
            "tech": tech_cells,
            "negative": {
                "cl": sorted(negative_cl),
                "features": negative_features,
                "timing": sorted(negative_timing),
            },
            "holdout": {
                "hosts": holdout_hosts,
                "validation_examples": len(validation),
                "metrics": self.validate(
                    {"global": global_cells, "hosts": host_cells, "tech": tech_cells},
                    validation,
                ) if validation else None,
            },
        }
        leaked = set(host_cells) & set(holdout_hosts)
        if leaked:  # pragma: no cover - defensive invariant
            raise RuntimeError("holdout leaked hosts into weights: %s" % sorted(leaked))
        return weights

    def score(self, weights: Dict[str, Any], features: Sequence[str], host: str = "*", tech: str = "") -> float:
        if not features:
            return 0.5
        scores = [self._score_feature(weights, feature, host, tech) for feature in features]
        return round(sum(scores) / len(scores), 4)

    def _score_feature(self, weights: Dict[str, Any], feature: str, host: str, tech: str) -> float:
        base_cell = (weights.get("global") or {}).get(feature)
        if self._solution_derived(base_cell):
            base = 0.5
        else:
            base = _cell_score(base_cell)
        tech_cell = ((weights.get("tech") or {}).get(tech) or {}).get(feature)
        if tech_cell and not self._solution_derived(tech_cell) and tech_cell.get("attempts", 0) >= self.min_exact_attempts:
            base = self.exact_weight * _cell_score(tech_cell) + (1.0 - self.exact_weight) * base
        host_cell = ((weights.get("hosts") or {}).get(host) or {}).get(feature)
        if host_cell and not self._solution_derived(host_cell) and host_cell.get("attempts", 0) >= self.min_exact_attempts:
            base = self.exact_weight * _cell_score(host_cell) + (1.0 - self.exact_weight) * base
        return round(base, 4)

    @staticmethod
    def _solution_derived(cell: Optional[Dict[str, Any]]) -> bool:
        if not cell:
            return False
        for source in cell.get("sources") or []:
            text = str(source).lower()
            if any(marker in text for marker in SOLUTION_DERIVED_MARKERS):
                return True
        return False

    def validate(self, weights: Dict[str, Any], examples: Sequence[TrainingExample]) -> Dict[str, Any]:
        if not examples:
            return {}
        correct = 0
        for ex in examples:
            predicted = self.score(weights, list(ex.features), ex.host, ex.tech)
            if (predicted >= 0.5) == (ex.label >= 0.5):
                correct += 1
        return {
            "accuracy": round(correct / float(len(examples)), 4),
            "examples": len(examples),
            "hosts": sorted({e.host for e in examples}),
        }


class LinUCB:
    """Small diagonal LinUCB bandit for contextual arm ranking."""

    def __init__(self, dimension: int = 64, alpha: float = 1.0) -> None:
        self.dimension = int(dimension)
        self.alpha = float(alpha)
        self.A: Dict[str, List[float]] = {}
        self.b: Dict[str, List[float]] = {}

    def vector(self, features: Dict[str, Any]) -> List[float]:
        vec = [0.0] * self.dimension
        for key, value in sorted(features.items()):
            digest = hashlib.sha256(("%s=%s" % (key, value)).encode("utf-8")).digest()
            index = int.from_bytes(digest[:4], "big") % self.dimension
            vec[index] += 1.0
        return vec

    def score(self, arm: str, features: Dict[str, Any]) -> float:
        self.A.setdefault(arm, [1.0] * self.dimension)
        self.b.setdefault(arm, [0.0] * self.dimension)
        x = self.vector(features)
        theta = [self.b[arm][i] / self.A[arm][i] for i in range(self.dimension)]
        mean = sum(theta[i] * x[i] for i in range(self.dimension))
        variance = sum((x[i] * x[i]) / self.A[arm][i] for i in range(self.dimension))
        return mean + self.alpha * math.sqrt(max(0.0, variance))

    def update(self, arm: str, features: Dict[str, Any], reward: float) -> None:
        self.A.setdefault(arm, [1.0] * self.dimension)
        self.b.setdefault(arm, [0.0] * self.dimension)
        x = self.vector(features)
        for i in range(self.dimension):
            self.A[arm][i] += x[i] * x[i]
            self.b[arm][i] += x[i] * float(reward)

    def rank(self, arms: Sequence[str], features: Dict[str, Any]) -> List[str]:
        return sorted(arms, key=lambda arm: self.score(arm, features), reverse=True)


class ParameterInferencer:
    """Derives gadget paths, framing boundaries and timing hypotheses."""

    def __init__(
        self,
        weights: Optional[Dict[str, Any]] = None,
        *,
        target_host: str = "",
        tech_stack: Optional[Iterable[str]] = None,
        external_hosts: Optional[Iterable[str]] = None,
        exact_weight: float = 0.8,
    ) -> None:
        self.weights = weights or {"global": {}, "hosts": {}, "tech": {}}
        self.target_host = target_host
        self.tech = tech_stack or ""
        if isinstance(self.tech, (list, tuple, set)):
            self.tech = normalize_tech(self.tech)
        self.external_hosts = set(external_hosts or [])
        self.learner = ExperienceLearner(exact_weight=exact_weight)

    def _score(self, feature: str) -> float:
        return self.learner._score_feature(self.weights, feature, self.target_host, str(self.tech))

    def _best_value(self, prefix: str, fallback: str) -> str:
        """Pick the best learned value for a timing/connection feature."""
        candidates = {fallback}
        scopes: List[Dict[str, Any]] = [self.weights.get("global") or {}]
        tech = str(self.tech)
        scopes.append((self.weights.get("tech") or {}).get(tech) or {})
        scopes.append((self.weights.get("hosts") or {}).get(self.target_host) or {})
        for scope in scopes:
            for key in scope:
                if key.startswith(prefix + ":"):
                    candidates.add(key.split(":", 1)[1])
        return max(candidates, key=lambda value: (self._score(prefix + ":" + value), value == fallback))

    def rank_paths(
        self,
        observations: Sequence[Dict[str, Any]],
        candidate_paths: Optional[Sequence[str]] = None,
    ) -> List[Tuple[str, float, str]]:
        candidates = list(candidate_paths or DEFAULT_CANDIDATE_PATHS)
        observed: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for obs in observations:
            path = str(obs.get("path") or extract_path(str(obs.get("body") or "")) or "/")
            observed[path.split("?")[0]].append(obs)
        ranked: List[Tuple[str, float, str]] = []
        for path in candidates:
            path = path.split("?")[0] or "/"
            reason = "prior"
            score = self._score(feature_key("path", path))
            for obs in observed.get(path, []):
                shape = classify_response_shape(
                    obs,
                    role=str(obs.get("role") or "baseline"),
                    target_host=self.target_host,
                    external_hosts=self.external_hosts,
                )
                status = int(obs.get("status") or 0)
                if shape.shape in {ResponseShape.APP_ROUTE_MISS, ResponseShape.WAF_OR_DECEPTION}:
                    score = -1.0
                    reason = shape.shape.value
                    continue
                location = ""
                for header in obs.get("headers") or []:
                    if isinstance(header, dict) and str(header.get("key", "")).lower() == "location":
                        location = str(header.get("value") or "")
                host = location_host(location)
                if status in {301, 302, 303, 307, 308} and host and host not in {self.target_host}:
                    score = 0.95
                    reason = "external_redirect"
                elif status in {301, 302, 303, 307, 308}:
                    score = 0.8
                    reason = "redirect"
                elif path and path in str(obs.get("body") or ""):
                    score = 0.7
                    reason = "path_reflected"
                else:
                    score = max(score, 0.2)
                    reason = shape.shape.value
            ranked.append((path, round(score, 4), reason))
        return sorted(ranked, key=lambda item: item[1], reverse=True)

    def rank_cl_values(
        self,
        *,
        negative_cl: Iterable[int] = (),
        low: int = 1,
        high: int = 16,
    ) -> List[Tuple[int, float]]:
        negatives = set(int(n) for n in negative_cl)
        negative_store = self.weights.get("negative") or {}
        if isinstance(negative_store, dict):
            for value in negative_store.get("cl") or []:
                negatives.add(int(value))
        elif isinstance(negative_store, list):  # backward compatibility with early drafts
            for cell in negative_store:
                for key in cell:
                    match = re.fullmatch(r"cl:(\d+)", str(key))
                    if match:
                        negatives.add(int(match.group(1)))
        ranked: List[Tuple[int, float]] = []
        for value in range(int(low), int(high) + 1):
            score = self._score(feature_key("cl", value))
            if value in negatives:
                score -= 1.0
            ranked.append((value, round(score, 4)))
        return sorted(ranked, key=lambda item: item[1], reverse=True)

    @staticmethod
    def adaptive_cl_search(
        evaluate,
        *,
        low: int = 1,
        high: int = 16,
        max_steps: int = 8,
    ) -> List[Tuple[int, str]]:
        """Bisect a monotone parser-reject -> queue-shift boundary."""
        observations: List[Tuple[int, str]] = []
        lo, hi = int(low), int(high)
        steps = 0
        while lo <= hi and steps < int(max_steps):
            steps += 1
            mid = (lo + hi) // 2
            shape = str(evaluate(mid))
            observations.append((mid, shape))
            if shape == ResponseShape.QUEUE_SHIFTED_REDIRECT.value:
                hi = mid - 1
            elif shape == ResponseShape.PARSER_REJECT_STRICT.value:
                lo = mid + 1
            else:
                lo = mid + 1
        return observations

    def infer(
        self,
        observations: Sequence[Dict[str, Any]],
        *,
        candidate_paths: Optional[Sequence[str]] = None,
        cl_range: Tuple[int, int] = (1, 16),
        max_hypotheses: int = 3,
    ) -> List[Dict[str, Any]]:
        paths = self.rank_paths(observations, candidate_paths)
        cls = self.rank_cl_values(low=cl_range[0], high=cl_range[1])
        # An unobserved path with no learned evidence is just a default 0.5; it
        # must not be emitted as an "inference".
        viable_paths = [(p, s, r) for p, s, r in paths if s > 0.5]
        viable_cl = [(cl, score) for cl, score in cls if score > 0.5]
        if not viable_paths or not viable_cl:
            return []
        hold_value = self._best_value("timing.hold_after_poison", TIMING_DEFAULTS["timing.hold_after_poison"])
        delay_value = self._best_value("timing.victim_delay", TIMING_DEFAULTS["timing.victim_delay"])
        connection_value = self._best_value("connection_mode", TIMING_DEFAULTS["connection_mode"])
        hold = self._score("timing.hold_after_poison:" + hold_value)
        delay = self._score("timing.victim_delay:" + delay_value)
        limit = max(0, int(max_hypotheses))
        if limit == 0:
            return []
        hypotheses: List[Dict[str, Any]] = []
        for path, path_score, reason in viable_paths:
            for cl, cl_score in viable_cl:
                hypotheses.append({
                    "provenance": "autonomous-inferred",
                    "probe": "h2-cl",
                    "tls": "h2",
                    "declared_length": 0,
                    "smuggled_path": path,
                    "smuggled_cl": cl,
                    "hold_after_poison": hold_value,
                    "victim_delay": delay_value,
                    "connection_mode": connection_value,
                    "scores": {
                        "path": round(path_score, 4),
                        "cl": round(cl_score, 4),
                        "timing": round((hold + delay) / 2, 4),
                    },
                    "evidence": reason,
                })
                if len(hypotheses) >= limit:
                    return hypotheses
        return hypotheses


def build_calibration_examples(
    audit_paths: Sequence[str],
    exploit_logs: Sequence[str] = (),
    feedback_confirmed: Sequence[str] = (),
    feedback_false_positive: Sequence[str] = (),
    simulate: bool = False,
    training_jsonl: Sequence[str] = (),
) -> List[TrainingExample]:
    examples: List[TrainingExample] = []
    for path in audit_paths:
        lab_id = ""
        match = re.search(r"psa-([0-9a-f]+)", path)
        if match:
            lab_id = "lab-" + match.group(1)[:12]
        examples.extend(examples_from_audit(path, fallback_host=lab_id or "*"))
    for path in exploit_logs:
        lab_id = "*"
        match = re.search(r"psa-([0-9a-f]+)", path)
        if match:
            lab_id = "lab-" + match.group(1)[:12]
        examples.extend(examples_from_exploit_log(path, default_host=lab_id))
    for path in feedback_confirmed:
        examples.extend(examples_from_feedback(path, True))
    for path in feedback_false_positive:
        examples.extend(examples_from_feedback(path, False))
    for path in training_jsonl:
        examples.extend(examples_from_training_jsonl(path))
    if simulate:
        examples.extend(local_simulations())
    return examples


ONLINE_META_KEY = "online"
_ONLINE_RANK_PREFIXES = ("path:", "cl:", "variant:", "mutation:", "probe:", "tls:", "shape:")


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def atomic_write_json(path: str, value: Any) -> None:
    """Write JSON through a same-directory temp file + os.replace.

    Readers (daemon, dashboard, tailer) never observe a half-written weight or
    status file. The temp file is fsynced before the rename so a crash cannot
    leave a truncated state file behind.
    """
    target = os.path.abspath(path)
    parent = os.path.dirname(target) or "."
    os.makedirs(parent, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-omnislash-", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(value, f, indent=2, ensure_ascii=False, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def save_weights(weights: Dict[str, Any], path: str) -> None:
    atomic_write_json(path, weights)


def _online_meta(weights: Dict[str, Any]) -> Dict[str, Any]:
    meta = weights.setdefault(ONLINE_META_KEY, {})
    meta.setdefault("processed", 0)
    meta.setdefault("positive", 0)
    meta.setdefault("negative", 0)
    meta.setdefault("holdout_skipped", 0)
    meta.setdefault("accuracy", 0.5)
    meta.setdefault("accuracy_delta", 0.0)
    meta.setdefault("accuracy_history", [])
    meta.setdefault("confirmations", {})
    meta.setdefault("hypotheses", [])
    return meta


def _ranking_features(features: Dict[str, str]) -> List[str]:
    return [key for key in sorted(features) if key.startswith(_ONLINE_RANK_PREFIXES)]


def apply_online_example(
    weights: Dict[str, Any],
    example: TrainingExample,
    *,
    alpha: Optional[float] = None,
    weight: float = 1.0,
    allow_holdout: bool = False,
) -> Dict[str, Any]:
    """Fold one streamed/feedback example into existing weights in place.

    The update mirrors ``ExperienceLearner._aggregate`` (EMA + observed rate)
    without replaying the entire corpus. Holdout hosts are never used for
    training cells; they are counted separately so a held-out lab cannot leak
    into the online prior. ``weight=2.0`` means two identical observations,
    which is how the UI's +/-2.0 quick labels are implemented.
    """
    host = example.host or "*"
    tech = example.tech or ""
    holdouts = set((weights.get("holdout") or {}).get("hosts") or [])
    repeats = max(1, int(round(float(weight))))
    meta = _online_meta(weights)
    if host != "*" and host in holdouts and not allow_holdout:
        meta["holdout_skipped"] = int(meta.get("holdout_skipped", 0)) + repeats
        meta["updated_at"] = _now()
        return {"applied": False, "reason": "holdout-isolation", "host": host}

    a = float(alpha if alpha is not None else weights.get("alpha", 0.3))
    a = min(1.0, max(0.0, a))
    label = 1.0 if example.label >= 0.5 else 0.0
    source = (example.source or "online").split(":")[0]
    features = dict(example.features)
    rank_features = _ranking_features(features)
    learner = ExperienceLearner(
        alpha=a,
        exact_weight=float(weights.get("exact_weight", 0.8)),
        min_exact_attempts=int(weights.get("min_exact_attempts", 2)),
    )
    score_before = learner.score(weights, rank_features, host, tech) if rank_features else 0.5

    global_cells = weights.setdefault("global", {})
    tech_cells = weights.setdefault("tech", {}).setdefault(tech, {}) if tech else {}
    host_cells = weights.setdefault("hosts", {}).setdefault(host, {}) if host != "*" else {}
    scopes = [global_cells]
    if tech_cells:
        scopes.append(tech_cells)
    if host_cells:
        scopes.append(host_cells)

    for feature in features:
        for scope in scopes:
            cell = dict(scope.get(feature) or {})
            for key, value in _blank_cell().items():
                cell.setdefault(key, value)
            sources = list(cell.get("sources") or [])
            if source not in sources:
                sources.append(source)
            cell["sources"] = sources
            for _ in range(repeats):
                cell["attempts"] = int(cell.get("attempts", 0)) + 1
                cell["successes"] = float(cell.get("successes", 0.0)) + label
                cell["ema"] = round(a * label + (1.0 - a) * float(cell.get("ema", 0.0)), 6)
            scope[feature] = cell

    negative = weights.setdefault("negative", {})
    if not isinstance(negative, dict):
        negative = {"cl": [], "features": [], "timing": []}
        weights["negative"] = negative
    if label <= 0.0:
        cl_values = set(int(v) for v in (negative.get("cl") or []))
        for key in features:
            match = re.fullmatch(r"cl:(\d+)", key)
            if match:
                cl_values.add(int(match.group(1)))
        negative["cl"] = sorted(cl_values)
        recent = list(negative.get("features") or [])
        recent.insert(0, dict(features))
        negative["features"] = recent[:200]
        reasons = [r for r in str(features.get("negative_reason", "")).split("+") if r]
        timing = set(negative.get("timing") or [])
        for key in features:
            if key.startswith(("timing.", "timing_hold_", "connection_mode:")) or key == "duplicate_cl:1":
                timing.add(key)
        if reasons:
            timing.add("negative_reason:" + "+".join(reasons))
        negative["timing"] = sorted(timing)

    score_after = learner.score(weights, rank_features, host, tech) if rank_features else 0.5
    weights["examples"] = int(weights.get("examples", 0)) + repeats
    weights["updated_at"] = _now()
    previous_accuracy = float(meta.get("accuracy", 0.5))
    accuracy = round(a * label + (1.0 - a) * previous_accuracy, 6)
    meta["accuracy"] = accuracy
    meta["accuracy_delta"] = round(accuracy - previous_accuracy, 6)
    history = list(meta.get("accuracy_history") or [])
    history.append({"time": _now(), "accuracy": accuracy, "label": label})
    meta["accuracy_history"] = history[-120:]
    meta["processed"] = int(meta.get("processed", 0)) + repeats
    if label > 0.0:
        meta["positive"] = int(meta.get("positive", 0)) + repeats
    else:
        meta["negative"] = int(meta.get("negative", 0)) + repeats
    meta["last_label"] = label
    meta["last_source"] = source
    meta["last_host"] = host
    meta["updated_at"] = _now()
    return {
        "applied": True,
        "host": host,
        "tech": tech,
        "label": label,
        "repeats": repeats,
        "score_before": score_before,
        "score_after": score_after,
        "score_delta": round(score_after - score_before, 4),
    }


def load_weights(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {"schema": WEIGHTS_SCHEMA, "version": 1, "global": {}, "hosts": {}, "tech": {}}
    with open(path, "r", encoding="utf-8") as f:
        obj = json.load(f)
    if not isinstance(obj, dict):
        return {"schema": WEIGHTS_SCHEMA, "version": 1, "global": {}, "hosts": {}, "tech": {}}
    obj.setdefault("schema", WEIGHTS_SCHEMA)
    obj.setdefault("global", {})
    obj.setdefault("hosts", {})
    obj.setdefault("tech", {})
    return obj


def main() -> None:  # pragma: no cover - CLI glue
    ap = argparse.ArgumentParser(description="Self-learning parameter inference for OmniSlash")
    ap.add_argument("--weights", default=DEFAULT_WEIGHTS_PATH)
    sub = ap.add_subparsers(dest="cmd", required=True)

    train = sub.add_parser("train", help="learn weights from audit and feedback data")
    train.add_argument("--audit", action="append", default=[])
    train.add_argument("--audit-glob", action="append", default=[])
    train.add_argument("--exploit-log", action="append", default=[])
    train.add_argument("--feedback-confirmed", action="append", default=[])
    train.add_argument("--feedback-false-positive", action="append", default=[])
    train.add_argument(
        "--training-jsonl", action="append", default=[],
        help="TrainingExample-compatible JSONL (native pair/WAF negative corpora)",
    )
    train.add_argument("--simulate", action="store_true", help="include native local cascade simulations")
    train.add_argument("--out", default=None)
    train.add_argument("--holdout", type=float, default=0.2)
    train.add_argument("--alpha", type=float, default=0.3)
    train.add_argument("--exact-weight", type=float, default=0.8)

    infer = sub.add_parser("infer", help="emit autonomous parameter hypotheses")
    infer.add_argument("--targets", required=True)
    infer.add_argument("--tech", action="append", default=[])
    infer.add_argument("--out", default="")
    infer.add_argument("--max", type=int, default=3)

    feedback = sub.add_parser("feedback", help="apply one manual +/- label to learned weights")
    label_group = feedback.add_mutually_exclusive_group(required=True)
    label_group.add_argument("--confirm", action="store_true", help="positive label (+2.0 by default)")
    label_group.add_argument("--false-positive", action="store_true", help="negative label (-2.0 by default)")
    feedback.add_argument("--host", default="*")
    feedback.add_argument("--tech", default="")
    feedback.add_argument("--cl", type=int, default=0)
    feedback.add_argument("--path", default="")
    feedback.add_argument("--finding", default="")
    feedback.add_argument("--features", default="{}", help="JSON object of extra feature keys")
    feedback.add_argument("--weight", type=float, default=2.0)
    feedback.add_argument("--out", default=None)

    args = ap.parse_args()
    weights_path = args.out if args.cmd == "train" and args.out else args.weights

    if args.cmd == "train":
        audit_paths = list(args.audit)
        for pattern in args.audit_glob:
            audit_paths.extend(sorted(glob.glob(pattern, recursive=True)))
        audit_paths = list(dict.fromkeys(audit_paths))
        examples = build_calibration_examples(
            audit_paths,
            args.exploit_log,
            args.feedback_confirmed,
            args.feedback_false_positive,
            simulate=args.simulate,
            training_jsonl=args.training_jsonl,
        )
        learner = ExperienceLearner(alpha=args.alpha, exact_weight=args.exact_weight)
        weights = learner.fit(examples, holdout_fraction=args.holdout)
        save_weights(weights, weights_path)
        print(json.dumps({
            "examples": len(examples),
            "train_examples": weights.get("examples"),
            "cells": len(weights.get("global") or {}),
            "holdout": weights.get("holdout") or {},
            "weights": weights_path,
        }, indent=2, ensure_ascii=False))
        return

    if args.cmd == "feedback":
        try:
            extra = json.loads(args.features or "{}")
        except ValueError as exc:
            raise SystemExit("feedback: --features must be a JSON object: %s" % exc)
        if not isinstance(extra, dict):
            raise SystemExit("feedback: --features must be a JSON object")
        features = {str(k): str(v) for k, v in extra.items()}
        if args.cl:
            features[feature_key("cl", args.cl)] = "1"
        if args.path:
            features[feature_key("path", args.path)] = "1"
        if args.finding:
            features[feature_key("finding", args.finding)] = "1"
        if not features:
            raise SystemExit("feedback: at least one of --cl, --path, --finding or --features is required")
        confirmed = bool(args.confirm)
        example = TrainingExample(
            host=args.host or "*",
            tech=args.tech or "",
            features=features,
            label=1.0 if confirmed else 0.0,
            source="manual-confirm" if confirmed else "manual-false-positive",
            confidence=abs(float(args.weight)),
        )
        if not confirmed:
            enforce_negative_tags(example, ["false-positive"])
        target = args.out or args.weights
        weights = load_weights(target)
        result = apply_online_example(weights, example, weight=args.weight)
        if result.get("applied"):
            save_weights(weights, target)
        print(json.dumps({
            "weights": target,
            "action": "confirm" if confirmed else "false-positive",
            **result,
        }, indent=2, ensure_ascii=False))
        return

    with open(args.targets, "r", encoding="utf-8") as f:
        raw = json.load(f)
    targets = raw.get("targets", []) if isinstance(raw, dict) else raw
    results = []
    for target in targets:
        if not isinstance(target, dict):
            continue
        host = str(target.get("target") or target.get("host") or "")
        tech = list(args.tech) or list(target.get("tech") or [])
        inferencer = ParameterInferencer(load_weights(args.weights), target_host=host, tech_stack=tech)
        hypotheses = inferencer.infer(
            list(target.get("observations") or []),
            candidate_paths=target.get("candidate_paths") or None,
            max_hypotheses=args.max,
        )
        results.append({"host": host, "provenance": "autonomous-inferred", "hypotheses": hypotheses})
    payload = json.dumps(results, indent=2, ensure_ascii=False)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(payload + "\n")
    print(payload)


if __name__ == "__main__":  # pragma: no cover
    main()
