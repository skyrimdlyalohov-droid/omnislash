#!/usr/bin/env python3
"""Streaming closed-loop feedback worker for omnislashd.

The worker tails the daemon's JSONL audit from a persisted byte offset,
classifies every completed attempt with the semantic analyzer, folds the
observation into ``state/learned_weights.json`` atomically and publishes
verified strike jobs in ``state/jobs_online.json``. Unverified signals adjust
weights as a weak signal but are only ever written to the ``candidates`` array:
the daemon refuses to execute them until the same path/framing was confirmed
from two independently attributed proxy exits.

Stdlib only; no network, Docker or Node.js is used.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

try:
    from research.self_learning import (
        DEFAULT_WEIGHTS_PATH,
        ExperienceLearner,
        ParameterInferencer,
        TrainingExample,
        _audit_identity,
        _now,
        apply_online_example,
        atomic_write_json,
        enforce_negative_tags,
        extract_cl,
        extract_path,
        feature_key,
        load_weights,
        normalize_tech,
    )
    from research.semantic_analyzer import (
        ResponseShape,
        TransitionTracker,
        classify_response_shape,
    )
except ImportError:  # pragma: no cover - direct script execution
    from self_learning import (  # type: ignore
        DEFAULT_WEIGHTS_PATH,
        ExperienceLearner,
        ParameterInferencer,
        TrainingExample,
        _audit_identity,
        _now,
        apply_online_example,
        atomic_write_json,
        enforce_negative_tags,
        extract_cl,
        extract_path,
        feature_key,
        load_weights,
        normalize_tech,
    )
    from semantic_analyzer import (  # type: ignore
        ResponseShape,
        TransitionTracker,
        classify_response_shape,
    )


JOBS_SCHEMA = "omnislash.jobs-online/v1"
OFFSET_SCHEMA = "omnislash.online-offset/v1"
STATUS_SCHEMA = "omnislash.online-status/v1"
MIN_CROSS_PROXY_IDENTITIES = 2

CONFIRMED_FINDINGS = frozenset({
    "h2_cl_confirmed",
    "smuggle_confirmed",
    "universal_key_confirmed",
    "queue_shift_confirmed",
})

_CL_MUTATION_RE = re.compile(r"cl[:=](\d+)", re.I)
_PATH_MUTATION_RE = re.compile(r"path[:=](/\S*)", re.I)
_SEEN_LIMIT = 2048


def _read_json(path: str, default: Any) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
        return obj if isinstance(obj, type(default)) else default
    except (OSError, ValueError):
        return default


def _identity(rec: Dict[str, Any]) -> List[str]:
    """One verified egress identity per audit record.

    A single proxy has both a label and an exit IP; counting them separately
    would fake cross-proxy confirmation. Prefer the validated exit IP.
    """
    attribution = rec.get("attribution") or {}
    if not isinstance(attribution, dict) or not attribution.get("verified"):
        return []
    value = str(attribution.get("exit_ip") or "") or str(attribution.get("proxy") or "")
    return [value] if value else []


def _host_port(target: str, fallback: str) -> Tuple[str, str]:
    target = str(target or "").strip()
    if not target and fallback:
        # No observed dial address: do not invent a port. Candidates stay
        # unexecutable until the daemon supplies a real target.
        return fallback, ""
    if ":" in target:
        host, port = target.rsplit(":", 1)
        if port.isdigit():
            return host or fallback, target
    return target or fallback, ""


def _ranking_features(example: TrainingExample) -> List[str]:
    prefixes = ("path:", "cl:", "variant:", "mutation:", "probe:", "tls:", "shape:")
    return [key for key in sorted(example.features) if key.startswith(prefixes)]


class OnlineLoop:
    """Tail an audit JSONL and keep weights/jobs/status files current."""

    def __init__(
        self,
        *,
        audit_path: str,
        weights_path: str = DEFAULT_WEIGHTS_PATH,
        jobs_path: str = "state/jobs_online.json",
        offset_path: str = "state/online_loop_offset.json",
        status_path: str = "state/online_status.json",
        control_path: str = "state/online_loop_control.json",
        interval: float = 0.25,
        alpha: Optional[float] = None,
        max_hypotheses: int = 1,
    ) -> None:
        self.audit_path = os.path.abspath(audit_path)
        self.weights_path = os.path.abspath(weights_path)
        self.jobs_path = os.path.abspath(jobs_path)
        self.offset_path = os.path.abspath(offset_path)
        self.status_path = os.path.abspath(status_path)
        self.control_path = os.path.abspath(control_path)
        self.interval = max(0.01, float(interval))
        self.alpha = alpha
        self.max_hypotheses = max(0, int(max_hypotheses))
        self.stop_event = threading.Event()
        self._seen: Dict[str, float] = {}
        self._last_jobs_hash = ""
        self._control_seq: Any = None
        self._paused = False
        self._last_error = ""

    # ------------------------------------------------------------------ control

    @property
    def paused(self) -> bool:
        return self._paused

    def _read_control(self) -> None:
        control = _read_json(self.control_path, {})
        seq = control.get("seq")
        if not isinstance(control, dict) or not control:
            enabled = True
        else:
            enabled = bool(control.get("enabled", True))
        if seq != self._control_seq:
            self._control_seq = seq
            self._paused = not enabled
        else:
            self._paused = not enabled

    # -------------------------------------------------------------------- state

    def _offset_state(self) -> Dict[str, Any]:
        state = _read_json(self.offset_path, {})
        state.setdefault("schema", OFFSET_SCHEMA)
        state.setdefault("offset", 0)
        state.setdefault("inode", 0)
        state.setdefault("device", 0)
        return state

    def _save_offset(self, offset: int, stat: os.stat_result) -> None:
        atomic_write_json(self.offset_path, {
            "schema": OFFSET_SCHEMA,
            "offset": offset,
            "inode": stat.st_ino,
            "device": stat.st_dev,
            "size": stat.st_size,
            "updated_at": _now(),
        })

    def read_new_lines(self) -> Tuple[List[str], int, Optional[os.stat_result]]:
        """Return complete JSONL lines appended since the last committed offset."""
        try:
            stat = os.stat(self.audit_path)
        except OSError:
            return [], 0, None
        state = self._offset_state()
        offset = int(state.get("offset") or 0)
        if (
            int(state.get("inode") or 0) != stat.st_ino
            or int(state.get("device") or 0) != stat.st_dev
            or offset < 0
            or offset > stat.st_size
        ):
            # Rotation or truncation: replay from the beginning of the new file.
            offset = 0
        with open(self.audit_path, "rb") as f:
            f.seek(offset)
            chunk = f.read()
        end = chunk.rfind(b"\n")
        if end < 0:
            return [], offset, stat
        lines = [
            line.decode("utf-8", "replace")
            for line in chunk[:end].split(b"\n")
            if line.strip()
        ]
        return lines, offset + end + 1, stat

    # ------------------------------------------------------------------ records

    def _analyse(self, rec: Dict[str, Any]) -> Dict[str, Any]:
        learning = rec.get("learning") or {}
        host, tech = _audit_identity(rec, fallback_host="*")
        target = str(rec.get("target") or "")
        dial_host, dial_addr = _host_port(target, host)
        if host == "*" and dial_host and dial_host != "*":
            host = dial_host
        tech = normalize_tech([tech]) if tech else ""

        result = rec.get("result") or {}
        responses = [r for r in (result.get("responses") or []) if isinstance(r, dict)]
        statuses = rec.get("statuses") or []
        if not responses and statuses:
            responses = [{"status": int(s), "body": ""} for s in statuses if isinstance(s, (int, float))]
        baseline = responses[0] if responses else None

        raw_request = ""
        for exchange in result.get("exchanges") or []:
            if isinstance(exchange, dict) and "HTTP/" in str(exchange.get("raw") or ""):
                raw_request += str(exchange.get("raw") or "") + "\n"
        mutation = str(learning.get("mutation") or "")
        cl = extract_cl(raw_request)
        if not cl:
            match = _CL_MUTATION_RE.search(mutation)
            cl = int(match.group(1)) if match else 0
        if not cl:
            cl = int(rec.get("declared_length") or result.get("declared_length") or 0)
        path = extract_path(raw_request) or str(learning.get("path") or rec.get("path") or "")
        if not path:
            match = _PATH_MUTATION_RE.search(mutation)
            path = match.group(1) if match else ""
        if not path:
            # A confirmed victim redirect names the smuggled gadget path even
            # when the daemon log has no raw exchange (e.g. a manual audit).
            for response in reversed(responses):
                for header in response.get("headers") or []:
                    if isinstance(header, dict) and str(header.get("key", "")).lower() == "location":
                        candidate = urlparse(str(header.get("value") or "")).path
                        if candidate:
                            path = candidate
                            break
                if path:
                    break
        path = path.split("?")[0] if path else ""

        findings = [
            str(f.get("kind") or "")
            for f in (rec.get("findings") or result.get("findings") or [])
            if isinstance(f, dict)
        ]
        findings = [kind for kind in findings if kind]
        independently_confirmed = any(kind in CONFIRMED_FINDINGS for kind in findings)

        session = "%s:%s:%s" % (rec.get("job", "audit"), rec.get("attempt", 0), target)
        tracker = TransitionTracker()
        if cl:
            tracker.add(session, "poison_sent", detail="framing observed in raw exchange")
        if len(responses) > 1 or rec.get("response_queued"):
            tracker.add(session, "response_queued", detail="cascade responses recorded")
        analysed: List[Any] = []
        for index, response in enumerate(responses):
            role = "poison" if index == 0 else "victim"
            shape = classify_response_shape(
                response, role=role, target_host=host, baseline=baseline
            )
            analysed.append(shape)
            tracker.add(
                session,
                "victim_response",
                response=response,
                role=role,
                target_host=host,
                baseline=baseline,
                detail="response[%d] %s" % (index, shape.shape.value),
            )
        confirmed = bool(independently_confirmed or tracker.has_confirmed())
        shapes = [item.shape for item in analysed]
        if confirmed:
            dominant = ResponseShape.QUEUE_SHIFTED_REDIRECT
        elif shapes:
            dominant = shapes[-1]
        else:
            dominant = ResponseShape.CLEAN_BASELINE

        features: Dict[str, str] = {
            "probe": str(rec.get("probe") or ""),
            "tls": str(rec.get("tls") or ""),
            "shape": dominant.value,
        }
        if cl:
            features[feature_key("cl", cl)] = "1"
        if path:
            features[feature_key("path", path)] = "1"
        for kind in findings:
            features[feature_key("finding", kind)] = "1"
        variant = str(learning.get("variant") or "")
        if variant:
            features[feature_key("variant", variant)] = "1"
        if mutation:
            features[feature_key("mutation", mutation)] = "1"
        if not confirmed:
            reasons: List[str] = []
            if cl in {1, 2, 3}:
                reasons.append("cl_too_short")
            if ResponseShape.PARSER_REJECT_STRICT in shapes:
                reasons.append("parser_reject")
            if ResponseShape.WAF_OR_DECEPTION in shapes:
                reasons.append("waf_or_deception")
            if ResponseShape.APP_ROUTE_MISS in shapes:
                reasons.append("route_miss")
            if reasons:
                features["negative_reason"] = "+".join(reasons)

        labels = [str(tag).lower().replace("_", "-") for tag in (rec.get("tags") or [])]
        example = TrainingExample(
            host=host,
            tech=tech,
            features=features,
            label=1.0 if confirmed else 0.0,
            source="online-audit",
        )
        enforce_negative_tags(example, labels)
        return {
            "host": host,
            "tech": tech,
            "cl": cl,
            "path": path,
            "dial_addr": dial_addr,
            "finding": next((k for k in findings if k in CONFIRMED_FINDINGS), ""),
            "confirmed": confirmed and example.label > 0.0,
            "shapes": [shape.value for shape in shapes],
            "features": features,
            "example": example,
            "identities": sorted(set(_identity(rec))),
            "response": responses[-1] if responses else {},
        }

    def process_record(self, rec: Dict[str, Any]) -> Dict[str, Any]:
        analysis = self._analyse(rec)
        example: TrainingExample = analysis["example"]
        weights = load_weights(self.weights_path)
        learner = ExperienceLearner(
            alpha=self.alpha if self.alpha is not None else float(weights.get("alpha", 0.3)),
            exact_weight=float(weights.get("exact_weight", 0.8)),
            min_exact_attempts=int(weights.get("min_exact_attempts", 2)),
        )
        rank_features = _ranking_features(example)
        before = learner.score(weights, rank_features, example.host, example.tech)
        result = apply_online_example(
            weights, example, alpha=self.alpha, weight=1.0
        )

        meta = weights.setdefault("online", {})
        if result.get("applied"):
            key = "%s|%s|%s" % (
                example.host, analysis["path"] or "*", analysis["cl"] or 0
            )
            if analysis["confirmed"] and analysis["identities"]:
                confirmation = meta.setdefault("confirmations", {}).setdefault(key, {})
                identities = sorted(set(confirmation.get("identities") or []) | set(analysis["identities"]))
                confirmation["identities"] = identities[-50:]
                confirmation["confirmed"] = True
                confirmation["last_seen"] = _now()
            if analysis["confirmed"]:
                self._add_hypothesis(weights, analysis, key, learner)
                # Re-evaluate verification even if the hypothesis already
                # existed: a second proxy identity can promote it to a strike.
                self._emit_jobs(weights)
        if result.get("applied") or result.get("reason") == "holdout-isolation":
            # A held-out event is counted but never folded into training cells;
            # persist that counter too so the dashboard sees the isolation.
            atomic_write_json(self.weights_path, weights)
        self.write_status(weights)
        return {
            "key": "%s:%s:%s" % (rec.get("job", ""), rec.get("attempt", 0), rec.get("time", "")),
            "applied": bool(result.get("applied")),
            "confirmed": analysis["confirmed"],
            "shapes": analysis["shapes"],
            "score_before": before,
            "score_after": result.get("score_after", before),
            "reason": result.get("reason", ""),
        }

    def _add_hypothesis(
        self,
        weights: Dict[str, Any],
        analysis: Dict[str, Any],
        key: str,
        learner: ExperienceLearner,
    ) -> None:
        host = analysis["host"]
        tech = analysis["tech"]
        path = analysis["path"]
        cl = int(analysis["cl"] or 0)
        observation = dict(analysis["response"] or {})
        observation["path"] = path or "/"
        observation["role"] = "victim"
        inferencer = ParameterInferencer(
            weights,
            target_host=host,
            tech_stack=[tech] if tech else [],
            exact_weight=float(weights.get("exact_weight", 0.8)),
        )
        inferred = inferencer.infer([observation], max_hypotheses=self.max_hypotheses)
        provenance = "confirmed-queue-shift"
        if inferred:
            path = inferred[0].get("smuggled_path") or path
            cl = int(inferred[0].get("smuggled_cl") or cl)
            provenance = "autonomous-inferred"
        if not path and not cl:
            return
        tls = str(analysis["features"].get("tls") or "h2")
        probe = "h2-cl" if tls == "h2" else "smuggle-chain"
        hypothesis = {
            "id": hashlib.sha256(("%s|%s|%s" % (host, path, cl)).encode("utf-8")).hexdigest()[:12],
            "key": key,
            "host": host,
            "path": path or "/",
            "cl": cl,
            "tls": tls,
            "probe": probe,
            "finding": analysis["finding"] or "h2_cl_confirmed",
            "dial_addr": analysis["dial_addr"],
            "provenance": provenance,
            "confirmed": True,
            "created_at": _now(),
        }
        meta = weights.setdefault("online", {})
        hypotheses = list(meta.setdefault("hypotheses", []))
        if any(item.get("id") == hypothesis["id"] for item in hypotheses):
            return
        hypotheses.insert(0, hypothesis)
        meta["hypotheses"] = hypotheses[:20]

    # --------------------------------------------------------------------- jobs

    def _emit_jobs(self, weights: Dict[str, Any]) -> Dict[str, Any]:
        meta = weights.get("online") or {}
        confirmations = meta.get("confirmations") or {}
        jobs: List[Dict[str, Any]] = []
        candidates: List[Dict[str, Any]] = []
        for hypothesis in meta.get("hypotheses") or []:
            confirmation = confirmations.get(hypothesis.get("key") or "") or {}
            identities = sorted(set(confirmation.get("identities") or []))
            cross_proxy = len(identities) >= MIN_CROSS_PROXY_IDENTITIES
            verified = bool(hypothesis.get("confirmed") and cross_proxy and hypothesis.get("dial_addr"))
            entry = {
                "schema": "omnislash.job-online/v1",
                "name": "online-" + str(hypothesis.get("id") or "unknown"),
                "provenance": hypothesis.get("provenance") or "unknown",
                "verified": verified,
                "strike": verified,
                "cross_proxy": {
                    "verified": cross_proxy,
                    "identities": identities,
                    "minimum": MIN_CROSS_PROXY_IDENTITIES,
                },
                "evidence": {
                    "host": hypothesis.get("host") or "*",
                    "path": hypothesis.get("path") or "/",
                    "cl": hypothesis.get("cl") or 0,
                    "provenance": hypothesis.get("provenance") or "unknown",
                },
                "patch": {
                    "name": "online-" + str(hypothesis.get("id") or "unknown"),
                    "enabled": True,
                    "target": {
                        "addr": hypothesis.get("dial_addr") or "",
                        "host": hypothesis.get("host") or "*",
                        "path": hypothesis.get("path") or "/",
                    },
                    "tls": hypothesis.get("tls") or "h2",
                    "probe": hypothesis.get("probe") or "h2-cl",
                    "declared_length": int(hypothesis.get("cl") or 0),
                    "smuggled_path": hypothesis.get("path") or "/",
                    "victim_path": hypothesis.get("path") or "/",
                    "success_finding": hypothesis.get("finding") or "h2_cl_confirmed",
                    "attempts": 1,
                    "interval": "30s",
                    "timeout": "5s",
                    "until_success": False,
                },
            }
            (jobs if verified else candidates).append(entry)
        previous = _read_json(self.jobs_path, {})
        seq = int(previous.get("seq") or 0) + 1 if isinstance(previous, dict) else 1
        payload = {
            "schema": JOBS_SCHEMA,
            "updated_at": _now(),
            "seq": seq,
            "jobs": jobs,
            "candidates": candidates,
        }
        digest = hashlib.sha256(
            json.dumps({"jobs": jobs, "candidates": candidates}, sort_keys=True).encode("utf-8")
        ).hexdigest()
        if digest != self._last_jobs_hash:
            atomic_write_json(self.jobs_path, payload)
            self._last_jobs_hash = digest
        return payload

    def write_status(self, weights: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        weights = weights if weights is not None else load_weights(self.weights_path)
        meta = weights.get("online") or {}
        jobs = _read_json(self.jobs_path, {}) if isinstance(_read_json(self.jobs_path, {}), dict) else {}
        status = {
            "schema": STATUS_SCHEMA,
            "state": "PAUSED" if self._paused else "ACTIVE",
            "active": not self._paused and not self.stop_event.is_set(),
            "available": True,
            "processed": int(meta.get("processed") or 0),
            "holdout_skipped": int(meta.get("holdout_skipped") or 0),
            "accuracy": float(meta.get("accuracy") or 0.5),
            "accuracy_delta": float(meta.get("accuracy_delta") or 0.0),
            "accuracy_history": list(meta.get("accuracy_history") or [])[-30:],
            "examples": int(weights.get("examples") or 0),
            "jobs": {
                "strike": len(jobs.get("jobs") or []),
                "candidates": len(jobs.get("candidates") or []),
            },
            "last_error": self._last_error,
            "updated_at": _now(),
        }
        atomic_write_json(self.status_path, status)
        return status

    # ---------------------------------------------------------------------- run

    def process_pending(self) -> int:
        lines, offset, stat = self.read_new_lines()
        processed = 0
        for line in lines:
            try:
                rec = json.loads(line)
                if not isinstance(rec, dict):
                    continue
                # Only completed attempts carry time + attempt. A partially
                # written record (or an operator note) is not a training event.
                if "time" not in rec or "attempt" not in rec:
                    continue
                key = "%s|%s|%s" % (rec.get("time"), rec.get("job", ""), rec.get("attempt"))
                if key in self._seen:
                    continue
                self._seen[key] = time.time()
                if len(self._seen) > _SEEN_LIMIT:
                    self._seen = dict(list(self._seen.items())[-_SEEN_LIMIT:])
                self.process_record(rec)
                processed += 1
                self._last_error = ""
            except Exception as exc:  # keep tailing; a bad line must not kill the loop
                self._last_error = "%s: %s" % (type(exc).__name__, exc)
        if stat is not None and offset:
            self._save_offset(offset, stat)
        return processed

    def run(self, *, once: bool = False) -> None:
        try:
            signal.signal(signal.SIGTERM, lambda *_: self.stop_event.set())
            signal.signal(signal.SIGINT, lambda *_: self.stop_event.set())
        except ValueError:  # only allowed from the main thread
            pass
        self._read_control()
        self.write_status()
        if once:
            self._read_control()
            if not self._paused:
                self.process_pending()
            self.write_status()
            return
        while not self.stop_event.is_set():
            was_paused = self._paused
            self._read_control()
            if was_paused != self._paused:
                # Publish state changes immediately; without a new attempt the
                # dashboard would otherwise see a stale ACTIVE/PAUSED status.
                self.write_status()
            if not self._paused:
                self.process_pending()
            deadline = time.monotonic() + self.interval
            while not self.stop_event.is_set() and time.monotonic() < deadline:
                time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
        self.write_status()


def main() -> None:  # pragma: no cover - CLI glue
    ap = argparse.ArgumentParser(description="Streaming online feedback loop for OmniSlash")
    ap.add_argument("--audit", required=True, help="daemon JSONL audit log to tail")
    ap.add_argument("--weights", default=DEFAULT_WEIGHTS_PATH)
    ap.add_argument("--jobs", default="state/jobs_online.json")
    ap.add_argument("--offset", default="state/online_loop_offset.json")
    ap.add_argument("--status", default="state/online_status.json")
    ap.add_argument("--control", default="state/online_loop_control.json")
    ap.add_argument("--interval", type=float, default=0.25)
    ap.add_argument("--alpha", type=float, default=None)
    ap.add_argument("--max-hypotheses", type=int, default=1)
    ap.add_argument("--once", action="store_true", help="process pending records and exit")
    args = ap.parse_args()

    loop = OnlineLoop(
        audit_path=args.audit,
        weights_path=args.weights,
        jobs_path=args.jobs,
        offset_path=args.offset,
        status_path=args.status,
        control_path=args.control,
        interval=args.interval,
        alpha=args.alpha,
        max_hypotheses=args.max_hypotheses,
    )
    loop.run(once=args.once)


if __name__ == "__main__":  # pragma: no cover
    main()
