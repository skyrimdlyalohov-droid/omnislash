#!/usr/bin/env python3
"""Generate omnislashd jobs from targets_verified.json.

Defensive planning only: drops honeypot/high deception-risk targets, keeps
scope fail-closed, and carries baseline metadata for runtime deception checks.
"""

from __future__ import annotations

import argparse
import json
import os
from typing import Any, Dict, List


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


def _target_addr(target: Dict[str, Any]) -> str:
    host = str(target.get("target") or target.get("host") or "").strip()
    port = 443
    ports = target.get("known_ports") or []
    if isinstance(ports, list) and 443 in ports:
        port = 443
    elif isinstance(ports, list) and 80 in ports:
        port = 80
    return f"{host}:{port}"


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


def plan_target(target: Dict[str, Any], critical_endpoints: List[str] = None) -> List[Dict[str, Any]]:
    critical_endpoints = list(critical_endpoints or target.get("critical_endpoints") or [])
    if is_excluded(target):
        return []
    host = str(target.get("target") or target.get("host") or "").strip()
    if not host:
        return []
    jobs: List[Dict[str, Any]] = []
    tech = _norm_tech(target)
    tech_l = " ".join(tech).lower()

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

    # If nothing matched but target is clean and web, add conservative smuggle-chain only for reverse proxies? no - avoid noise.
    # Keep fail-closed: no jobs if no clear signal.
    return jobs


def build_daemon_config(targets: List[Dict[str, Any]], omnislash_config: str = "config.json", log_file: str = "omnislashd-audit.jsonl") -> Dict[str, Any]:
    jobs: List[Dict[str, Any]] = []
    allow_hosts: List[str] = []
    seen_hosts = set()
    for t in targets:
        if is_excluded(t):
            continue
        host = str(t.get("target") or t.get("host") or "").strip()
        if not host:
            continue
        t_jobs = plan_target(t, t.get("critical_endpoints") or [])
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
    return {
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


def main(argv=None):
    ap = argparse.ArgumentParser(description="Generate omnislashd jobs.json from targets_verified.json")
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--omnislash-config", default="config.json")
    ap.add_argument("--log-file", default="omnislashd-audit.jsonl")
    ap.add_argument("--only-diff", action="store_true", help="Only plan targets marked as new/changed (_diff) or from diff scanner output")
    ap.add_argument("--previous", default="", help="Optional previous targets_verified.json for internal diff when --only-diff is set")
    args = ap.parse_args(argv)

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
    cfg = build_daemon_config(targets, omnislash_config=args.omnislash_config, log_file=args.log_file)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(json.dumps({"jobs": len(cfg["jobs"]), "allow_hosts": cfg["generated_scope"]["allow_hosts"], "only_diff": bool(args.only_diff)}, ensure_ascii=False))


if __name__ == "__main__":
    main()