#!/usr/bin/env python3
"""Diff scanner for OmniSlash radar.

Compares current targets_verified.json against previous state and emits only
fresh or changed targets for --only-diff planning.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from typing import Any, Dict, List, Tuple


def load_targets(path: str) -> List[Dict[str, Any]]:
    if not path or not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        obj = json.load(f)
    if isinstance(obj, list):
        return [x for x in obj if isinstance(x, dict)]
    if isinstance(obj, dict):
        if isinstance(obj.get("targets"), list):
            return [x for x in obj["targets"] if isinstance(x, dict)]
        return [obj]
    return []


def target_key(t: Dict[str, Any]) -> str:
    host = str(t.get("target") or t.get("host") or t.get("ip") or "").strip().lower()
    ip = str(t.get("ip") or "").strip().lower()
    return f"{host}|{ip}"


def fingerprint(t: Dict[str, Any]) -> str:
    # Fingerprint meaningful change fields; ignore volatile timestamps.
    keys = [
        "target", "ip", "is_honeypot", "deception_risk", "recommended_profile",
        "known_ports", "tech", "cdn_name", "webserver", "cache_headers",
        "baseline", "origin_ips", "behind_waf", "auth_context",
    ]
    norm = {}
    for k in keys:
        v = t.get(k)
        if isinstance(v, list):
            v = sorted([str(x) for x in v])
        elif isinstance(v, dict):
            v = {str(kk): v[kk] for kk in sorted(v.keys())}
        norm[k] = v
    blob = json.dumps(norm, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def diff_targets(current: List[Dict[str, Any]], previous: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    prev_map = {target_key(t): fingerprint(t) for t in previous}
    fresh: List[Dict[str, Any]] = []
    stats = {"current": len(current), "previous": len(previous), "new": 0, "changed": 0, "unchanged": 0}
    for t in current:
        k = target_key(t)
        fp = fingerprint(t)
        if k not in prev_map:
            stats["new"] += 1
            item = dict(t)
            item["_diff"] = "new"
            fresh.append(item)
        elif prev_map[k] != fp:
            stats["changed"] += 1
            item = dict(t)
            item["_diff"] = "changed"
            fresh.append(item)
        else:
            stats["unchanged"] += 1
    return fresh, stats


def main() -> None:
    ap = argparse.ArgumentParser(description="Diff targets_verified.json for OmniSlash radar")
    ap.add_argument("--current", required=True)
    ap.add_argument("--previous", default="")
    ap.add_argument("--out", required=True)
    ap.add_argument("--stats-out", default="")
    args = ap.parse_args()

    current = load_targets(args.current)
    previous = load_targets(args.previous) if args.previous else []
    fresh, stats = diff_targets(current, previous)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(fresh, f, indent=2, ensure_ascii=False)
        f.write("\n")
    if args.stats_out:
        with open(args.stats_out, "w", encoding="utf-8") as f:
            json.dump(stats, f, indent=2, ensure_ascii=False)
            f.write("\n")
    print(json.dumps(stats, ensure_ascii=False))


if __name__ == "__main__":
    main()
