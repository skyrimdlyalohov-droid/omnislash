#!/usr/bin/env python3
"""Global projector for Echelon 2.

Takes a Universal Key tech_stack_hash, finds matching targets in local cache
(and emits Shodan/Censys query hints), generates fan-out jobs, and optionally
runs verification/notification pipeline.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from typing import Any, Dict, List

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from research.knowledge_base import DEFAULT_VAULT_PATH, find_keys_for_stack, load_vault, tech_stack_hash  # noqa: E402
from research.meta_controller import WaldSPRT, compute_gittins_index  # noqa: E402
from osint.planner import build_daemon_config, load_targets  # noqa: E402


def shodan_query(tech_stack: List[str]) -> str:
    parts = []
    for t in tech_stack:
        t = t.strip().lower()
        if not t:
            continue
        if t in {"nginx", "envoy", "haproxy", "apache"}:
            parts.append(f'product:"{t}"')
        else:
            parts.append(f'"{t}"')
    return " ".join(parts)


def censys_query(tech_stack: List[str]) -> str:
    parts = []
    for t in tech_stack:
        t = t.strip().lower()
        if not t:
            continue
        parts.append(f'services.software.product="{t}"')
    return " and ".join(parts) if parts else ""


def match_targets(targets: List[Dict[str, Any]], wanted_sig: str) -> List[Dict[str, Any]]:
    wanted = set([x for x in wanted_sig.lower().split("+") if x])
    out = []
    for t in targets:
        tech = [str(x).lower() for x in (t.get("tech") or [])]
        tech += [str(t.get("webserver", "")).lower()] if t.get("webserver") else []
        tech += [str(t.get("cdn_name", "")).lower()] if t.get("cdn_name") else []
        techset = set([x for x in tech if x])
        if wanted and wanted.issubset(techset):
            out.append(t)
    return out


def rank_by_gittins(targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    ranked = []
    for t in targets:
        conf = float(t.get("confidence_score", 0) or 0)
        reward = max(1.0, conf + 10.0)
        # initial prior: unknown success/failure
        idx = compute_gittins_index(successes=1, failures=1, reward=reward, cost=1.0)
        item = dict(t)
        item["gittins_index"] = idx
        ranked.append(item)
    ranked.sort(key=lambda x: x["gittins_index"], reverse=True)
    return ranked


def main() -> None:
    ap = argparse.ArgumentParser(description="Project Universal Key across matching targets")
    ap.add_argument("--tech", required=True, help="tech_stack_hash, e.g. nginx+python+h1.1")
    ap.add_argument("--vault", default=DEFAULT_VAULT_PATH)
    ap.add_argument("--targets", default="", help="Local targets_verified.json cache")
    ap.add_argument("--out-dir", default="")
    ap.add_argument("--omnislash-config", default="config.example.json")
    ap.add_argument("--run", action="store_true", help="Run omnislashd -once")
    ap.add_argument("--skip-notify", action="store_true")
    ap.add_argument("--caido-url", default=os.environ.get("CAIDO_URL", ""))
    ap.add_argument("--caido-pat", default=os.environ.get("CAIDO_PAT", ""))
    args = ap.parse_args()

    wanted_sig = args.tech.strip().lower()
    tech_stack = [x for x in wanted_sig.split("+") if x]
    vault = load_vault(args.vault)
    keys = find_keys_for_stack(vault, tech_stack)
    if not keys:
        print(json.dumps({"error": "no universal key for tech", "tech": wanted_sig, "shodan_query": shodan_query(tech_stack), "censys_query": censys_query(tech_stack)}))
        raise SystemExit(1)

    targets = load_targets(args.targets) if args.targets else []
    matched = match_targets(targets, wanted_sig)
    matched = rank_by_gittins(matched)

    out_dir = args.out_dir or os.path.join("runs", f"project_{wanted_sig.replace('+','_')}")
    os.makedirs(out_dir, exist_ok=True)

    # Build jobs from matched targets using vault (planner will inject universal key)
    daemon_cfg = build_daemon_config(matched, omnislash_config=args.omnislash_config, log_file=os.path.join(out_dir, "omnislashd-audit.jsonl"), vault=vault)
    # Limit attempts per host (3-5 requests) via Wald SPRT budget metadata
    for j in daemon_cfg.get("jobs", []):
        j["attempts"] = min(int(j.get("attempts", 3) or 3), 5)
        j.setdefault("metadata", {})["wald_sprt"] = {"p0": 0.05, "p1": 0.8, "alpha": 0.01, "beta": 0.01, "max_requests": 5}
    jobs_path = os.path.join(out_dir, "jobs.json")
    with open(jobs_path, "w", encoding="utf-8") as f:
        json.dump(daemon_cfg, f, indent=2, ensure_ascii=False)
        f.write("\n")

    summary = {
        "tech_stack_hash": wanted_sig,
        "shodan_query": shodan_query(tech_stack),
        "censys_query": censys_query(tech_stack),
        "keys_found": len(keys),
        "targets_matched": len(matched),
        "jobs": len(daemon_cfg.get("jobs", [])),
        "out_dir": out_dir,
    }

    if args.run and daemon_cfg.get("jobs"):
        bin_path = os.path.join(REPO_ROOT, "bin", "omnislashd")
        if not os.path.exists(bin_path):
            subprocess.run(["go", "build", "-trimpath", "-o", bin_path, "./cmd/omnislashd"], cwd=REPO_ROOT, check=False)
        subprocess.run([bin_path, "-config", jobs_path, "-once"], cwd=REPO_ROOT, check=False)
        # Verify and notify
        audit_path = os.path.join(out_dir, "omnislashd-audit.jsonl")
        verified_path = os.path.join(out_dir, "verified.json")
        if os.path.exists(audit_path):
            subprocess.run([sys.executable, os.path.join(REPO_ROOT, "research", "verifier.py"), "--in", audit_path, "--out", verified_path, "--min-verifications", "2"], cwd=REPO_ROOT, check=False)
            if not args.skip_notify and os.path.exists(verified_path):
                env = os.environ.copy()
                if args.caido_url:
                    env["CAIDO_URL"] = args.caido_url
                if args.caido_pat:
                    env["CAIDO_PAT"] = args.caido_pat
                subprocess.run([sys.executable, os.path.join(REPO_ROOT, "osint", "notifier.py"), "--in", verified_path, "--out", os.path.join(out_dir, "notify.json"), "--min-confidence", "85"], cwd=REPO_ROOT, env=env, check=False)
        summary["verified_path"] = verified_path

    with open(os.path.join(out_dir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    main()
