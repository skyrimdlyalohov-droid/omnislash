#!/usr/bin/env python3
"""Filter Nuclei JSONL results through defensive deception/soft-404 heuristics.

This is NOT an evasion tool. It removes likely synthetic/tarpit/soft-404 noise
before reporting.

Usage:
  nuclei ... -jsonl -o raw.jsonl
  python3 osint/filter_nuclei.py --in raw.jsonl --out clean.jsonl --report report.json
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, List


SUSPICIOUS_BODY_RE = re.compile(
    r"(?i)(canarytoken|oastify|interact\.sh|burpcollaborator|webhook\.site|honeypot|tarpit|fake admin|dummy admin)"
)
SUSPICIOUS_TITLE_RE = re.compile(r"(?i)(honeypot|canary|tarpit|deception)")


def load_jsonl(path: str) -> List[Dict[str, Any]]:
    items = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except Exception:
                continue
    return items


def write_jsonl(path: str, items: Iterable[Dict[str, Any]]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for item in items:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")


def _sig(item: Dict[str, Any]) -> str:
    info = item.get("info", {}) if isinstance(item.get("info"), dict) else {}
    return "|".join([
        str(item.get("host", "")),
        str(item.get("status", "")),
        str(info.get("name", "")),
        str(item.get("matched-at", "")),
    ])


def filter_findings(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    # Count repeated same host+status+template signatures - common soft-404/tarpit pattern.
    counts = Counter()
    for it in items:
        info = it.get("info", {}) if isinstance(it.get("info"), dict) else {}
        counts[(str(it.get("host", "")), str(it.get("status", "")), str(info.get("name", "")))] += 1

    clean = []
    quarantined = []
    for it in items:
        info = it.get("info", {}) if isinstance(it.get("info"), dict) else {}
        host = str(it.get("host", ""))
        status = str(it.get("status", ""))
        name = str(info.get("name", ""))
        matched = str(it.get("matched-at", ""))
        body = str(it.get("response", "")) or str(it.get("extracted-results", ""))
        reason = None

        if SUSPICIOUS_BODY_RE.search(body) or SUSPICIOUS_TITLE_RE.search(name):
            reason = "suspicious_deception_marker"
        elif counts[(host, status, name)] >= 5 and status == "200":
            reason = "repeated_soft_404_pattern"
        elif status == "200" and "nonexistent" in matched.lower():
            reason = "synthetic_nonexistent_200"

        if reason:
            q = dict(it)
            q["_omnislash_filter"] = {"quarantined": True, "verified": False, "reason": reason}
            quarantined.append(q)
        else:
            clean.append(it)

    return {
        "total": len(items),
        "clean": clean,
        "quarantined": quarantined,
        "summary": {
            "clean_count": len(clean),
            "quarantined_count": len(quarantined),
            "reasons": dict(Counter(q["_omnislash_filter"]["reason"] for q in quarantined)),
        },
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="Filter Nuclei JSONL for deception/soft-404")
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--report", default="")
    args = ap.parse_args(argv)

    items = load_jsonl(args.inp)
    result = filter_findings(items)
    write_jsonl(args.out, result["clean"])
    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            json.dump(result["summary"] | {"quarantined": result["quarantined"]}, f, indent=2, ensure_ascii=False)
            f.write("\n")
    print(json.dumps(result["summary"], ensure_ascii=False))


if __name__ == "__main__":
    main()