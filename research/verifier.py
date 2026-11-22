#!/usr/bin/env python3
"""Cross-proxy verifier for OmniSlash Echelon 1.

A candidate is verified only after 2 independent confirmations from different
proxy/exit identities and no deception/unverified flags.
"""

from __future__ import annotations

import argparse
import json
from typing import Any, Dict, List, Tuple


def _proxy_id(record: Dict[str, Any]) -> str:
    attr = record.get("attribution") or {}
    if isinstance(attr, dict):
        for k in ("proxy", "exit_ip", "proxy_label"):
            v = attr.get(k)
            if v:
                return str(v)
    return str(record.get("proxy_label") or record.get("exit_ip") or "")


def _is_deceptive(record: Dict[str, Any]) -> bool:
    if record.get("unverified") is True:
        return True
    if record.get("deception_flagged") is True:
        return True
    for f in record.get("findings") or []:
        if isinstance(f, dict) and (f.get("unverified") is True or f.get("deception_flagged") is True):
            return True
    filt = record.get("_omnislash_filter") or {}
    if isinstance(filt, dict) and filt.get("verified") is False:
        return True
    return False


def finding_fingerprint(record: Dict[str, Any], finding: Dict[str, Any]) -> str:
    return "|".join([
        str(record.get("target", "")),
        str(record.get("job", "")),
        str(finding.get("kind", "")),
        str(finding.get("detail", ""))[:200],
    ])


def verify_candidates(records: List[Dict[str, Any]], min_verifications: int = 2) -> List[Dict[str, Any]]:
    """Return verified findings with confidence_score.

    min_verifications counts distinct proxy identities confirming the same finding.
    """
    groups: Dict[str, Dict[str, Any]] = {}
    for rec in records:
        if not isinstance(rec, dict) or not rec.get("success"):
            continue
        if _is_deceptive(rec):
            continue
        pid = _proxy_id(rec)
        for f in rec.get("findings") or []:
            if not isinstance(f, dict):
                continue
            if f.get("unverified") is True or f.get("deception_flagged") is True:
                continue
            kind = str(f.get("kind", ""))
            if not kind or kind.endswith("_unconfirmed"):
                continue
            fp = finding_fingerprint(rec, f)
            g = groups.setdefault(fp, {
                "kind": kind,
                "target": rec.get("target"),
                "host": (rec.get("target") or "").split(":")[0],
                "path": f.get("path", "/"),
                "detail": f.get("detail", ""),
                "proxy_ids": set(),
                "records": 0,
                "confidence_base": 50,
            })
            if pid:
                g["proxy_ids"].add(pid)
            else:
                g["proxy_ids"].add(f"anon-{g['records']}")
            g["records"] += 1

    verified: List[Dict[str, Any]] = []
    for fp, g in groups.items():
        ver = len(g["proxy_ids"])
        if ver < min_verifications:
            continue
        # Confidence scoring: base + verifications + kind bonus, capped at 100.
        kind_bonus = 20 if "confirmed" in g["kind"] else 10
        score = min(100, g["confidence_base"] + ver * 15 + kind_bonus)
        verified.append({
            "fingerprint": fp,
            "kind": g["kind"],
            "target": g["target"],
            "host": g["host"],
            "path": g["path"],
            "detail": g["detail"],
            "cross_proxy_verifications": ver,
            "confidence_score": score,
            "proxy_label": ",".join(sorted(g["proxy_ids"])[:3]),
            "unverified": False,
        })
    verified.sort(key=lambda x: x["confidence_score"], reverse=True)
    return verified


def main() -> None:
    ap = argparse.ArgumentParser(description="Verify OmniSlash findings across proxies")
    ap.add_argument("--in", dest="inp", required=True, help="JSONL audit or JSON list")
    ap.add_argument("--out", required=True)
    ap.add_argument("--min-verifications", type=int, default=2)
    args = ap.parse_args()

    records: List[Dict[str, Any]] = []
    with open(args.inp, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    try:
        obj = json.loads(text)
        if isinstance(obj, list):
            records = [x for x in obj if isinstance(x, dict)]
        elif isinstance(obj, dict):
            records = [obj]
    except Exception:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except Exception:
                pass

    verified = verify_candidates(records, min_verifications=args.min_verifications)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(verified, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(json.dumps({"verified": len(verified)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
