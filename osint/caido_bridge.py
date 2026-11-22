#!/usr/bin/env python3
"""Bridge confirmed omnislashd findings into Caido Replay/notes.

Reads omnislashd JSONL audit, filters confirmed non-unverified findings, and
creates a Caido Replay/session note via GraphQL. Byte-exact probes still run
direct via Dialer/Session; this bridge only forwards metadata/raw request hints
for manual replay in Caido with the same exit proxy label.
"""

from __future__ import annotations

import argparse
import json
import os
import time
from typing import Any, Dict, Iterable, List, Set

from caido_client import CaidoClient


CONFIRMED_FINDINGS = {
    "smuggle_confirmed",
    "cache_poisoned",
    "h2_tunnel_confirmed",
    "race_confirmed",
    "desync_confirmed",
}


def load_jsonl(path: str) -> List[Dict[str, Any]]:
    items = []
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
                items.append(obj)
    return items


def is_unverified(record: Dict[str, Any], finding: Dict[str, Any]) -> bool:
    if record.get("unverified") is True:
        return True
    if finding.get("unverified") is True:
        return True
    # quarantine markers from filters
    filt = record.get("_omnislash_filter") or finding.get("_omnislash_filter") or {}
    if isinstance(filt, dict) and filt.get("verified") is False:
        return True
    return False


def confirmed_findings(record: Dict[str, Any]) -> List[Dict[str, Any]]:
    if not record.get("success"):
        return []
    out = []
    for f in record.get("findings") or []:
        if not isinstance(f, dict):
            continue
        kind = str(f.get("kind", ""))
        if kind not in CONFIRMED_FINDINGS:
            continue
        if is_unverified(record, f):
            continue
        out.append(f)
    return out


def finding_key(record: Dict[str, Any], finding: Dict[str, Any]) -> str:
    attr = record.get("attribution") or {}
    proxy = attr.get("proxy", "") if isinstance(attr, dict) else ""
    return "|".join([
        str(record.get("time", "")),
        str(record.get("job", "")),
        str(record.get("target", "")),
        str(finding.get("kind", "")),
        str(proxy),
    ])


def build_replay_payload(record: Dict[str, Any], finding: Dict[str, Any]) -> Dict[str, Any]:
    attr = record.get("attribution") or {}
    proxy = attr.get("proxy", "") if isinstance(attr, dict) else ""
    result = record.get("result") or {}
    responses = result.get("responses") or [] if isinstance(result, dict) else []
    raw_hint = ""
    if responses and isinstance(responses[0], dict):
        raw_hint = str(responses[0].get("raw", ""))[:4000]
    return {
        "title": f"omnislashd:{record.get('job','')}:{finding.get('kind','')}",
        "target": record.get("target"),
        "proxy_label": proxy,
        "proxy_pin_header": "X-Omnislash-Proxy",
        "finding": finding,
        "record": {
            "time": record.get("time"),
            "job": record.get("job"),
            "probe": record.get("probe"),
            "tls": record.get("tls"),
            "success": record.get("success"),
            "statuses": record.get("statuses", []),
        },
        "raw_response_hint": raw_hint,
        "note": "Replay via Caido with same exit IP by setting gateway.proxy_pin_header to proxy_label.",
    }


def send_to_caido(client: CaidoClient, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Best-effort: create a replay session or store note. Schema varies by Caido version."""
    # Try replay session creation; fallback to generic note mutation/query.
    mutations = [
        (
            """
            mutation CreateReplay($name: String!, $host: String!, $path: String!) {
              createReplaySession(input: {name: $name, host: $host, path: $path}) {
                session { id name }
              }
            }
            """,
            {"name": payload["title"], "host": str(payload.get("target", "")), "path": "/"},
        ),
        (
            """
            mutation($input: CreateReplaySessionInput!) {
              createReplaySession(input: $input) { id }
            }
            """,
            {"input": {"name": payload["title"]}},
        ),
    ]
    last_err = None
    for q, vars in mutations:
        try:
            return {"ok": True, "data": client.graphql(q, vars), "payload": payload}
        except Exception as e:
            last_err = str(e)
    # Fallback: return payload for manual import / UI note.
    return {"ok": False, "error": last_err, "payload": payload}


def process_records(records: Iterable[Dict[str, Any]], client: CaidoClient, seen: Set[str] = None) -> List[Dict[str, Any]]:
    seen = seen if seen is not None else set()
    out = []
    for rec in records:
        for finding in confirmed_findings(rec):
            key = finding_key(rec, finding)
            if key in seen:
                continue
            seen.add(key)
            payload = build_replay_payload(rec, finding)
            out.append(send_to_caido(client, payload))
    return out


def watch_file(path: str, client: CaidoClient, interval: float = 2.0, once: bool = False) -> List[Dict[str, Any]]:
    seen: Set[str] = set()
    offset = 0
    results: List[Dict[str, Any]] = []
    while True:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(offset)
                chunk = f.read()
                offset = f.tell()
        except FileNotFoundError:
            chunk = ""
        if chunk.strip():
            lines = [l for l in chunk.splitlines() if l.strip()]
            recs = []
            for line in lines:
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        recs.append(obj)
                except Exception:
                    pass
            results.extend(process_records(recs, client, seen))
        if once:
            break
        time.sleep(interval)
    return results


def main(argv=None):
    ap = argparse.ArgumentParser(description="Bridge omnislashd confirmed findings to Caido Replay")
    ap.add_argument("--audit", required=True, help="omnislashd JSONL audit file")
    ap.add_argument("--url", default=os.environ.get("CAIDO_URL", "http://127.0.0.1:8080/graphql"))
    ap.add_argument("--pat", default=os.environ.get("CAIDO_PAT", ""))
    ap.add_argument("--watch", action="store_true")
    ap.add_argument("--interval", type=float, default=2.0)
    ap.add_argument("--out", default="", help="optional output JSON report")
    args = ap.parse_args(argv)

    client = CaidoClient(url=args.url, pat=args.pat)
    results = watch_file(args.audit, client, interval=args.interval, once=not args.watch)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
            f.write("\n")
    print(json.dumps({"processed": len(results), "ok": sum(1 for r in results if r.get("ok"))}, ensure_ascii=False))


if __name__ == "__main__":
    main()