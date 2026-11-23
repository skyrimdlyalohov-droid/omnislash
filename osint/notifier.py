#!/usr/bin/env python3
"""OmniSlash notifier: Telegram + Caido Replay push.

Env:
  OMNI_TG_TOKEN   - Telegram bot token
  OMNI_TG_CHAT_ID - Telegram chat id
  CAIDO_URL       - Caido GraphQL URL
  CAIDO_PAT       - Caido PAT
"""

from __future__ import annotations

import argparse
import json
import os
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

from caido_client import CaidoClient
try:
    from caido_bridge import attach_adaptive_artifact, load_adaptive_artifacts
except Exception:  # pragma: no cover - optional adaptive handoff
    def load_adaptive_artifacts(path): return {}
    def attach_adaptive_artifact(record, finding, artifacts): return finding


def send_telegram(token: str, chat_id: str, text: str, timeout: int = 15) -> Dict[str, Any]:
    if not token or not chat_id:
        return {"ok": False, "error": "missing OMNI_TG_TOKEN/OMNI_TG_CHAT_ID"}
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = urllib.parse.urlencode({
        "chat_id": chat_id,
        "text": text[:4000],
        "disable_web_page_preview": "true",
    }).encode("utf-8")
    req = urllib.request.Request(url, data=payload, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
        return {"ok": True, "response": json.loads(body)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def push_caido_replay(client: CaidoClient, finding: Dict[str, Any]) -> Dict[str, Any]:
    title = finding.get("title") or f"omnislash:{finding.get('kind','finding')}"
    host = str(finding.get("host") or finding.get("target") or "")
    path = str(finding.get("path") or "/")
    payload = {
        "title": title,
        "host": host,
        "path": path,
        "proxy_pin_header": "X-Omnislash-Proxy",
        "proxy_label": finding.get("proxy_label", ""),
        "confidence_score": finding.get("confidence_score"),
        "minimal_artifact": finding.get("minimal_artifact"),
    }
    mutations = [
        (
            """
            mutation CreateReplay($name: String!, $host: String!, $path: String!) {
              createReplaySession(input: {name: $name, host: $host, path: $path}) {
                session { id name }
              }
            }
            """,
            {"name": title, "host": host, "path": path},
        ),
    ]
    last_err = None
    for q, vars in mutations:
        try:
            data = client.graphql(q, vars)
            return {"ok": True, "data": data, "payload": payload}
        except Exception as e:
            last_err = str(e)
    return {"ok": False, "error": last_err or "unknown", "payload": payload}


def should_alert(finding: Dict[str, Any], min_confidence: int = 85, min_verifications: int = 2) -> bool:
    score = finding.get("confidence_score", 0)
    try:
        score = float(score)
    except Exception:
        score = 0
    ver = finding.get("cross_proxy_verifications", finding.get("verifications", 0))
    try:
        ver = int(ver)
    except Exception:
        ver = 0
    if finding.get("unverified") is True:
        return False
    return score >= min_confidence and ver >= min_verifications


def format_alert(finding: Dict[str, Any]) -> str:
    text = (
        "🚨 OmniSlash verified finding\n"
        f"Kind: {finding.get('kind','')}\n"
        f"Target: {finding.get('target') or finding.get('host','')}\n"
        f"Path: {finding.get('path','/')}\n"
        f"Confidence: {finding.get('confidence_score','')}\n"
        f"Verifications: {finding.get('cross_proxy_verifications', finding.get('verifications',''))}\n"
        f"Proxy: {finding.get('proxy_label','')}\n"
        f"Detail: {str(finding.get('detail',''))[:500]}"
    )
    artifact = finding.get("minimal_artifact") or {}
    if isinstance(artifact, dict) and artifact.get("checksum_sha256"):
        req = artifact.get("request") or {}
        text += (
            "\nMinimal artifact: "
            f"{str(artifact.get('checksum_sha256'))[:16]} "
            f"({req.get('body_len', 0)}B body, {len(req.get('headers') or [])} headers)"
        )
    return text


def notify_finding(finding: Dict[str, Any], min_confidence: int = 85) -> Dict[str, Any]:
    result = {"finding": finding.get("kind"), "alerted": False}
    if not should_alert(finding, min_confidence=min_confidence):
        result["skipped"] = "threshold_not_met"
        return result
    token = os.environ.get("OMNI_TG_TOKEN", "")
    chat_id = os.environ.get("OMNI_TG_CHAT_ID", "")
    text = format_alert(finding)
    tg = send_telegram(token, chat_id, text)
    result["telegram"] = tg

    caido_url = os.environ.get("CAIDO_URL", "")
    caido_pat = os.environ.get("CAIDO_PAT", "")
    if caido_url and caido_pat:
        client = CaidoClient(url=caido_url, pat=caido_pat)
        result["caido"] = push_caido_replay(client, finding)
    else:
        result["caido"] = {"ok": False, "error": "missing CAIDO_URL/CAIDO_PAT"}
    result["alerted"] = bool(tg.get("ok") or result.get("caido", {}).get("ok"))
    return result


def main() -> None:
    ap = argparse.ArgumentParser(description="Send OmniSlash alerts for verified findings")
    ap.add_argument("--in", dest="inp", required=True, help="JSON file with findings list or object")
    ap.add_argument("--out", default="")
    ap.add_argument("--min-confidence", type=int, default=85)
    ap.add_argument("--adaptive-artifacts", default="", help="Minimal artifacts from GroupTestSplitter/ddmin")
    args = ap.parse_args()
    with open(args.inp, "r", encoding="utf-8") as f:
        obj = json.load(f)
    findings = obj if isinstance(obj, list) else obj.get("findings", []) if isinstance(obj, dict) else []
    artifacts = load_adaptive_artifacts(args.adaptive_artifacts)
    results = [
        notify_finding(attach_adaptive_artifact({"target": str(f.get("target") or "")}, f, artifacts), min_confidence=args.min_confidence)
        for f in findings
        if isinstance(f, dict)
    ]
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
            f.write("\n")
    print(json.dumps({"count": len(results), "alerted": sum(1 for r in results if r.get('alerted'))}, ensure_ascii=False))


if __name__ == "__main__":
    main()
