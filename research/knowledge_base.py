#!/usr/bin/env python3
"""Knowledge base for Universal Keys discovered in local incubator.

Stores confirmed byte patterns keyed by tech_stack_hash in state/zero_day_vault.json.
Stdlib only.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Any, Dict, List, Optional


DEFAULT_VAULT_PATH = os.path.join("state", "zero_day_vault.json")


def normalize_tech_stack(stack: List[str]) -> List[str]:
    out = []
    for s in stack or []:
        s = str(s).strip().lower()
        if not s:
            continue
        # normalize common names
        aliases = {
            "nginx/": "nginx",
            "envoy proxy": "envoy",
            "gunicorn/": "gunicorn",
            "python": "python",
            "node.js": "node",
            "nodejs": "node",
            "haproxy": "haproxy",
            "h2": "h2",
            "http2": "h2",
            "http/2": "h2",
            "h1.1": "h1.1",
            "http/1.1": "h1.1",
        }
        for k, v in aliases.items():
            if s == k or s.startswith(k):
                s = v
                break
        out.append(s)
    # dedupe preserve stable order
    seen = set()
    deduped = []
    for s in out:
        if s in seen:
            continue
        seen.add(s)
        deduped.append(s)
    return deduped


def tech_stack_hash(stack: List[str]) -> str:
    norm = normalize_tech_stack(stack)
    if not norm:
        return "unknown"
    # human-readable signature as spec examples: envoy+gunicorn, nginx+h2
    return "+".join(norm)


def tech_stack_digest(stack: List[str]) -> str:
    sig = tech_stack_hash(stack)
    return hashlib.sha256(sig.encode("utf-8")).hexdigest()[:16]


def load_vault(path: str = DEFAULT_VAULT_PATH) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {"version": 1, "keys": []}
    with open(path, "r", encoding="utf-8") as f:
        obj = json.load(f)
    if not isinstance(obj, dict):
        return {"version": 1, "keys": []}
    obj.setdefault("version", 1)
    obj.setdefault("keys", [])
    if not isinstance(obj["keys"], list):
        obj["keys"] = []
    return obj


def save_vault(vault: Dict[str, Any], path: str = DEFAULT_VAULT_PATH) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(vault, f, indent=2, ensure_ascii=False)
        f.write("\n")


def add_universal_key(
    vault: Dict[str, Any],
    raw_payload: bytes,
    mutation_type: str,
    protocol_edge: str,
    tech_stack: List[str],
    source: str = "incubator",
    confidence: float = 1.0,
    metadata: Optional[Dict[str, Any]] = None,
    technique: str = "raw-replay",
    tls: Optional[str] = None,
    job_overrides: Optional[Dict[str, Any]] = None,
    provenance: Optional[str] = None,
    evidence: Optional[List[Dict[str, Any]]] = None,
    signals: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    sig = tech_stack_hash(tech_stack)
    fingerprint = "|".join([
        sig,
        technique,
        mutation_type,
        protocol_edge,
        base64.b64encode(raw_payload).decode(),
        json.dumps(job_overrides or {}, sort_keys=True),
    ])
    entry = {
        "id": hashlib.sha256(fingerprint.encode()).hexdigest()[:16],
        "tech_stack_hash": sig,
        "tech_stack_digest": tech_stack_digest(tech_stack),
        "tech_stack": normalize_tech_stack(tech_stack),
        "raw_payload_b64": base64.b64encode(raw_payload).decode("ascii"),
        "mutation_type": mutation_type,
        "protocol_edge": protocol_edge,
        "technique": technique,
        "tls": tls or "",
        "job_overrides": job_overrides or {},
        "source": source,
        "provenance": provenance or source,
        "evidence": evidence or [],
        "signals": signals or [],
        "confidence": float(confidence),
        "metadata": metadata or {},
    }
    keys = vault.setdefault("keys", [])
    # dedupe by id
    keys[:] = [k for k in keys if k.get("id") != entry["id"]]
    keys.append(entry)
    return entry


def import_playbook(
    vault: Dict[str, Any],
    case: Dict[str, Any],
    template: str = "verify",
) -> Dict[str, Any]:
    """Turn a structured playbook case into a vault entry.

    The case keeps the byte pattern and its provenance in one tracked file; the
    vault entry is what the planner can project onto authorized targets. This
    is a curated replay source, not autonomous discovery: ``provenance`` and
    ``autonomous_discovery`` are carried into the entry verbatim.
    """
    if not isinstance(case, dict):
        raise ValueError("playbook case must be a JSON object")
    if case.get("schema") != "omnislash.playbook/v1":
        raise ValueError("unsupported playbook schema")
    case_id = str(case.get("id") or "").strip()
    if not case_id:
        raise ValueError("playbook case requires an id")
    templates = case.get("job_templates") or {}
    if template not in templates:
        raise ValueError("playbook has no %r job template" % template)
    job = templates[template]
    if not isinstance(job, dict) or not str(job.get("body") or ""):
        raise ValueError("job template requires a body byte pattern")
    applies = case.get("applies_to") or {}
    provenance = case.get("provenance") or {}
    signals = list(case.get("response_signals") or []) + list(case.get("negative_signals") or [])
    metadata = {
        "case_id": case_id,
        "case_schema": case.get("schema"),
        "template": template,
        "provenance_kind": provenance.get("kind", "unspecified"),
        "autonomous_discovery": bool(provenance.get("autonomous_discovery", False)),
        "source_url": provenance.get("source_url", ""),
        "disclosure": provenance.get("disclosure", ""),
        "validated_parameters": case.get("validated_parameters") or {},
        "success_contains": job.get("success_contains", ""),
        "success_finding": job.get("success_finding", ""),
        "external_verification": template == "solve",
    }
    return add_universal_key(
        vault,
        raw_payload=str(job["body"]).encode("utf-8"),
        mutation_type="playbook:" + case_id,
        protocol_edge=str(applies.get("protocol_edge") or ""),
        tech_stack=list(applies.get("tech_stack") or []),
        source="playbook:" + case_id,
        confidence=float((case.get("learning") or {}).get("confidence", 0.8)),
        metadata=metadata,
        technique=str(applies.get("probe") or "raw-replay"),
        tls=applies.get("tls"),
        job_overrides=job,
        provenance=provenance.get("kind", "unspecified"),
        evidence=list(case.get("evidence") or []),
        signals=signals,
    )


def find_keys_for_stack(vault: Dict[str, Any], tech_stack: List[str]) -> List[Dict[str, Any]]:
    sig = tech_stack_hash(tech_stack)
    norm = set(normalize_tech_stack(tech_stack))
    matches = []
    for k in vault.get("keys", []):
        ksig = str(k.get("tech_stack_hash", ""))
        kstack = set(normalize_tech_stack(k.get("tech_stack", [])))
        if ksig == sig or (kstack and kstack.issubset(norm)):
            matches.append(k)
    # highest confidence first
    matches.sort(key=lambda x: float(x.get("confidence", 0)), reverse=True)
    return matches


def decode_payload(entry: Dict[str, Any]) -> bytes:
    return base64.b64decode(entry.get("raw_payload_b64", "").encode("ascii"))


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description="Manage OmniSlash zero-day vault")
    ap.add_argument("--vault", default=DEFAULT_VAULT_PATH)
    sub = ap.add_subparsers(dest="cmd", required=True)
    ls = sub.add_parser("list")
    ls.add_argument("--tech", nargs="*", default=[])
    add = sub.add_parser("add")
    add.add_argument("--payload-file", required=True)
    add.add_argument("--mutation-type", required=True)
    add.add_argument("--protocol-edge", required=True)
    add.add_argument("--tech", nargs="+", required=True)
    add.add_argument("--source", default="incubator")
    imp = sub.add_parser("import-playbook", help="import a structured OmniSlash playbook case")
    imp.add_argument("file")
    imp.add_argument("--template", default="verify", choices=["verify", "solve"])
    args = ap.parse_args()

    vault = load_vault(args.vault)
    if args.cmd == "list":
        keys = find_keys_for_stack(vault, args.tech) if args.tech else vault.get("keys", [])
        print(json.dumps(keys, indent=2, ensure_ascii=False))
    elif args.cmd == "add":
        with open(args.payload_file, "rb") as f:
            payload = f.read()
        entry = add_universal_key(vault, payload, args.mutation_type, args.protocol_edge, args.tech, source=args.source)
        save_vault(vault, args.vault)
        print(json.dumps(entry, indent=2, ensure_ascii=False))
    elif args.cmd == "import-playbook":
        with open(args.file, "r", encoding="utf-8") as f:
            case = json.load(f)
        entry = import_playbook(vault, case, template=args.template)
        save_vault(vault, args.vault)
        print(json.dumps(entry, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
