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
) -> Dict[str, Any]:
    sig = tech_stack_hash(tech_stack)
    entry = {
        "id": hashlib.sha256((sig + "|" + mutation_type + "|" + protocol_edge + "|" + base64.b64encode(raw_payload).decode()).encode()).hexdigest()[:16],
        "tech_stack_hash": sig,
        "tech_stack_digest": tech_stack_digest(tech_stack),
        "tech_stack": normalize_tech_stack(tech_stack),
        "raw_payload_b64": base64.b64encode(raw_payload).decode("ascii"),
        "mutation_type": mutation_type,
        "protocol_edge": protocol_edge,
        "source": source,
        "confidence": float(confidence),
        "metadata": metadata or {},
    }
    keys = vault.setdefault("keys", [])
    # dedupe by id
    keys[:] = [k for k in keys if k.get("id") != entry["id"]]
    keys.append(entry)
    return entry


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


if __name__ == "__main__":
    main()
