#!/usr/bin/env python3
"""Simplified active grammar inference for WAF token rules.

Builds a compact WAFProfile from safe probe observations and adapts payloads
by replacing blocked bytes/tokens with allowed equivalents.
Stdlib only.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Sequence, Tuple


DEFAULT_WAF_PROFILES = os.path.join("state", "waf_profiles.json")


TOKEN_CLASSES = {
    "space": " ",
    "tab": "\t",
    "cr": "\r",
    "lf": "\n",
    "nul": "\x00",
    "vtab": "\x0b",
    "ff": "\x0c",
    "del": "\x7f",
    "semicolon": ";",
    "underscore": "_",
    "dash": "-",
}


@dataclass
class ProbeObservation:
    name: str
    token_class: str
    status: int
    allowed: bool
    context: str = ""


@dataclass
class WAFProfile:
    host: str
    vendor: str = "unknown"
    observations: List[ProbeObservation] = field(default_factory=list)
    allowed_tokens: Dict[str, bool] = field(default_factory=dict)
    blocked_tokens: Dict[str, bool] = field(default_factory=dict)
    allowed_chunk_ext: bool = True
    allowed_space_before_colon: bool = False
    allowed_alt_whitespace: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["observations"] = [asdict(o) for o in self.observations]
        return d

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "WAFProfile":
        obs = [ProbeObservation(**o) for o in d.get("observations", []) if isinstance(o, dict)]
        return WAFProfile(
            host=d.get("host", ""),
            vendor=d.get("vendor", "unknown"),
            observations=obs,
            allowed_tokens=dict(d.get("allowed_tokens", {})),
            blocked_tokens=dict(d.get("blocked_tokens", {})),
            allowed_chunk_ext=bool(d.get("allowed_chunk_ext", True)),
            allowed_space_before_colon=bool(d.get("allowed_space_before_colon", False)),
            allowed_alt_whitespace=list(d.get("allowed_alt_whitespace", [])),
        )


def infer_vendor(observations: Sequence[ProbeObservation], headers: Optional[Dict[str, str]] = None) -> str:
    headers = headers or {}
    blob = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
    if "cloudflare" in blob or "cf-ray" in blob:
        return "cloudflare"
    if "akamai" in blob:
        return "akamai"
    if "qrator" in blob:
        return "qrator"
    if "ddos-guard" in blob or "ddosguard" in blob:
        return "ddos-guard"
    # heuristic from observations
    blocked = [o.token_class for o in observations if not o.allowed]
    if "tab" in blocked and "vtab" in blocked:
        return "strict-waf"
    return "unknown"


class ActiveGrammarInferencer:
    """Simplified active inference: learns allowed/blocked token classes from probes."""

    def __init__(self, host: str):
        self.host = host
        self.profile = WAFProfile(host=host)

    def record(self, name: str, token_class: str, status: int, context: str = "") -> ProbeObservation:
        allowed = status in (200, 201, 202, 204, 301, 302, 304, 404)
        # 400/403 usually indicates blocked by WAF/filter; 404 can mean passed to app
        if status in (400, 403, 406, 413, 418, 429):
            allowed = False
        obs = ProbeObservation(name=name, token_class=token_class, status=status, allowed=allowed, context=context)
        self.profile.observations.append(obs)
        self.profile.allowed_tokens[token_class] = self.profile.allowed_tokens.get(token_class, False) or allowed
        if not allowed:
            self.profile.blocked_tokens[token_class] = True
            # if previously marked allowed, keep but blocked takes precedence for adaptation safety
        return obs

    def infer(self, headers: Optional[Dict[str, str]] = None) -> WAFProfile:
        p = self.profile
        p.vendor = infer_vendor(p.observations, headers=headers)
        # derive convenience flags
        p.allowed_space_before_colon = bool(p.allowed_tokens.get("space_before_colon", False)) and not p.blocked_tokens.get("space_before_colon", False)
        p.allowed_chunk_ext = not p.blocked_tokens.get("chunk_ext", False)
        alts = []
        for tc in ["space", "tab"]:
            if p.allowed_tokens.get(tc, False) and not p.blocked_tokens.get(tc, False):
                alts.append(TOKEN_CLASSES.get(tc, tc))
        p.allowed_alt_whitespace = alts
        return p

    def generate_safe_probes(self) -> List[Dict[str, Any]]:
        """Return a set of safe probe descriptors (caller sends them)."""
        return [
            {"name": "space", "token_class": "space", "header": "X-Omni-Probe: a b"},
            {"name": "tab", "token_class": "tab", "header": "X-Omni-Probe: a\tb"},
            {"name": "vtab", "token_class": "vtab", "header": "X-Omni-Probe: a\x0bb"},
            {"name": "ff", "token_class": "ff", "header": "X-Omni-Probe: a\x0cb"},
            {"name": "nul", "token_class": "nul", "header": "X-Omni-Probe: a\x00b"},
            {"name": "space_before_colon", "token_class": "space_before_colon", "header": "X-Omni-Probe : value"},
            {"name": "chunk_ext", "token_class": "chunk_ext", "header": "Transfer-Encoding: chunked"},
        ]


def adapt_payload_for_waf(payload: bytes, profile: WAFProfile) -> bytes:
    """Adapt payload by replacing blocked bytes/tokens with allowed equivalents."""
    if not payload or profile is None:
        return payload
    out = bytearray(payload)

    # Replace blocked control chars with allowed whitespace or remove.
    replacements: List[Tuple[bytes, bytes]] = []
    for tc, bstr in [("nul", b"\x00"), ("vtab", b"\x0b"), ("ff", b"\x0c"), ("del", b"\x7f")]:
        if profile.blocked_tokens.get(tc):
            repl = b" "
            if "tab" in profile.allowed_alt_whitespace and not profile.blocked_tokens.get("tab"):
                repl = b"\t"
            elif profile.allowed_alt_whitespace:
                repl = profile.allowed_alt_whitespace[0].encode("latin1", errors="ignore") or b" "
            replacements.append((bstr, repl))
    # Unpaired CR/LF: if blocked, normalize to CRLF in safe contexts (best effort)
    if profile.blocked_tokens.get("cr"):
        replacements.append((b"\r", b"\r\n"))
    if profile.blocked_tokens.get("lf"):
        replacements.append((b"\n", b"\r\n"))

    for old, new in replacements:
        if old in out:
            out = bytearray(out.replace(old, new))

    text = out.decode("latin1", errors="ignore")

    # Space before colon: if blocked, remove; if allowed and payload uses it, keep.
    if profile.blocked_tokens.get("space_before_colon"):
        text = re.sub(r"([A-Za-z0-9\-]+)\s+:", r"\1:", text)

    # Chunk-extension: if blocked, strip extensions; if allowed, can wrap marker.
    if profile.blocked_tokens.get("chunk_ext"):
        # remove chunk extensions like "5;ext=val"
        text = re.sub(r"([0-9a-fA-F]+);[^\r\n]*\r\n", r"\1\r\n", text)

    return text.encode("latin1", errors="ignore")


def load_profiles(path: str = DEFAULT_WAF_PROFILES) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {"version": 1, "profiles": []}
    with open(path, "r", encoding="utf-8") as f:
        obj = json.load(f)
    if not isinstance(obj, dict):
        return {"version": 1, "profiles": []}
    obj.setdefault("profiles", [])
    return obj


def save_profiles(store: Dict[str, Any], path: str = DEFAULT_WAF_PROFILES) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(store, f, indent=2, ensure_ascii=False)
        f.write("\n")


def upsert_profile(store: Dict[str, Any], profile: WAFProfile) -> None:
    profiles = store.setdefault("profiles", [])
    profiles[:] = [p for p in profiles if not (isinstance(p, dict) and p.get("host") == profile.host)]
    profiles.append(profile.to_dict())


def get_profile(store: Dict[str, Any], host: str) -> Optional[WAFProfile]:
    for p in store.get("profiles", []):
        if isinstance(p, dict) and p.get("host") == host:
            return WAFProfile.from_dict(p)
    return None


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description="WAF grammar inference/adaptation")
    ap.add_argument("--profiles", default=DEFAULT_WAF_PROFILES)
    sub = ap.add_subparsers(dest="cmd", required=True)
    inf = sub.add_parser("infer")
    inf.add_argument("--host", required=True)
    inf.add_argument("--observations", required=True, help="JSON file: [{name,token_class,status}] ")
    ad = sub.add_parser("adapt")
    ad.add_argument("--host", required=True)
    ad.add_argument("--payload-file", required=True)
    ad.add_argument("--out", required=True)
    args = ap.parse_args()

    store = load_profiles(args.profiles)
    if args.cmd == "infer":
        with open(args.observations, "r", encoding="utf-8") as f:
            obs = json.load(f)
        inf = ActiveGrammarInferencer(args.host)
        for o in obs:
            inf.record(o.get("name",""), o.get("token_class",""), int(o.get("status", 0)), o.get("context",""))
        prof = inf.infer()
        upsert_profile(store, prof)
        save_profiles(store, args.profiles)
        print(json.dumps(prof.to_dict(), indent=2, ensure_ascii=False))
    elif args.cmd == "adapt":
        prof = get_profile(store, args.host)
        if prof is None:
            raise SystemExit(f"no profile for host {args.host}")
        with open(args.payload_file, "rb") as f:
            payload = f.read()
        adapted = adapt_payload_for_waf(payload, prof)
        with open(args.out, "wb") as f:
            f.write(adapted)
        print(json.dumps({"host": args.host, "bytes": len(adapted)}))


if __name__ == "__main__":
    main()
