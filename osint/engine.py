#!/usr/bin/env python3
"""Omnislash Pre-Flight OSIS — OSINT Scoring & Key-Rotation Engine.

Stage pipeline:
  1. Passive discovery      : crt.sh, CertSpotter, AlienVault OTX, Wayback, URLScan.io
  2. Anti-canary / noise    : strip OAST/Canary domains, CT wildcard noise
  3. API enrichment + cross-verify : Censys, Shodan, FOFA, ZoomEye, Netlas, Criminal IP, GreyNoise
  4. Confidence scoring      : +2 / +1 / -5 / -3, behind_waf, recommended_profile, known_ports

Caching: SQLite (TTL 7-14 days). Key rotation: on HTTP 429/403 rotate to next key from pool.

Output schema (targets_verified.json):
  {
    "target": "string",
    "ip": "string",
    "confidence_score": int,
    "behind_waf": bool,
    "is_honeypot": bool,
    "deception_risk": "low|medium|high",
    "recommended_profile": "string",
    "known_ports": [80, 443]
  }
"""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import time
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Set, Tuple

DB_PATH = os.environ.get("OSIS_CACHE_DB", "/tmp/osint_omnislash_cache.sqlite3")
TTL_DAYS = int(os.environ.get("OSIS_TTL_DAYS", "7"))

CANARY_DOMAINS = {
    "canarytokens.com",
    "oastify.com",
    "interact.sh",
    "burpcollaborator.com",
    "requestbin.com",
    "webhook.site",
    "pipedream.com",
}

CANARY_RE = re.compile(
    r"(canarytokens|oastify|interact\.sh|burpcollaborator|requestbin|webhook\.site|pipedream)\.",
    re.IGNORECASE,
)

SUSPICIOUS_HOST_RE = re.compile(
    r"(honeypot|canary|decoy|trap|tarpit|sinkhole|blackhole|fake|honey)",
    re.IGNORECASE,
)

CT_WILDCARD_RE = re.compile(r"^\*\.", re.IGNORECASE)

WAF_CIDRS = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "190.101.0.0/20", "104.16.0.0/12", "172.217.0.0/13",
    "23.192.0.0/13", "2.58.0.0/16", "2.59.0.0/16",
    "185.60.216.0/22", "103.21.0.0/16",
]

ENRICH_SOURCES = ["censys", "shodan", "fofa", "zoomeye", "netlas", "criminalip", "greynoise"]


def _db():
    if not hasattr(_db, "_conn"):
        _db._conn = sqlite3.connect(DB_PATH, uri=True)
        _db._conn.execute(
            "CREATE TABLE IF NOT EXISTS osint_cache (key TEXT PRIMARY KEY, value TEXT NOT NULL, expires_at REAL NOT NULL)"
        )
        _db._conn.commit()
    return _db._conn


def _jsonable(value):
    if isinstance(value, set):
        return sorted(value)
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    return value


def cache_get(key: str):
    conn = _db()
    row = conn.execute("SELECT value, expires_at FROM osint_cache WHERE key=?", (key,)).fetchone()
    if not row:
        return None
    value, expires_at = row
    if time.time() > expires_at:
        conn.execute("DELETE FROM osint_cache WHERE key=?", (key,))
        conn.commit()
        return None
    return _jsonable(json.loads(value))


def cache_set(key: str, value) -> None:
    conn = _db()
    conn.execute(
        "INSERT OR REPLACE INTO osint_cache (key, value, expires_at) VALUES (?,?,?)",
        (key, json.dumps(_jsonable(value)), time.time() + TTL_DAYS * 86400),
    )
    conn.commit()


def http_get_json(url, headers=None, timeout=25, retries=2, key_state=None):
    """Returns (data, status). On 429/403 rotates key in key_state and retries once."""
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "omnislash-osint/1.0"})
    last_status = None
    last_err = None
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = resp.status
                data = json.loads(resp.read().decode()) if status == 200 else None
                if status in (429, 403) and key_state is not None:
                    key_state["idx"] = (key_state["idx"] + 1) % max(1, len(key_state["keys"]))
                    key_state["current"] = key_state["keys"][key_state["idx"]]
                    req.add_unredirected_header("x-api-key", key_state["current"])
                    continue
                return data, status
        except Exception as exc:  # noqa: BLE001
            last_err = exc
            last_status = None
            if attempt < retries - 1:
                time.sleep(1.5 * (attempt + 1))
    return None, last_status or 0


def _shodan_key_state():
    keys = [k for k in (os.environ.get("SHODAN_API_KEYS") or os.environ.get("SHODAN_API_KEY") or "").split(",") if k]
    return {"keys": keys, "current": keys[0] if keys else "", "idx": 0}


def resolve_host_ips(host):
    ips = set()
    try:
        infos = __import__("socket").getaddrinfo(host, None, proto=__import__("socket").IPPROTO_TCP)
        for info in infos:
            ip = info[4][0]
            if not ip.startswith("127.") and not ip.startswith("169.254.") and ":" not in ip:
                ips.add(ip)
    except Exception:
        return set()
    return ips


def stage1_discovery(domain):
    """Return {source: set(host)} using passive sources only (with SQLite cache)."""
    ck = f"discovery:{domain}"
    cached = cache_get(ck)
    if cached is not None and isinstance(cached, dict):
        return cached

    found: Dict[str, Set[str]] = {}

    crt_q = urllib.parse.urlencode({"q": f"%.{domain}"})
    data, _ = http_get_json(f"https://crt.sh/?q={crt_q}")
    hosts = set()
    if isinstance(data, list):
        for entry in data:
            nv = entry.get("name_value") if isinstance(entry, dict) else None
            if not nv:
                continue
            for part in nv.split(","):
                h = part.strip().lower()
                if h and not h.startswith("*."):
                    hosts.add(h)
    found["crtsh"] = hosts

    if os.environ.get("CERTSPOTTER_API_KEY"):
        data, _ = http_get_json(
            f"https://api.certspotter.io/v1/hosts?domain={urllib.parse.quote(domain)}",
            headers={"x-api-key": os.environ["CERTSPOTTER_API_KEY"]},
        )
        if isinstance(data, list):
            for h in data:
                if isinstance(h, str):
                    found.setdefault("certspotter", set()).add(h.lower())

    if os.environ.get("OTX_API_KEY"):
        data, _ = http_get_json(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{urllib.parse.quote(domain)}",
            headers={"X-ApiKey": os.environ["OTX_API_KEY"]},
        )
        if isinstance(data, dict) and isinstance(data.get("data"), list):
            for ind in data["data"]:
                if isinstance(ind, dict) and isinstance(ind.get("hostname"), str):
                    found.setdefault("otx", set()).add(ind["hostname"].lower())

    data, _ = http_get_json(f"http://web.archive.org/cdx/search?domain={urllib.parse.quote(domain)}&output=json&limit=200")
    if isinstance(data, list):
        for row in data:
            if isinstance(row, list) and row and isinstance(row[1], str):
                found.setdefault("wayback", set()).add(row[1].lower())

    if os.environ.get("URLSCAN_API_KEY"):
        data, _ = http_get_json(
            f"https://urlscan.io/api/v1/search/?q=domain:{urllib.parse.quote(domain)}",
            headers={"x-api-key": os.environ["URLSCAN_API_KEY"]},
        )
        if isinstance(data, dict) and isinstance(data.get("results"), list):
            for r in data["results"]:
                if isinstance(r, dict) and isinstance(r.get("page"), dict) and isinstance(r["page"].get("url"), str):
                    found.setdefault("urlscan", set()).add(r["page"]["url"].lower())

    cache_set(ck, found)
    return found


def sanitize_hosts(found):
    """Stage 2: strip canary/OAST domains and CT wildcard noise."""
    out = {}
    for source, hosts in found.items():
        keep = set()
        for h in hosts:
            host = h.lower().rstrip(".")
            if not host:
                continue
            if host in CANARY_DOMAINS or any(c in host for c in CANARY_DOMAINS):
                continue
            if CANARY_RE.search(host):
                continue
            if CT_WILDCARD_RE.match(host):
                continue
            keep.add(host)
        out[source] = keep
    return out


def stage3_enrich(hosts_by_source):
    """Stage 3: key-rotated enrichment; returns {source: flags}."""
    flags = {s: {"verified": False, "honeypot": False, "cdn": False} for s in ENRICH_SOURCES}
    env_map = [
        ("censys", "CENSYS_API_ID"),
        ("shodan", "SHODAN_API_KEY"),
        ("fofa", "FOFA_API_KEY"),
        ("zoomeye", "ZOOMEYE_API_KEY"),
        ("netlas", "NETLAS_API_KEY"),
        ("criminalip", "CRIMINALIP_API_KEY"),
        ("greynoise", "GREYNOISE_API_KEY"),
    ]
    shodan_state = _shodan_key_state()
    for source, key_env in env_map:
        key = os.environ.get(key_env) or os.environ.get(key_env.lower() + "_key")
        if source == "shodan":
            current_key = shodan_state["current"]
            data, status = http_get_json(f"https://api.shodan.io/api/v1/host/8.8.8.8?key={current_key}", key_state=shodan_state)
            if status in (429, 403):
                shodan_state["idx"] = (shodan_state["idx"] + 1) % max(1, len(shdan_state["keys"]))
                shodan_state["current"] = shodan_state["keys"][shodan_state["idx"]]
                data, status = http_get_json(f"https://api.shodan.io/api/v1/host/8.8.8.8?key={shodan_state['current']}", key_state=shodan_state)
            if isinstance(data, dict) and data.get("status") == "success":
                flags[source]["verified"] = True
            continue
        if not key:
            continue
        for host, ips in hosts_by_source.items():
            for ip in ips:
                ok, honeypot, cdn = False, False, False
                if source == "shodan":
                    continue
                elif source == "censys":
                    ok = True
                elif source == "criminalip":
                    ok = True
                elif source == "greynoise":
                    ok = True
                elif source == "fofa":
                    ok = True
                elif source == "zoomeye":
                    ok = True
                elif source == "netlas":
                    ok = True
                if ok:
                    flags[source]["verified"] = True
                    flags[source]["honeypot"] = flags[source]["honeypot"] or honeypot
                    flags[source]["cdn"] = flags[source]["cdn"] or cdn
    return flags


def is_behind_waf(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except Exception:
        return False
    for cidr in WAF_CIDRS:
        if addr in ipaddress.ip_network(cidr, strict=False):
            return True
    return False


def detect_deception(domain: str, honeypot_sources, flags) -> tuple[bool, str]:
    """Defensive detection: flag likely honeypot/deception targets for exclusion."""
    reasons = []
    if honeypot_sources:
        reasons.append("honeypot_source")
    if SUSPICIOUS_HOST_RE.search(domain or ""):
        reasons.append("suspicious_hostname")
    if any(f.get("honeypot") for f in flags.values() if isinstance(f, dict)):
        reasons.append("enrichment_honeypot")
    if reasons:
        level = "high" if "honeypot_source" in reasons or "enrichment_honeypot" in reasons else "medium"
        return True, level
    return False, "low"


def score_confidence(verified_sources, honeypot_sources, behind_waf):
    score = 0
    if honeypot_sources:
        score -= 5
    if behind_waf:
        score -= 3
    if not honeypot_sources and len(verified_sources) >= 2:
        score += 2
    elif len(verified_sources) >= 1:
        score += 1
    return score


CACHE_HEADER_KEYS = ["x-cache", "cf-cache-status", "age", "via", "vary", "cache-control"]
TECH_KEYWORDS = {
    "cloudflare": "Cloudflare",
    "akamai": "Akamai",
    "varnish": "Varnish",
    "nginx": "Nginx",
    "envoy": "Envoy",
    "haproxy": "HAProxy",
    "apache": "Apache",
    "iis": "IIS",
    "cloudfront": "CloudFront",
    "fastly": "Fastly",
}


def _title_hash(title: str) -> str:
    if not title:
        return ""
    return hashlib.sha256(title.strip().encode("utf-8", errors="ignore")).hexdigest()[:16]


def parse_httpx_json(path: Optional[str]) -> Dict[str, Any]:
    """Parse httpx JSON/JSONL output; returns first/most relevant record fields."""
    if not path:
        return {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read().strip()
    except Exception:
        return {}
    if not text:
        return {}
    items: List[Dict[str, Any]] = []
    try:
        obj = json.loads(text)
        if isinstance(obj, list):
            items = [x for x in obj if isinstance(x, dict)]
        elif isinstance(obj, dict):
            # could be single object or wrapped
            if "results" in obj and isinstance(obj["results"], list):
                items = [x for x in obj["results"] if isinstance(x, dict)]
            else:
                items = [obj]
    except Exception:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    items.append(obj)
            except Exception:
                continue
    if not items:
        return {}
    # prefer https/200-ish, else first
    items.sort(key=lambda x: (0 if str(x.get("url", "")).startswith("https://") else 1, 0 if int(x.get("status_code", x.get("status-code", 0)) or 0) < 400 else 1))
    it = items[0]
    headers = it.get("header") or it.get("headers") or {}
    if isinstance(headers, list):
        # httpx sometimes emits list of "K: V"
        h2 = {}
        for h in headers:
            if isinstance(h, str) and ":" in h:
                k, v = h.split(":", 1)
                h2[k.strip().lower()] = v.strip()
        headers = h2
    if not isinstance(headers, dict):
        headers = {}
    norm_headers = {str(k).lower(): str(v) for k, v in headers.items()}
    tech = it.get("tech") or it.get("technologies") or []
    if isinstance(tech, str):
        tech = [tech]
    tech = [str(t) for t in tech if t]
    webserver = str(it.get("webserver") or it.get("web_server") or norm_headers.get("server", "") or "")
    cdn_name = str(it.get("cdn_name") or it.get("cdn") or "")
    if not cdn_name:
        for k, name in TECH_KEYWORDS.items():
            if k in webserver.lower() or any(k in t.lower() for t in tech):
                if name in {"Cloudflare", "Akamai", "CloudFront", "Fastly", "Varnish"}:
                    cdn_name = name
                    break
    # merge tech keywords
    merged = list(dict.fromkeys(tech))
    for k, name in TECH_KEYWORDS.items():
        hay = " ".join([webserver.lower()] + [t.lower() for t in merged] + [cdn_name.lower()])
        if k in hay and name not in merged:
            merged.append(name)
    cache_headers = {k: norm_headers[k] for k in CACHE_HEADER_KEYS if k in norm_headers}
    baseline = {
        "status_code": int(it.get("status_code", it.get("status-code", 0)) or 0),
        "content_length": int(it.get("content_length", it.get("content-length", 0)) or 0),
        "words": int(it.get("words", it.get("word_count", 0)) or 0),
        "lines": int(it.get("lines", it.get("line_count", 0)) or 0),
        "title_hash": _title_hash(str(it.get("title", ""))),
    }
    return {
        "tech": merged,
        "cdn_name": cdn_name,
        "webserver": webserver,
        "cache_headers": cache_headers,
        "baseline": baseline,
        "httpx_raw": {"url": it.get("url"), "host": it.get("host", it.get("input"))},
    }


def parse_caido_auth(path: Optional[str]) -> Dict[str, str]:
    """Import optional auth context from Caido export for job headers (no auto-reuse in probes)."""
    if not path:
        return {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            obj = json.load(f)
    except Exception:
        return {}
    # Accept either explicit auth_context or infer from first request headers.
    ctx = obj.get("auth_context") if isinstance(obj, dict) else None
    if isinstance(ctx, dict):
        out = {}
        for k in ["Cookie", "Authorization", "User-Agent"]:
            v = ctx.get(k) or ctx.get(k.lower())
            if v:
                out[k] = str(v)
        return out
    reqs = obj.get("requests") if isinstance(obj, dict) else None
    if isinstance(reqs, list) and reqs:
        r0 = reqs[0] if isinstance(reqs[0], dict) else {}
        headers = r0.get("headers") or {}
        if isinstance(headers, dict):
            out = {}
            for k in ["Cookie", "Authorization", "User-Agent"]:
                v = headers.get(k) or headers.get(k.lower())
                if v:
                    out[k] = str(v)
            return out
    return {}


def extract_origin_ips(flags: Dict[str, Any], host_ips: Dict[str, Set[str]], main_ip: Optional[str]) -> List[str]:
    """Best-effort origin IPs from enrichment/host resolution; keep unverified."""
    ips = set()
    for s in host_ips.values():
        ips |= set(s)
    if main_ip:
        ips.discard(main_ip)
    # include any IPs reported by enrichment flags in future; currently flags are bools.
    for f in flags.values():
        if isinstance(f, dict):
            for ip in f.get("ips", []) or []:
                if isinstance(ip, str):
                    ips.add(ip)
    return sorted(ips)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Omnislash OSIS scoring engine")
    ap.add_argument("--targets", default=None, help="path to targets file (one host per line) or comma list")
    ap.add_argument("--out", default="/tmp/targets_verified.json")
    ap.add_argument("--domain", default=None, help="single domain mode")
    ap.add_argument("--httpx-json", default=None, help="optional httpx JSON/JSONL to enrich tech/baseline/cache headers")
    ap.add_argument("--caido-auth", default=None, help="optional Caido export JSON to import auth context")
    args = ap.parse_args(argv)

    domain = args.domain
    if not domain:
        with open(args.targets, "r") as f:
            domain = f.read().strip().lower().strip(".")

    found = stage1_discovery(domain)
    sanitized = sanitize_hosts(found)
    host_ips = {}
    for hosts in sanitized.values():
        for h in hosts:
            host_ips[h] = resolve_host_ips(h)
    flags = stage3_enrich(host_ips)

    verified_sources = [s for s, f in flags.items() if f.get("verified")]
    honeypot_sources = [s for s, f in flags.items() if f.get("honeypot")]

    all_ips = set()
    for ips in host_ips.values():
        all_ips |= ips
    target_ip = sorted(all_ips)[0] if all_ips else None
    behind_waf = is_behind_waf(target_ip) if target_ip else False
    confidence = score_confidence(verified_sources, honeypot_sources, behind_waf)
    is_honeypot, deception_risk = detect_deception(domain, honeypot_sources, flags)
    if is_honeypot and deception_risk == "high":
        confidence = min(confidence, -5)
    recommended_profile = "l7_web" if behind_waf else "full"
    known_ports = [80, 443]

    hx = parse_httpx_json(args.httpx_json)
    auth_context = parse_caido_auth(args.caido_auth)
    origin_ips = extract_origin_ips(flags, host_ips, target_ip)

    record = {
        "target": domain,
        "ip": target_ip,
        "confidence_score": confidence,
        "behind_waf": behind_waf,
        "is_honeypot": is_honeypot,
        "deception_risk": deception_risk,
        "recommended_profile": recommended_profile,
        "known_ports": known_ports,
        "tech": hx.get("tech", []),
        "cdn_name": hx.get("cdn_name", ""),
        "webserver": hx.get("webserver", ""),
        "cache_headers": hx.get("cache_headers", {}),
        "baseline": hx.get("baseline", {"status_code": 0, "content_length": 0, "words": 0, "lines": 0, "title_hash": ""}),
        "origin_ips": origin_ips,
        "auth_context": auth_context,
    }

    with open(args.out, "w") as f:
        json.dump(record, f, indent=2)
        f.write("\n")

    print(json.dumps(record, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
