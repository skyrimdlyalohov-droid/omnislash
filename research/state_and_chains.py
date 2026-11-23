"""State-graph reconstruction and multi-step chain synthesis (Echelon 3/4).

Two cooperating pieces:

* :class:`StateGraphMiner` turns exported Caido request sequences into a
  directed state graph, highlights transitions that mutate security-sensitive
  state (cart, balance, role, session, ...) and emits synchronized cross-state
  race tasks for ``probe/`` via Last-Byte Sync.
* :class:`ChainSynthesizer` merges isolated confirmed anomalies (parser
  divergence, unkeyed cache input, direct origin reachability, ...) into a
  reachability proof for a target capability.  ``z3-solver`` is used when it is
  installed; otherwise a deterministic BFS over the capability rules runs on
  the standard library alone.

Nothing here sends traffic.  The output is inert JSON for the planner.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from itertools import combinations
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

try:  # optional dependency
    import z3  # type: ignore

    HAVE_Z3 = True
except Exception:  # pragma: no cover - exercised only without z3
    z3 = None  # type: ignore
    HAVE_Z3 = False


SENSITIVE_KEYS: Tuple[str, ...] = (
    "cart",
    "basket",
    "balance",
    "role",
    "permission",
    "permissions",
    "session",
    "credits",
    "coupon",
    "order",
    "inventory",
    "price",
    "auth",
    "token",
)

SENSITIVE_PATH_RE = re.compile(
    r"(?:cart|basket|checkout|purchase|order|transfer|payment|balance|wallet|"
    r"withdraw|admin|role|permission|password|email|redeem|coupon|invite|"
    r"referral|credit|inventory|price|session|login|logout|signin|signup)",
    re.IGNORECASE,
)

UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
HEX_ID_RE = re.compile(r"\b[0-9a-fA-F]{12,}\b")
NUM_ID_RE = re.compile(r"(?<=/)\d+(?=/|$)")


def stable_id(*parts: Any) -> str:
    """Deterministic short id that does not depend on ``hash()`` randomisation."""
    blob = "|".join(str(p) for p in parts)
    return hashlib.sha1(blob.encode("utf-8", "replace")).hexdigest()[:16]


def normalize_token(value: Any) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[\s\-/]+", "_", text)
    return re.sub(r"[^a-z0-9_:.]", "", text)


def normalize_path(path: str) -> str:
    """Strip query/fragment and replace volatile identifiers with templates."""
    p = str(path or "/").split("#", 1)[0].split("?", 1)[0]
    p = re.sub(r"/{2,}", "/", p)
    if not p.startswith("/"):
        p = "/" + p
    p = UUID_RE.sub("{uuid}", p)
    p = HEX_ID_RE.sub("{hex}", p)
    p = NUM_ID_RE.sub("{id}", p)
    return p


def parse_raw_request(raw: str) -> Dict[str, str]:
    """Parse the request line and headers of a raw HTTP/1.1 request."""
    out = {"method": "", "path": "", "host": "", "headers": {}}  # type: ignore[dict-item]
    if not raw or not isinstance(raw, str):
        return out
    text = raw.replace("\r\n", "\n")
    lines = text.split("\n")
    if lines:
        parts = lines[0].strip().split(" ")
        if len(parts) >= 2:
            out["method"] = parts[0].upper()
            out["path"] = parts[1]
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if not line.strip():
            break
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    out["headers"] = headers  # type: ignore[assignment]
    out["host"] = headers.get("host", "")
    return out


@dataclass
class SequenceRecord:
    """One normalized request inside a Caido-exported sequence."""

    method: str = ""
    path: str = "/"
    host: str = ""
    status: int = 0
    request_id: str = ""
    timestamp: float = 0.0
    state_before: str = ""
    state_after: str = ""
    delta: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    session: str = ""

    @staticmethod
    def from_caido(record: Dict[str, Any], position: int = 0) -> "SequenceRecord":
        raw = record.get("raw") or record.get("request") or ""
        parsed = parse_raw_request(raw) if isinstance(raw, str) else {"method": "", "path": "", "host": "", "headers": {}}
        headers = dict(parsed.get("headers") or {})  # type: ignore[arg-type]
        extra_headers = record.get("headers") or record.get("request_headers") or {}
        if isinstance(extra_headers, dict):
            headers.update({str(k).lower(): str(v) for k, v in extra_headers.items()})
        status = record.get("statusCode", record.get("status", 0)) or 0
        try:
            status = int(status)
        except (TypeError, ValueError):
            status = 0
        ts = record.get("timestamp", record.get("time", position))
        try:
            timestamp = float(ts)
        except (TypeError, ValueError):
            timestamp = float(position)
        delta = record.get("state_delta", record.get("delta", {}))
        if isinstance(delta, str):
            try:
                delta = json.loads(delta)
            except Exception:
                delta = {}
        if not isinstance(delta, dict):
            delta = {}
        return SequenceRecord(
            method=str(record.get("method") or parsed.get("method") or "").upper(),
            path=str(record.get("path") or parsed.get("path") or "/"),
            host=str(record.get("host") or parsed.get("host") or ""),
            status=status,
            request_id=str(record.get("id") or record.get("request_id") or ""),
            timestamp=timestamp,
            state_before=str(record.get("state_before") or ""),
            state_after=str(record.get("state_after") or ""),
            delta={normalize_token(k): v for k, v in delta.items()},
            headers=headers,
            session=str(record.get("session") or record.get("session_id") or ""),
        )


@dataclass
class Transition:
    src: str
    dst: str
    method: str
    path: str
    host: str = ""
    count: int = 0
    critical: bool = False
    delta: Dict[str, Any] = field(default_factory=dict)
    request_ids: List[str] = field(default_factory=list)
    statuses: List[int] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from": self.src,
            "to": self.dst,
            "method": self.method,
            "path": self.path,
            "host": self.host,
            "count": self.count,
            "critical": self.critical,
            "delta": dict(sorted(self.delta.items())),
            "request_ids": sorted(set(self.request_ids)),
            "statuses": sorted(set(self.statuses)),
        }


class StateGraphMiner:
    """Process-mining over ordered HTTP sequences."""

    def __init__(self, sensitive_keys: Optional[Sequence[str]] = None):
        self.sensitive_keys = {normalize_token(k) for k in (sensitive_keys or SENSITIVE_KEYS)}
        self._nodes: Set[str] = {"S_0"}
        self._labels: Dict[str, Dict[str, Any]] = {"S_0": {}}
        self._edges: Dict[Tuple[str, str, str, str], Transition] = {}
        self._state_signature: Dict[Tuple[Tuple[str, str], ...], str] = {(): "S_0"}
        self._sessions = 0
        self._records = 0
        self._counter = 0

    # -- ingestion -----------------------------------------------------

    def add_records(self, records: Iterable[Dict[str, Any]], group_by_session: bool = True) -> "StateGraphMiner":
        normalized: List[SequenceRecord] = []
        for pos, rec in enumerate(records):
            if isinstance(rec, SequenceRecord):
                normalized.append(rec)
            elif isinstance(rec, dict):
                normalized.append(SequenceRecord.from_caido(rec, pos))
        groups: Dict[str, List[SequenceRecord]] = defaultdict(list)
        for rec in normalized:
            key = rec.session if (group_by_session and rec.session) else "__default__"
            groups[key].append(rec)
        for key in groups:
            seq = sorted(groups[key], key=lambda r: (r.timestamp, r.request_id))
            self._mine_sequence(seq)
            self._sessions += 1
        self._records += len(normalized)
        return self

    def add_export(self, export: Dict[str, Any]) -> "StateGraphMiner":
        """Accept either a list or a Caido-shaped ``{"requests": [...]}`` export."""
        records = export.get("requests") if isinstance(export, dict) else export
        if isinstance(records, dict):
            records = records.get("nodes", [])
        return self.add_records(records or [])

    def _mine_sequence(self, seq: Sequence[SequenceRecord]) -> None:
        current = "S_0"
        for rec in seq:
            before = rec.state_before or current
            if before not in self._labels:
                self._nodes.add(before)
                self._labels[before] = {}
            delta = dict(rec.delta or self._infer_delta(rec))
            after = rec.state_after
            if after and after != before:
                nxt = after
                self._nodes.add(nxt)
                if delta:
                    self._labels[nxt] = dict(sorted(delta.items()))
            elif delta:
                nxt = self._new_state(delta)
            else:
                nxt = before
            critical = self._is_critical(rec, delta, before, nxt)
            self._add_edge(before, nxt, rec, delta, critical)
            current = nxt

    def _new_state(self, delta: Dict[str, Any]) -> str:
        signature = tuple(sorted((k, json.dumps(v, sort_keys=True, default=str)) for k, v in delta.items()))
        if signature in self._state_signature:
            return self._state_signature[signature]
        self._counter += 1
        name = f"S_{self._counter}"
        self._nodes.add(name)
        self._labels[name] = dict(sorted(delta.items()))
        self._state_signature[signature] = name
        return name

    def _infer_delta(self, rec: SequenceRecord) -> Dict[str, Any]:
        path = normalize_path(rec.path)
        method = rec.method.upper()
        delta: Dict[str, Any] = {}
        if rec.status in (401, 403):
            return {"auth": "denied"}
        if not (200 <= rec.status < 400) and rec.status != 0:
            return delta
        if re.search(r"/(?:login|signin|auth)", path, re.I) and method in ("POST", "PUT"):
            delta["session"] = "authenticated"
        elif re.search(r"/(?:logout|signout)", path, re.I):
            delta["session"] = "anonymous"
        if re.search(r"/(?:cart|basket)", path, re.I) and method in ("POST", "PUT", "PATCH", "DELETE"):
            delta["cart"] = "mutated"
        if re.search(r"/(?:checkout|purchase|order|orders)", path, re.I) and method == "POST":
            delta["cart"] = "checked_out"
        if re.search(r"/(?:admin|role|roles|permission|permissions)", path, re.I) and method in ("POST", "PUT", "PATCH"):
            delta["role"] = "escalated"
        if re.search(r"/(?:transfer|payment|balance|wallet|withdraw)", path, re.I) and method == "POST":
            delta["balance"] = "mutated"
        if re.search(r"/(?:coupon|redeem|invite|referral|credit|credits)", path, re.I) and method == "POST":
            delta["credits"] = "mutated"
        if "authorization" in rec.headers:
            delta.setdefault("session", "authenticated")
        return delta

    def _is_critical(self, rec: SequenceRecord, delta: Dict[str, Any], before: str, after: str) -> bool:
        if delta and (set(delta) & self.sensitive_keys):
            return True
        if rec.status in (200, 201, 202, 204) and SENSITIVE_PATH_RE.search(normalize_path(rec.path)):
            return before != after or bool(delta)
        return False

    def _add_edge(self, src: str, dst: str, rec: SequenceRecord, delta: Dict[str, Any], critical: bool) -> None:
        key = (src, dst, rec.method.upper(), normalize_path(rec.path))
        edge = self._edges.get(key)
        if edge is None:
            edge = Transition(src=src, dst=dst, method=rec.method.upper(), path=normalize_path(rec.path), host=rec.host)
            self._edges[key] = edge
        edge.count += 1
        edge.critical = edge.critical or critical
        for k, v in delta.items():
            edge.delta.setdefault(k, v)
        if rec.request_id:
            edge.request_ids.append(rec.request_id)
        if rec.status:
            edge.statuses.append(rec.status)

    # -- queries -------------------------------------------------------

    def transitions(self) -> List[Transition]:
        return [self._edges[k] for k in sorted(self._edges)]

    def critical_transitions(self) -> List[Transition]:
        return [t for t in self.transitions() if t.critical]

    def node_labels(self) -> Dict[str, Dict[str, Any]]:
        return {k: dict(sorted(v.items())) for k, v in sorted(self._labels.items())}

    def find_state_goal(self, key: str, value: Any = None) -> Optional[Dict[str, Any]]:
        norm_key = normalize_token(key)
        for state, delta in sorted(self._labels.items()):
            if norm_key not in delta:
                continue
            if value is None or str(delta[norm_key]) == str(value):
                return {"state": state, "delta": dict(sorted(delta.items()))}
        return None

    def _path_to(self, target: str) -> List[Transition]:
        """Deterministic BFS from S_0 to target over existing edges."""
        if target == "S_0":
            return []
        adj: Dict[str, List[Transition]] = defaultdict(list)
        for t in self.transitions():
            adj[t.src].append(t)
        for src in adj:
            adj[src].sort(key=lambda t: (t.dst, t.method, t.path))
        seen = {"S_0"}
        queue: deque[Tuple[str, List[Transition]]] = deque([("S_0", [])])
        while queue:
            node, path = queue.popleft()
            for edge in adj.get(node, []):
                if edge.dst == target:
                    return path + [edge]
                if edge.dst in seen:
                    continue
                seen.add(edge.dst)
                queue.append((edge.dst, path + [edge]))
        return []

    def race_tasks(self, replicas: int = 2) -> List[Dict[str, Any]]:
        tasks: List[Dict[str, Any]] = []
        for edge in self.critical_transitions():
            pre = self._path_to(edge.src)
            task_id = stable_id("race", edge.src, edge.dst, edge.method, edge.path)
            tasks.append({
                "id": task_id,
                "kind": "cross-state-race",
                "probe": "h2race",
                "transition": f"{edge.src}->{edge.dst}",
                "target_state": edge.dst,
                "delta": dict(sorted(edge.delta.items())),
                "host": edge.host,
                "sync": "last-byte",
                "replicas": int(max(2, replicas)),
                "preconditions": [
                    {"method": t.method, "path": t.path, "host": t.host} for t in pre
                ],
                "race": {"method": edge.method, "path": edge.path, "host": edge.host},
                "request_ids": sorted(set(edge.request_ids)),
            })
        return sorted(tasks, key=lambda t: (t["transition"], t["race"]["path"]))

    def to_dict(self) -> Dict[str, Any]:
        tasks = self.race_tasks()
        return {
            "schema": "omnislash.state-graph/v1",
            "sessions": self._sessions,
            "records": self._records,
            "nodes": sorted(self._nodes),
            "labels": self.node_labels(),
            "transitions": [t.to_dict() for t in self.transitions()],
            "critical": [t.to_dict() for t in self.critical_transitions()],
            "race_tasks": tasks,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Chain synthesis
# ---------------------------------------------------------------------------


CAPABILITY_ALIASES: Dict[str, str] = {
    "parse_discrepancy": "parser_divergence",
    "parser_discrepancy": "parser_divergence",
    "parser_divergence": "parser_divergence",
    "desync": "parser_divergence",
    "desync_confirmed": "parser_divergence",
    "smuggle_confirmed": "parser_divergence",
    "h2_tunnel_confirmed": "parser_divergence",
    "request_smuggling": "parser_divergence",
    "cache_poisoned": "cache_key_gap",
    "cache_poison": "cache_key_gap",
    "unkeyed_input": "cache_key_gap",
    "unkeyed_header": "cache_key_gap",
    "cache_key_gap": "cache_key_gap",
    "origin_ip": "origin_reachable",
    "origin_reachable": "origin_reachable",
    "direct_origin": "origin_reachable",
    "server_fetch": "server_fetch",
    "ssrf": "server_fetch",
    "race_confirmed": "concurrency_window",
    "race": "concurrency_window",
    "concurrency_window": "concurrency_window",
    "auth_bypass": "auth_bypass",
    "authentication_bypass": "auth_bypass",
    "privilege_escalation": "auth_bypass",
    "stored_xss": "content_control",
    "response_splitting": "parser_divergence",
}


@dataclass(frozen=True)
class ChainRule:
    requires: Tuple[str, ...]
    provides: str
    rationale: str

    def key(self) -> Tuple[str, ...]:
        return (self.provides,) + self.requires

    def to_dict(self) -> Dict[str, Any]:
        return {
            "requires": list(self.requires),
            "provides": self.provides,
            "rationale": self.rationale,
        }


DEFAULT_RULES: Tuple[ChainRule, ...] = (
    ChainRule(("parser_divergence", "cache_key_gap"), "cache_poison",
              "an unkeyed cache input plus parser disagreement lets one request poison another response"),
    ChainRule(("cache_poison", "origin_reachable"), "origin_content_control",
              "poisoned cached content reaches the origin path reached directly"),
    ChainRule(("parser_divergence", "origin_reachable"), "origin_desync",
              "direct origin access exposes the parser that disagrees with the edge"),
    ChainRule(("auth_bypass", "origin_reachable"), "privileged_origin_access",
              "an auth bypass becomes authoritative when the origin is directly reachable"),
    ChainRule(("concurrency_window", "cache_key_gap"), "race_amplification",
              "a cache-key gap widens the concurrent state window"),
    ChainRule(("server_fetch", "origin_reachable"), "internal_origin_access",
              "server-side fetch to a directly reachable origin crosses the trust boundary"),
    ChainRule(("origin_content_control", "parser_divergence"), "persistent_response_split",
              "persistent content control plus a parser gap yields a stable split response"),
    ChainRule(("privileged_origin_access", "content_control"), "origin_takeover",
              "privileged origin access plus content control yields authoritative content"),
)


def _is_quarantined(finding: Dict[str, Any]) -> bool:
    if finding.get("unverified") is True:
        return True
    if finding.get("quarantined") is True:
        return True
    if str(finding.get("status", "")).lower() in ("unverified", "quarantined"):
        return True
    filt = finding.get("_omnislash_filter") or {}
    if isinstance(filt, dict) and filt.get("verified") is False:
        return True
    return False


def finding_capabilities(finding: Dict[str, Any]) -> List[str]:
    explicit = finding.get("capabilities") or finding.get("provides")
    caps: List[str] = []
    if isinstance(explicit, (list, tuple, set)):
        caps.extend(normalize_token(c) for c in explicit if str(c).strip())
    elif isinstance(explicit, str) and explicit.strip():
        caps.append(normalize_token(explicit))
    kind = normalize_token(finding.get("kind") or finding.get("type") or "unknown")
    mapped = CAPABILITY_ALIASES.get(kind, kind)
    if mapped and mapped not in caps:
        caps.append(mapped)
    return sorted(set(caps))


@dataclass
class FindingNode:
    id: str
    kind: str
    capabilities: Tuple[str, ...]
    host: str = ""
    path: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)

    def summary(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "capabilities": list(self.capabilities),
            "host": self.host,
            "path": self.path,
        }


class ChainSynthesizer:
    """Reachability proof over anomaly capabilities (z3 or stdlib BFS)."""

    def __init__(
        self,
        findings: Optional[Iterable[Dict[str, Any]]] = None,
        rules: Optional[Sequence[ChainRule]] = None,
        include_unverified: bool = False,
    ):
        self.rules: List[ChainRule] = sorted(rules or DEFAULT_RULES, key=lambda r: r.key())
        self.include_unverified = include_unverified
        self.findings: List[FindingNode] = []
        self.skipped: List[Dict[str, Any]] = []
        if findings:
            self.add_findings(findings)

    def add_findings(self, findings: Iterable[Dict[str, Any]]) -> "ChainSynthesizer":
        for raw in findings:
            if not isinstance(raw, dict):
                continue
            if _is_quarantined(raw) and not self.include_unverified:
                self.skipped.append({"kind": raw.get("kind", ""), "reason": "quarantined"})
                continue
            kind = normalize_token(raw.get("kind") or raw.get("type") or "unknown")
            caps = finding_capabilities(raw)
            fid = str(raw.get("id") or raw.get("request_id") or stable_id(kind, raw.get("host", ""), raw.get("path", "")))
            self.findings.append(FindingNode(
                id=fid,
                kind=kind,
                capabilities=tuple(caps),
                host=str(raw.get("host") or raw.get("target") or ""),
                path=str(raw.get("path") or ""),
                raw=raw,
            ))
        self.findings.sort(key=lambda f: (f.kind, f.id))
        return self

    def _closure(self, capabilities: Set[str]) -> Tuple[Set[str], List[ChainRule]]:
        caps = set(capabilities)
        used: List[ChainRule] = []
        changed = True
        while changed:
            changed = False
            for rule in self.rules:
                if rule.provides in caps:
                    continue
                if all(req in caps for req in rule.requires):
                    caps.add(rule.provides)
                    used.append(rule)
                    changed = True
        used.sort(key=lambda r: r.key())
        return caps, used

    def _satisfies(self, caps: Set[str], goals: Sequence[str]) -> bool:
        return any(g in caps for g in goals)

    def _goal_expr(self, goals: Sequence[str]) -> Any:
        exprs = [z3.Bool(f"cap_{g}") for g in goals]  # type: ignore[union-attr]
        return z3.Or(exprs)  # type: ignore[union-attr]

    def _solve_z3(self, goals: Sequence[str]) -> Optional[List[int]]:
        if not HAVE_Z3:
            return None
        use = [z3.Bool(f"use_{i}") for i in range(len(self.findings))]  # type: ignore[union-attr]
        names = sorted({c for f in self.findings for c in f.capabilities} | {r.provides for r in self.rules} | set(goals))
        cap = {name: z3.Bool(f"cap_{name}") for name in names}  # type: ignore[union-attr]
        opt = z3.Optimize()  # type: ignore[union-attr]
        providers: Dict[str, List[Any]] = defaultdict(list)
        for i, f in enumerate(self.findings):
            for c in f.capabilities:
                providers[c].append(use[i])
        for r in self.rules:
            providers[r.provides].append(z3.And(*[cap[q] for q in r.requires]))  # type: ignore[union-attr]
        for name in names:
            providers[name] = providers.get(name, [])
            rhs = z3.Or(*providers[name]) if providers[name] else z3.BoolVal(False)  # type: ignore[union-attr]
            opt.add(cap[name] == rhs)
        goal_expr = z3.Or(*[cap[g] for g in goals]) if goals else z3.BoolVal(False)  # type: ignore[union-attr]
        opt.add(goal_expr)
        opt.minimize(z3.Sum([z3.If(u, 1, 0) for u in use]) if use else z3.IntVal(0))  # type: ignore[union-attr]
        if opt.check() != z3.sat:  # type: ignore[union-attr]
            return None
        model = opt.model()
        return [i for i, u in enumerate(use) if z3.is_true(model.eval(u, model_completion=True))]  # type: ignore[union-attr]

    def _solve_bfs(self, goals: Sequence[str], max_combinations: int = 200_000) -> Optional[List[int]]:
        base: Set[str] = set()
        base_caps, _ = self._closure(base)
        if self._satisfies(base_caps, goals):
            return []
        n = len(self.findings)
        # Search subsets in increasing cardinality for a minimal chain.
        checked = 0
        for size in range(1, min(n, 8) + 1):
            for combo in combinations(range(n), size):
                checked += 1
                if checked > max_combinations:
                    return None
                caps = set()
                for idx in combo:
                    caps.update(self.findings[idx].capabilities)
                closed, _ = self._closure(caps)
                if self._satisfies(closed, goals):
                    return list(combo)
        if n > 8:
            # Greedy deterministic fallback for very large finding sets.
            selected: List[int] = []
            caps: Set[str] = set()
            remaining = list(range(n))
            while remaining:
                best = None
                best_gain = 0
                for idx in remaining:
                    trial = set(caps)
                    trial.update(self.findings[idx].capabilities)
                    closed, _ = self._closure(trial)
                    gain = len(closed - caps)
                    if gain > best_gain:
                        best_gain = gain
                        best = idx
                if best is None:
                    break
                selected.append(best)
                caps.update(self.findings[best].capabilities)
                caps, _ = self._closure(caps)
                remaining.remove(best)
                if self._satisfies(caps, goals):
                    return sorted(selected)
        return None

    def synthesize(
        self,
        goal: Any,
        miner: Optional[StateGraphMiner] = None,
        state_key: str = "",
        state_value: Any = None,
    ) -> Dict[str, Any]:
        goals = [normalize_token(g) for g in (goal if isinstance(goal, (list, tuple, set)) else [goal]) if str(g).strip()]
        goals = sorted(set(goals))
        engine = "bfs"
        selected: Optional[List[int]] = None
        if HAVE_Z3:
            selected = self._solve_z3(goals)
            if selected is not None:
                engine = "z3"
        if selected is None:
            selected = self._solve_bfs(goals)
        selected = selected or []
        caps: Set[str] = set()
        for idx in selected:
            caps.update(self.findings[idx].capabilities)
        closed, used_rules = self._closure(caps)
        reachable = self._satisfies(closed, goals)

        state_transition = None
        if miner is not None and state_key:
            state_transition = miner.find_state_goal(state_key, state_value)

        steps = []
        for rule in used_rules:
            steps.append({
                "rule": "+".join(rule.requires) + " -> " + rule.provides,
                "requires": list(rule.requires),
                "provides": rule.provides,
                "rationale": rule.rationale,
            })
        chosen = sorted(selected, key=lambda i: self.findings[i].id)
        summaries = [self.findings[i].summary() for i in chosen]
        return {
            "schema": "omnislash.chain-synthesis/v1",
            "goal": goals,
            "reachable": bool(reachable),
            "engine": engine,
            "findings": summaries,
            "chain": summaries,
            "capabilities": sorted(closed),
            "derived": sorted({r.provides for r in used_rules}),
            "steps": steps,
            "state_transition": state_transition,
            "skipped": sorted(self.skipped, key=lambda s: (s.get("kind", ""), s.get("reason", ""))),
        }

    def to_json(self, result: Dict[str, Any]) -> str:
        return json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False)


def synthesize_chain(
    findings: Iterable[Dict[str, Any]],
    goal: Any,
    miner: Optional[StateGraphMiner] = None,
    state_key: str = "",
    state_value: Any = None,
    include_unverified: bool = False,
) -> Dict[str, Any]:
    """Convenience wrapper around :class:`ChainSynthesizer`."""
    synth = ChainSynthesizer(findings, include_unverified=include_unverified)
    return synth.synthesize(goal, miner=miner, state_key=state_key, state_value=state_value)
