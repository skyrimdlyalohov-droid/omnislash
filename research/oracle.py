"""Scientific oracle for OmniSlash Echelon 1.

Robust statistics and TPE-like mutation selection. Stdlib only.
"""

from __future__ import annotations

import math
import random
import statistics
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple


def trim_upper_outliers(values: Sequence[float], trim_fraction: float = 0.15) -> List[float]:
    """Drop upper trim_fraction of values (e.g. TCP retransmits)."""
    vals = [float(v) for v in values if v is not None]
    if not vals:
        return []
    vals.sort()
    if len(vals) < 4:
        return vals
    k = int(math.floor(len(vals) * trim_fraction))
    k = max(0, min(k, len(vals) - 1))
    if k == 0:
        return vals
    return vals[: len(vals) - k]


def is_monotonic_increase(values: Sequence[float], tolerance: float = 0.0) -> bool:
    """Return True if values show monotonic non-decreasing trend (WAF throttling)."""
    vals = [float(v) for v in values]
    if len(vals) < 3:
        return False
    increases = 0
    decreases = 0
    for a, b in zip(vals, vals[1:]):
        if b > a + tolerance:
            increases += 1
        elif b < a - tolerance:
            decreases += 1
    # monotonic increase if mostly increasing and no significant decreases
    return increases >= max(2, int(0.6 * (len(vals) - 1))) and decreases == 0


def _rankdata(values: Sequence[float]) -> List[float]:
    indexed = sorted(enumerate(values), key=lambda x: x[1])
    ranks = [0.0] * len(values)
    i = 0
    while i < len(indexed):
        j = i
        while j + 1 < len(indexed) and indexed[j + 1][1] == indexed[i][1]:
            j += 1
        avg_rank = (i + j + 2) / 2.0  # 1-based average
        for k in range(i, j + 1):
            ranks[indexed[k][0]] = avg_rank
        i = j + 1
    return ranks


def mann_whitney_u(x: Sequence[float], y: Sequence[float]) -> Tuple[float, float]:
    """Mann-Whitney U test (two-sided) with normal approximation.

    Returns (U, p_value). U is statistic for x.
    """
    x = [float(v) for v in x]
    y = [float(v) for v in y]
    n1, n2 = len(x), len(y)
    if n1 == 0 or n2 == 0:
        return 0.0, 1.0
    all_vals = x + y
    ranks = _rankdata(all_vals)
    r1 = sum(ranks[:n1])
    u1 = r1 - n1 * (n1 + 1) / 2.0
    u2 = n1 * n2 - u1
    u = min(u1, u2)

    # tie correction
    tie_counts: Dict[float, int] = {}
    for v in all_vals:
        tie_counts[v] = tie_counts.get(v, 0) + 1
    tie_term = sum(t * t * t - t for t in tie_counts.values())
    n = n1 + n2
    mu = n1 * n2 / 2.0
    if n > 1:
        sigma_sq = (n1 * n2 / 12.0) * ((n + 1) - tie_term / (n * (n - 1)))
    else:
        sigma_sq = 0.0
    if sigma_sq <= 0:
        p = 1.0
    else:
        sigma = math.sqrt(sigma_sq)
        # continuity correction
        z = (abs(u1 - mu) - 0.5) / sigma
        p = math.erfc(z / math.sqrt(2.0))
    p = min(max(p, 0.0), 1.0)
    return float(u1), float(p)


def wasserstein_distance(x: Sequence[float], y: Sequence[float]) -> float:
    """1D Wasserstein (earth mover's) distance."""
    xs = sorted(float(v) for v in x)
    ys = sorted(float(v) for v in y)
    if not xs or not ys:
        return 0.0
    if len(xs) == len(ys):
        return sum(abs(a - b) for a, b in zip(xs, ys)) / len(xs)
    # quantile approximation for unequal sizes
    n = max(len(xs), len(ys))
    qs = [i / (n - 1) if n > 1 else 0.0 for i in range(n)]

    def q(vals: List[float], p: float) -> float:
        if len(vals) == 1:
            return vals[0]
        pos = p * (len(vals) - 1)
        lo = int(math.floor(pos))
        hi = int(math.ceil(pos))
        if lo == hi:
            return vals[lo]
        frac = pos - lo
        return vals[lo] + frac * (vals[hi] - vals[lo])

    return sum(abs(q(xs, p) - q(ys, p)) for p in qs) / n


def rank_biserial_correlation(x: Sequence[float], y: Sequence[float]) -> float:
    """Rank-biserial correlation from Mann-Whitney U.

    r = 1 - (2*U) / (n1*n2), where U is U1 for x. Range [-1,1].
    Positive means x tends larger than y.
    """
    x = [float(v) for v in x]
    y = [float(v) for v in y]
    n1, n2 = len(x), len(y)
    if n1 == 0 or n2 == 0:
        return 0.0
    u1, _ = mann_whitney_u(x, y)
    return 1.0 - (2.0 * u1) / (n1 * n2)


@dataclass
class OracleVerdict:
    significant: bool
    p_value: float
    wasserstein: float
    rank_biserial: float
    clean_n: int
    mutated_n: int
    throttling: bool
    reasons: List[str] = field(default_factory=list)


def evaluate_differential(
    clean: Sequence[float],
    mutated: Sequence[float],
    trim_fraction: float = 0.15,
    p_threshold: float = 0.01,
    r_threshold: float = 0.7,
) -> OracleVerdict:
    """Evaluate clean vs mutated latency samples with robust stats."""
    c = trim_upper_outliers(clean, trim_fraction)
    m = trim_upper_outliers(mutated, trim_fraction)
    reasons: List[str] = []
    throttling = is_monotonic_increase(clean) or is_monotonic_increase(mutated)
    if throttling:
        reasons.append("monotonic_latency_increase_waf_throttling")
    if len(c) < 3 or len(m) < 3:
        return OracleVerdict(False, 1.0, 0.0, 0.0, len(c), len(m), throttling, reasons + ["insufficient_samples"])

    _, p = mann_whitney_u(c, m)
    wd = wasserstein_distance(c, m)
    rbc = rank_biserial_correlation(m, c)  # positive when mutated > clean
    rbc_abs = abs(rbc)

    significant = (p < p_threshold) and (rbc_abs > r_threshold) and (not throttling)
    if p < p_threshold:
        reasons.append("mann_whitney_significant")
    if rbc_abs > r_threshold:
        reasons.append("rank_biserial_large")
    if wd > 0:
        reasons.append(f"wasserstein={wd:.4f}")
    return OracleVerdict(significant, p, wd, rbc, len(c), len(m), throttling, reasons)


# ---- TPE-like mutator selection ----

@dataclass
class MutationArm:
    name: str
    successes: int = 0
    failures: int = 0

    @property
    def trials(self) -> int:
        return self.successes + self.failures

    def score(self) -> float:
        # Beta posterior mean with small exploration bonus
        a = self.successes + 1.0
        b = self.failures + 1.0
        mean = a / (a + b)
        bonus = 0.5 / math.sqrt(self.trials + 1)
        return mean + bonus


class TPEMutatorSelector:
    """Lightweight TPE-like selector for mutation operators."""

    def __init__(self, mutations: Sequence[str], max_generations: int = 3, population_size: int = 30, top_k: int = 5, seed: int = 0):
        self.max_generations = max(1, int(max_generations))
        self.population_size = max(1, int(population_size))
        self.top_k = max(1, int(top_k))
        self.rng = random.Random(seed)
        self.arms: Dict[str, MutationArm] = {m: MutationArm(name=m) for m in mutations}
        self.generation = 0

    def update(self, mutation: str, success: bool) -> None:
        arm = self.arms.setdefault(mutation, MutationArm(name=mutation))
        if success:
            arm.successes += 1
        else:
            arm.failures += 1

    def ranked(self) -> List[MutationArm]:
        return sorted(self.arms.values(), key=lambda a: a.score(), reverse=True)

    def next_generation(self) -> List[str]:
        """Generate next population of mutation names within budget."""
        if self.generation >= self.max_generations:
            return []
        self.generation += 1
        ranked = self.ranked()
        top = [a.name for a in ranked[: self.top_k]]
        if not top:
            top = list(self.arms.keys())[: self.top_k]
        pop: List[str] = []
        # exploit top_k
        for i in range(self.population_size):
            if top and (i < int(self.population_size * 0.7) or len(self.arms) == len(top)):
                pop.append(top[i % len(top)])
            else:
                # explore: random from all
                pop.append(self.rng.choice(list(self.arms.keys())))
        self.rng.shuffle(pop)
        return pop

    def make_jobs(self, base_job: dict, target: str) -> List[dict]:
        """Create next-gen job dicts for omnislashd."""
        muts = self.next_generation()
        jobs = []
        for i, m in enumerate(muts):
            j = dict(base_job)
            j["name"] = f"{base_job.get('name','job')}-g{self.generation}-{i}-{m}"
            j["probe"] = "differential-fuzz"
            j["mutations"] = [m]
            j.setdefault("target", {})
            if isinstance(j["target"], dict):
                j["target"].setdefault("host", target)
            j["metadata"] = dict(j.get("metadata", {}))
            j["metadata"]["generation"] = self.generation
            j["metadata"]["mutation"] = m
            jobs.append(j)
        return jobs
