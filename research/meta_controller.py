"""Meta-controller for OmniSlash Echelon 1.

Provides Gittins index ranking, Wald SPRT early stopping, and Kelly allocation.
Stdlib only.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import List, Optional


def compute_gittins_index(
    successes: float,
    failures: float,
    reward: float = 1.0,
    cost: float = 1.0,
    discount: float = 0.95,
) -> float:
    """Compute a Gittins-like index for a Bernoulli arm.

    Uses a discounted Beta-posterior approximation:
      p_hat = (s+1)/(s+f+2)
      exploration = sqrt(p_hat*(1-p_hat)/(s+f+3)) * sqrt(2*log(1/(1-discount)))
      index = (reward * (p_hat + exploration)) / max(cost, eps)

    Higher is better. This balances expected reward, uncertainty, and cost.
    """
    s = max(0.0, float(successes))
    f = max(0.0, float(failures))
    reward = max(0.0, float(reward))
    cost = max(1e-9, float(cost))
    discount = min(max(discount, 1e-6), 0.999999)
    n = s + f
    p_hat = (s + 1.0) / (n + 2.0)
    uncertainty = math.sqrt(p_hat * (1.0 - p_hat) / (n + 3.0))
    # discount factor amplifies exploration when future matters
    disc_bonus = math.sqrt(2.0 * math.log(1.0 / (1.0 - discount)))
    expected = reward * min(1.0, p_hat + uncertainty * disc_bonus)
    return expected / cost


@dataclass
class SPRTResult:
    decision: str  # "accept", "reject", "continue"
    log_lr: float
    upper: float
    lower: float
    observations: int


class WaldSPRT:
    """Wald Sequential Probability Ratio Test.

    H0: p = p0 (noise/uninteresting)
    H1: p = p1 (signal/interesting)
    alpha: false positive rate, beta: false negative rate.
    """

    def __init__(self, p0: float = 0.05, p1: float = 0.8, alpha: float = 0.01, beta: float = 0.01):
        if not (0 < p0 < 1 and 0 < p1 < 1):
            raise ValueError("p0 and p1 must be in (0,1)")
        if p0 >= p1:
            raise ValueError("p1 must be > p0")
        if not (0 < alpha < 1 and 0 < beta < 1):
            raise ValueError("alpha and beta must be in (0,1)")
        self.p0 = p0
        self.p1 = p1
        self.alpha = alpha
        self.beta = beta
        # Wald thresholds: A = (1-beta)/alpha, B = beta/(1-alpha)
        self.A = (1.0 - beta) / alpha
        self.B = beta / (1.0 - alpha)
        self.upper = math.log(self.A)
        self.lower = math.log(self.B)
        self.log_lr = 0.0
        self.observations = 0

    def reset(self) -> None:
        self.log_lr = 0.0
        self.observations = 0

    def update(self, success: bool) -> SPRTResult:
        """Update with one Bernoulli observation. success=True means signal."""
        self.observations += 1
        if success:
            llr_inc = math.log(self.p1 / self.p0)
        else:
            llr_inc = math.log((1.0 - self.p1) / (1.0 - self.p0))
        self.log_lr += llr_inc
        return self.result()

    def update_batch(self, successes: int, failures: int) -> SPRTResult:
        for _ in range(max(0, int(successes))):
            self.update(True)
        for _ in range(max(0, int(failures))):
            self.update(False)
        return self.result()

    def result(self) -> SPRTResult:
        if self.log_lr >= self.upper:
            decision = "accept"
        elif self.log_lr <= self.lower:
            decision = "reject"
        else:
            decision = "continue"
        return SPRTResult(
            decision=decision,
            log_lr=self.log_lr,
            upper=self.upper,
            lower=self.lower,
            observations=self.observations,
        )


def kelly_allocation(p: float, b: float) -> float:
    """Compute Kelly fraction f* = (p*b - q) / b.

    p: probability of win/success
    b: net odds received on win (reward/risk - 1, or payout multiple)
    Returns 0 when not advantageous.
    """
    p = min(max(float(p), 0.0), 1.0)
    b = float(b)
    if b <= 0:
        return 0.0
    q = 1.0 - p
    f = (p * b - q) / b
    if f <= 0:
        return 0.0
    # cap at 1.0 for safety (full budget)
    return min(1.0, f)


def rank_targets(targets: List[dict], discount: float = 0.95) -> List[dict]:
    """Rank targets by Gittins index descending.

    Each target dict may contain: successes, failures, reward, cost, name/id.
    Returns new list with 'gittins_index' added.
    """
    out = []
    for t in targets:
        idx = compute_gittins_index(
            successes=t.get("successes", 0),
            failures=t.get("failures", 0),
            reward=t.get("reward", 1.0),
            cost=t.get("cost", 1.0),
            discount=discount,
        )
        item = dict(t)
        item["gittins_index"] = idx
        out.append(item)
    out.sort(key=lambda x: x["gittins_index"], reverse=True)
    return out
