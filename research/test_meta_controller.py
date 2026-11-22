import unittest

from meta_controller import WaldSPRT, compute_gittins_index, kelly_allocation, rank_targets


class TestGittins(unittest.TestCase):
    def test_higher_success_higher_index(self):
        low = compute_gittins_index(successes=1, failures=10, reward=1, cost=1)
        high = compute_gittins_index(successes=10, failures=1, reward=1, cost=1)
        self.assertGreater(high, low)

    def test_lower_cost_higher_index(self):
        cheap = compute_gittins_index(successes=5, failures=5, reward=1, cost=1)
        expensive = compute_gittins_index(successes=5, failures=5, reward=1, cost=10)
        self.assertGreater(cheap, expensive)

    def test_rank_targets(self):
        targets = [
            {"name": "a", "successes": 1, "failures": 20, "reward": 1, "cost": 1},
            {"name": "b", "successes": 20, "failures": 1, "reward": 1, "cost": 1},
        ]
        ranked = rank_targets(targets)
        self.assertEqual(ranked[0]["name"], "b")
        self.assertIn("gittins_index", ranked[0])


class TestWaldSPRT(unittest.TestCase):
    def test_accept_on_strong_signal(self):
        sprt = WaldSPRT(p0=0.05, p1=0.8, alpha=0.01, beta=0.01)
        result = None
        for _ in range(20):
            result = sprt.update(True)
        self.assertEqual(result.decision, "accept")

    def test_reject_on_no_signal(self):
        sprt = WaldSPRT(p0=0.05, p1=0.8, alpha=0.01, beta=0.01)
        result = None
        for _ in range(20):
            result = sprt.update(False)
        self.assertEqual(result.decision, "reject")

    def test_continue_initially(self):
        sprt = WaldSPRT(p0=0.05, p1=0.8, alpha=0.01, beta=0.01)
        result = sprt.update(True)
        self.assertIn(result.decision, {"continue", "accept", "reject"})

    def test_batch_update(self):
        sprt = WaldSPRT(p0=0.05, p1=0.8, alpha=0.01, beta=0.01)
        result = sprt.update_batch(successes=10, failures=0)
        self.assertEqual(result.decision, "accept")


class TestKelly(unittest.TestCase):
    def test_positive_edge(self):
        f = kelly_allocation(p=0.6, b=2.0)  # b=2 means 2:1 net odds
        self.assertGreater(f, 0)
        self.assertLessEqual(f, 1)

    def test_no_edge(self):
        self.assertEqual(kelly_allocation(p=0.1, b=1.0), 0.0)

    def test_invalid_b(self):
        self.assertEqual(kelly_allocation(p=0.9, b=0.0), 0.0)


if __name__ == "__main__":
    unittest.main()
