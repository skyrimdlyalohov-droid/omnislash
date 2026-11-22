import unittest

from oracle import (
    TPEMutatorSelector,
    evaluate_differential,
    is_monotonic_increase,
    mann_whitney_u,
    rank_biserial_correlation,
    trim_upper_outliers,
    wasserstein_distance,
)


class TestTrimOutliers(unittest.TestCase):
    def test_trims_upper_15_percent(self):
        vals = list(range(100))  # 0..99
        trimmed = trim_upper_outliers(vals, 0.15)
        self.assertEqual(len(trimmed), 85)
        self.assertEqual(max(trimmed), 84)

    def test_small_input(self):
        self.assertEqual(trim_upper_outliers([1, 2, 3], 0.15), [1, 2, 3])


class TestMonotonic(unittest.TestCase):
    def test_increasing(self):
        self.assertTrue(is_monotonic_increase([1, 2, 3, 4, 5, 6]))

    def test_not_increasing(self):
        self.assertFalse(is_monotonic_increase([5, 4, 5, 4, 5, 4]))

    def test_short(self):
        self.assertFalse(is_monotonic_increase([1, 2]))


class TestMannWhitney(unittest.TestCase):
    def test_shifted_distributions(self):
        x = [1, 2, 3, 4, 5, 6, 7, 8]
        y = [10, 11, 12, 13, 14, 15, 16, 17]
        u, p = mann_whitney_u(x, y)
        self.assertLess(p, 0.01)

    def test_similar_distributions(self):
        x = [1, 2, 3, 4, 5, 6, 7, 8]
        y = [1, 2, 3, 4, 5, 6, 7, 8]
        _, p = mann_whitney_u(x, y)
        self.assertGreater(p, 0.05)


class TestWasserstein(unittest.TestCase):
    def test_identical(self):
        self.assertEqual(wasserstein_distance([1, 2, 3], [1, 2, 3]), 0.0)

    def test_shifted(self):
        d = wasserstein_distance([0, 0, 0], [1, 1, 1])
        self.assertAlmostEqual(d, 1.0, places=5)


class TestRankBiserial(unittest.TestCase):
    def test_strong_effect(self):
        x = [10, 11, 12, 13, 14]
        y = [1, 2, 3, 4, 5]
        r = rank_biserial_correlation(x, y)
        self.assertGreater(abs(r), 0.7)


class TestEvaluateDifferential(unittest.TestCase):
    def test_significant_signal(self):
        clean = [10, 11, 10, 12, 11, 10, 11, 12, 10, 11]
        mutated = [100, 110, 105, 120, 115, 108, 112, 118, 109, 111]
        verdict = evaluate_differential(clean, mutated)
        self.assertTrue(verdict.significant)
        self.assertLess(verdict.p_value, 0.01)
        self.assertGreater(abs(verdict.rank_biserial), 0.7)

    def test_no_signal(self):
        clean = [10, 11, 10, 12, 11, 10, 11, 12]
        mutated = [10, 11, 10, 12, 11, 10, 11, 12]
        verdict = evaluate_differential(clean, mutated)
        self.assertFalse(verdict.significant)

    def test_throttling_blocks(self):
        clean = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        mutated = [100, 110, 120, 130, 140, 150, 160, 170, 180, 190]
        verdict = evaluate_differential(clean, mutated)
        self.assertTrue(verdict.throttling)
        self.assertFalse(verdict.significant)


class TestTPESelector(unittest.TestCase):
    def test_budget_and_generations(self):
        sel = TPEMutatorSelector(["a", "b", "c", "d", "e", "f"], max_generations=3, population_size=30, top_k=5, seed=1)
        g1 = sel.next_generation()
        self.assertEqual(len(g1), 30)
        g2 = sel.next_generation()
        self.assertEqual(len(g2), 30)
        g3 = sel.next_generation()
        self.assertEqual(len(g3), 30)
        g4 = sel.next_generation()
        self.assertEqual(g4, [])

    def test_prefers_successful(self):
        sel = TPEMutatorSelector(["a", "b", "c"], max_generations=1, population_size=30, top_k=1, seed=1)
        for _ in range(10):
            sel.update("b", True)
            sel.update("a", False)
        pop = sel.next_generation()
        self.assertGreater(pop.count("b"), pop.count("a"))

    def test_make_jobs(self):
        sel = TPEMutatorSelector(["x", "y"], max_generations=1, population_size=2, top_k=2, seed=1)
        jobs = sel.make_jobs({"name": "base", "target": {"host": "example.com"}}, "example.com")
        self.assertEqual(len(jobs), 2)
        self.assertEqual(jobs[0]["probe"], "differential-fuzz")
        self.assertIn("mutation", jobs[0]["metadata"])


if __name__ == "__main__":
    unittest.main()
