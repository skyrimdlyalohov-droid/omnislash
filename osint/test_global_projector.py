import os
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from osint.global_projector import censys_query, match_targets, rank_by_gittins, shodan_query
from research.knowledge_base import add_universal_key


class TestGlobalProjector(unittest.TestCase):
    def test_queries(self):
        tech = ["nginx", "python", "h1.1"]
        self.assertIn("nginx", shodan_query(tech))
        q = censys_query(tech)
        self.assertIn("services.software.product", q)

    def test_match_targets(self):
        targets = [
            {"target": "a.com", "tech": ["nginx", "python", "h1.1"], "known_ports": [443]},
            {"target": "b.com", "tech": ["apache", "php"], "known_ports": [443]},
            {"target": "c.com", "tech": ["nginx", "python", "h1.1", "redis"], "known_ports": [443]},
        ]
        matched = match_targets(targets, "nginx+python+h1.1")
        hosts = {t["target"] for t in matched}
        self.assertEqual(hosts, {"a.com", "c.com"})

    def test_rank_by_gittins(self):
        targets = [
            {"target": "low", "confidence_score": 0},
            {"target": "high", "confidence_score": 100},
        ]
        ranked = rank_by_gittins(targets)
        self.assertEqual(ranked[0]["target"], "high")
        self.assertIn("gittins_index", ranked[0])


if __name__ == "__main__":
    unittest.main()
