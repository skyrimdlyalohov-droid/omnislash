import json
import os
import tempfile
import unittest

from diff_scanner import diff_targets, fingerprint, load_targets


class TestDiffScanner(unittest.TestCase):
    def test_new_and_changed(self):
        prev = [{"target": "a.example", "ip": "1.1.1.1", "tech": ["nginx"], "known_ports": [443]}]
        cur = [
            {"target": "a.example", "ip": "1.1.1.1", "tech": ["nginx", "envoy"], "known_ports": [443]},
            {"target": "b.example", "ip": "2.2.2.2", "tech": ["apache"], "known_ports": [80]},
        ]
        fresh, stats = diff_targets(cur, prev)
        self.assertEqual(stats["new"], 1)
        self.assertEqual(stats["changed"], 1)
        self.assertEqual(stats["unchanged"], 0)
        kinds = {t["target"]: t["_diff"] for t in fresh}
        self.assertEqual(kinds["a.example"], "changed")
        self.assertEqual(kinds["b.example"], "new")

    def test_unchanged(self):
        prev = [{"target": "a.example", "ip": "1.1.1.1", "tech": ["nginx"]}]
        cur = [{"target": "a.example", "ip": "1.1.1.1", "tech": ["nginx"]}]
        fresh, stats = diff_targets(cur, prev)
        self.assertEqual(len(fresh), 0)
        self.assertEqual(stats["unchanged"], 1)

    def test_fingerprint_ignores_order(self):
        a = {"target": "a", "tech": ["b", "a"], "known_ports": [443, 80]}
        b = {"target": "a", "tech": ["a", "b"], "known_ports": [80, 443]}
        self.assertEqual(fingerprint(a), fingerprint(b))

    def test_load_targets(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "t.json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump([{"target": "x"}], f)
            self.assertEqual(len(load_targets(p)), 1)


if __name__ == "__main__":
    unittest.main()
