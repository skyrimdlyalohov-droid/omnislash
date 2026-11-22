#!/usr/bin/env python3
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import filter_nuclei  # noqa: E402


class TestFilterNuclei(unittest.TestCase):
    def test_quarantines_suspicious_deception_marker(self):
        items = [{
            "host": "http://example.com",
            "status": "200",
            "matched-at": "http://example.com/admin",
            "info": {"name": "Admin panel"},
            "response": "welcome canarytoken=oastify.test",
        }]
        r = filter_nuclei.filter_findings(items)
        self.assertEqual(r["summary"]["clean_count"], 0)
        self.assertEqual(r["summary"]["quarantined_count"], 1)
        self.assertEqual(r["quarantined"][0]["_omnislash_filter"]["reason"], "suspicious_deception_marker")

    def test_quarantines_repeated_soft_404_pattern(self):
        items = []
        for i in range(6):
            items.append({
                "host": "http://example.com",
                "status": "200",
                "matched-at": f"http://example.com/path{i}",
                "info": {"name": "Generic Template"},
                "response": "ok",
            })
        r = filter_nuclei.filter_findings(items)
        self.assertEqual(r["summary"]["clean_count"], 0)
        self.assertEqual(r["summary"]["quarantined_count"], 6)

    def test_keeps_normal_finding(self):
        items = [{
            "host": "http://example.com",
            "status": "200",
            "matched-at": "http://example.com/.git/config",
            "info": {"name": "Git Config Exposure"},
            "response": "[core]",
        }]
        r = filter_nuclei.filter_findings(items)
        self.assertEqual(r["summary"]["clean_count"], 1)
        self.assertEqual(r["summary"]["quarantined_count"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)