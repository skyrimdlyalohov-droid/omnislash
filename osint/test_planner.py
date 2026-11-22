#!/usr/bin/env python3
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import planner  # noqa: E402


class TestPlanner(unittest.TestCase):
    def test_excludes_honeypot_and_high_deception(self):
        targets = [
            {"target": "a.example.com", "is_honeypot": True, "deception_risk": "high", "tech": ["Nginx"], "cache_headers": {"x-cache": "HIT"}},
            {"target": "b.example.com", "is_honeypot": False, "deception_risk": "high", "tech": ["Nginx"]},
            {"target": "c.example.com", "is_honeypot": False, "deception_risk": "low", "tech": ["Nginx"], "cache_headers": {"age": "1"}, "known_ports": [443]},
        ]
        cfg = planner.build_daemon_config(targets)
        hosts = cfg["generated_scope"]["allow_hosts"]
        self.assertNotIn("a.example.com", hosts)
        self.assertNotIn("b.example.com", hosts)
        self.assertIn("c.example.com", hosts)

    def test_cache_headers_h2_generates_h2_tunnel(self):
        t = {
            "target": "cache.example.com",
            "is_honeypot": False,
            "deception_risk": "low",
            "tech": ["Cloudflare", "Nginx"],
            "cache_headers": {"cf-cache-status": "HIT", "age": "10"},
            "known_ports": [443],
            "baseline": {"status_code": 200, "content_length": 100, "words": 10, "lines": 5, "title_hash": "abc"},
        }
        jobs = planner.plan_target(t)
        probes = [j["probe"] for j in jobs]
        self.assertIn("h2-tunnel", probes)
        jt = next(j for j in jobs if j["probe"] == "h2-tunnel")
        self.assertEqual(jt["success_finding"], "cache_poisoned")
        self.assertEqual(jt["tls"], "h2")
        self.assertEqual(jt["metadata"]["baseline"]["status_code"], 200)

    def test_reverse_proxy_generates_smuggle(self):
        t = {
            "target": "rp.example.com",
            "is_honeypot": False,
            "deception_risk": "low",
            "tech": ["Nginx", "HAProxy"],
            "cache_headers": {},
            "known_ports": [443],
        }
        jobs = planner.plan_target(t)
        probes = [j["probe"] for j in jobs]
        self.assertIn("smuggle-chain", probes)
        self.assertTrue(any(j["probe"] == "smuggle" and j.get("variant") == "h2-downgrade" for j in jobs))

    def test_critical_endpoints_generate_h2race_limited(self):
        t = {
            "target": "api.example.com",
            "is_honeypot": False,
            "deception_risk": "low",
            "tech": ["Envoy"],
            "cache_headers": {},
            "known_ports": [443],
            "critical_endpoints": ["/api/v1/transfer", "/api/v1/reset", "/api/v1/otp", "/api/v1/extra"],
        }
        jobs = planner.plan_target(t)
        races = [j for j in jobs if j["probe"] == "h2race"]
        self.assertEqual(len(races), 3)  # limited to 3
        self.assertTrue(all(j["attempts"] == 1 for j in races))
        self.assertTrue(all(j["until_success"] is False for j in races))

    def test_scope_fail_closed_only_selected(self):
        targets = [
            {"target": "good.example.com", "is_honeypot": False, "deception_risk": "low", "tech": ["Nginx"], "cache_headers": {"age": "1"}},
            {"target": "no-signal.example.com", "is_honeypot": False, "deception_risk": "low", "tech": ["Unknown"], "cache_headers": {}},
        ]
        cfg = planner.build_daemon_config(targets)
        allow = cfg["generated_scope"]["allow_hosts"]
        self.assertIn("good.example.com", allow)
        self.assertNotIn("no-signal.example.com", allow)


if __name__ == "__main__":
    unittest.main(verbosity=2)