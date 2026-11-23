#!/usr/bin/env python3
import os
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from research.adaptive_prober import (
    AdaptiveProbePlanner,
    GroupTestSplitter,
    ProbeObservation,
    SyndromeDecoder,
    adaptive_observations_from_records,
    build_unkeyed_payload,
    distill_trigger,
    observation_triggered,
)


class TestGroupTestSplitter(unittest.TestCase):
    def test_localizes_one_unkeyed_header_from_64_in_log2(self):
        candidates = [f"X-Unkeyed-{i:02d}" for i in range(64)]
        active = "X-Unkeyed-37"
        calls = []

        def oracle(group):
            calls.append(list(group))
            triggered = active in group
            return ProbeObservation(
                triggered=triggered,
                ncd_delta=0.81 if triggered else 0.0,
                ttfb_residual_ms=90.0 if triggered else 1.0,
                headers={"X-Cache": "HIT"} if triggered else {},
            )

        splitter = GroupTestSplitter(oracle)
        result = splitter.run(candidates)
        self.assertEqual(result.active, [active])
        self.assertLessEqual(result.requests, 7)
        self.assertEqual(result.requests, 1 + 6)  # 64 -> 1 batch + log2(64)
        self.assertEqual(splitter.requests_used, result.requests)
        self.assertEqual(len(calls), result.requests)
        self.assertTrue(all(b["size"] >= 1 for b in result.batches))

    def test_clean_batch_rejected_in_one_request(self):
        splitter = GroupTestSplitter(lambda g: ProbeObservation(ncd_delta=0.0, status=200))
        result = splitter.run([f"H{i}" for i in range(32)])
        self.assertEqual(result.active, [])
        self.assertEqual(result.requests, 1)

    def test_threshold_uses_ncd_ttfb_and_header_shift(self):
        self.assertTrue(observation_triggered(ProbeObservation(ncd_delta=0.06)))
        self.assertTrue(observation_triggered(ProbeObservation(ttfb_residual_ms=30.0)))
        self.assertTrue(observation_triggered(ProbeObservation(header_changes={"etag": ["a", "b"]})))
        self.assertFalse(observation_triggered(ProbeObservation(status=200, ncd_delta=0.001, ttfb_residual_ms=1.0)))


class TestSyndromeDecoder(unittest.TestCase):
    def test_classifies_parser_cascades(self):
        decoder = SyndromeDecoder()
        cases = [
            (
                ProbeObservation(status=400, close_type="FIN", error_signature="400 Bad Request content-length transfer-encoding upstream"),
                "nginx", "gunicorn", "CL.TE",
            ),
            (
                ProbeObservation(status=400, close_type="RST", error_signature="invalid header transfer-encoding connection reset"),
                "haproxy", "nginx", "TE.CL",
            ),
            (
                ProbeObservation(status=400, close_type="FIN", error_signature="AkamaiGHost 400 Bad Request transfer-encoding bad request"),
                "akamai", "nginx", "TE.TE",
            ),
            (
                ProbeObservation(status=502, close_type="RST", headers={"CF-Ray": "abc", "X-Cache": "MISS"}, error_signature="502 Bad Gateway upstream timeout cloudflare", ncd_delta=0.7, ttfb_residual_ms=120),
                "cloudflare", "nginx", "H2_DOWNGRADE",
            ),
            (
                ProbeObservation(status=200, close_type="KEEPALIVE", headers={"X-Cache": "HIT", "ETag": "a", "Age": "5", "CF-Ray": "x"}, body="cached"),
                "cloudflare", "nginx", "CACHE_UNKEYED",
            ),
        ]
        for obs, fe, be, vector in cases:
            match = decoder.decode(obs)
            self.assertEqual((match.frontend_parser, match.backend_parser, match.vector), (fe, be, vector))
            self.assertGreaterEqual(match.score, 0.0)
            self.assertGreaterEqual(match.confidence, 0.0)

    def test_fin_and_rst_400_are_not_the_same_syndrome(self):
        decoder = SyndromeDecoder()
        fin = decoder.decode(ProbeObservation(status=400, close_type="FIN", error_signature="400 bad request content-length"))
        rst = decoder.decode(ProbeObservation(status=400, close_type="RST", error_signature="400 invalid header reset by peer"))
        self.assertNotEqual(fin.vector, rst.vector)
        self.assertEqual(fin.syndrome.close_types[0], "FIN")
        self.assertEqual(rst.syndrome.close_types[0], "RST")


class TestAdaptiveProbePlanner(unittest.TestCase):
    def test_entropy_decreases_and_prunes_impossible_branches(self):
        planner = AdaptiveProbePlanner(prune_threshold=0.03)
        before = planner.entropy()
        planner.observe("cache", True)
        planner.observe("h2", False)
        planner.observe("framing", False)
        after = planner.entropy()
        self.assertLess(after, before)
        self.assertLess(len(planner.posterior), 6)
        self.assertNotIn("CL.TE", planner.posterior)
        self.assertNotIn("TE.CL", planner.posterior)
        self.assertEqual(planner.top_hypothesis(), "CACHE_UNKEYED")
        self.assertTrue(any(v in planner.pruned for v in ["CL.TE", "TE.CL", "TE.TE"]))
        self.assertGreaterEqual(planner.information_gain(planner.action_by_name["framing"]), 0.0)

    def test_plan_is_compact_and_strikes_on_strong_posterior(self):
        target = {"target": "edge.example.com", "tech": ["cloudflare", "nginx"], "known_ports": [443], "impact": 7}
        planner = AdaptiveProbePlanner()
        plan = planner.plan(target, max_probes=7)
        self.assertLessEqual(plan.requested_probes, 7)
        self.assertTrue(plan.jobs)
        self.assertEqual(plan.jobs[0]["metadata"]["adaptive"]["action"] in {"framing", "upgrade", "h2", "cache", "unkeyed"}, True)

        planner2 = AdaptiveProbePlanner()
        strike = planner2.plan(
            target,
            observations={"framing": False, "h2": False, "upgrade": False, "cache": True, "unkeyed": False},
            max_probes=7,
            min_posterior=0.5,
        )
        self.assertEqual(len(strike.jobs), 1)
        self.assertEqual(strike.jobs[0]["metadata"]["adaptive"]["action"], "strike")
        self.assertEqual(strike.jobs[0]["metadata"]["adaptive"]["target_vector"], "CACHE_UNKEYED")

    def test_audit_record_mapping_prefers_triggered_observation(self):
        records = [
            {"job": "edge.example.com-adaptive-framing", "target": "edge.example.com:443", "success": False, "error": "", "result": {"responses": [{"status": 200}]}},
            {"job": "edge.example.com-adaptive-cache", "target": "edge.example.com:443", "success": True, "findings": [{"detail": "neighbor_shift ncd=0.8"}], "result": {"responses": [{"status": 200, "headers": [{"key": "X-Cache", "value": "HIT"}]}]}},
            {"job": "edge.example.com-adaptive-cache", "target": "edge.example.com:443", "success": False, "result": {"responses": [{"status": 200}]}},
        ]
        mapped = adaptive_observations_from_records(records)
        self.assertIn("edge.example.com", mapped)
        self.assertTrue(mapped["edge.example.com"]["actions"]["cache"])
        self.assertEqual(mapped["edge.example.com"]["observation"]["status"], 200)


class TestDistillTrigger(unittest.TestCase):
    def test_group_test_result_flows_to_ddmin_artifact(self):
        candidates = ["X-A", "X-B", "X-Forwarded-Host", "X-C"]

        def oracle(group):
            return {"triggered": "X-Forwarded-Host" in group, "ncd_delta": 0.7 if "X-Forwarded-Host" in group else 0.0}

        finding = {"kind": "cache_poisoned", "host": "edge.example.com", "confidence_score": 88, "cross_proxy_verifications": 2}
        request = {"method": "GET", "host": "edge.example.com", "path": "/", "headers": {"User-Agent": "omnislash", "Accept": "*/*"}}
        out = distill_trigger(candidates, oracle, finding, request)
        self.assertEqual(out["trigger"], "X-Forwarded-Host")
        self.assertLessEqual(out["requests"], 3)
        artifact = out["artifact"]
        self.assertEqual(artifact["schema"], "omnislash.minimal-artifact/v1")
        header_names = [h[0] for h in artifact["request"]["headers"]]
        self.assertIn("X-Forwarded-Host", header_names)
        self.assertEqual(out["finding"]["minimal_artifact"]["checksum_sha256"], artifact["checksum_sha256"])

    def test_unkeyed_payload_is_multiplexed(self):
        payload = build_unkeyed_payload("edge.example.com", ["X-A", "X-B"])
        text = payload.decode("utf-8")
        self.assertIn("GET / HTTP/1.1", text)
        self.assertIn("Host: edge.example.com", text)
        self.assertIn("X-A: omnislash-00", text)
        self.assertIn("X-B: omnislash-01", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
