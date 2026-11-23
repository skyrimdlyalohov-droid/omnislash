import base64
import os
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from research.game_arbitrage import (
    WeibullArbitrageScorer,
    artifact_to_finding,
    build_minimal_artifact,
    ddmin,
    is_one_minimal,
    minimize_request,
    minimal_artifact_for_finding,
)


class TestWeibullArbitrageScorer(unittest.TestCase):
    def test_survival_decays_with_age(self):
        s = WeibullArbitrageScorer(shape=1.5, scale_seconds=3600.0)
        self.assertEqual(s.survival(0), 1.0)
        self.assertGreater(s.survival(60), s.survival(600))
        self.assertGreater(s.survival(600), s.survival(3600))

    def test_kelly_score_fresh_high_impact(self):
        s = WeibullArbitrageScorer(min_sniper_pool=2)
        score = s.score(impact=10.0, age_seconds=0.0, probability=0.8, odds=2.0, sniper_pool=5)
        self.assertEqual(score.survival, 1.0)
        self.assertAlmostEqual(score.kelly, 0.7, places=6)
        self.assertAlmostEqual(score.score, 7.0, places=6)
        self.assertEqual(score.scarcity, 0.0)
        self.assertEqual(score.penalty, 1.0)

    def test_sniper_pool_scarcity_penalty(self):
        s = WeibullArbitrageScorer(min_sniper_pool=2, sniper_penalty_weight=0.75)
        healthy = s.score(10.0, 0.0, 0.8, 2.0, sniper_pool=2)
        scarce = s.score(10.0, 0.0, 0.8, 2.0, sniper_pool=0)
        self.assertEqual(healthy.scarcity, 0.0)
        self.assertEqual(scarce.scarcity, 1.0)
        self.assertGreater(scarce.penalty, healthy.penalty)
        self.assertLess(scarce.kelly, healthy.kelly)
        self.assertLess(scarce.score, healthy.score)
        self.assertAlmostEqual(scarce.effective_odds, 2.0 / 1.75, places=6)

    def test_negative_edge_has_zero_kelly(self):
        s = WeibullArbitrageScorer(min_sniper_pool=0)
        score = s.score(100.0, 0.0, 0.1, 1.0, sniper_pool=0)
        self.assertEqual(score.kelly, 0.0)
        self.assertEqual(score.score, 0.0)

    def test_score_task_resolves_age_and_confidence(self):
        s = WeibullArbitrageScorer(scale_seconds=86400.0)
        score = s.score_task(
            {
                "id": "diff-1",
                "impact": 8,
                "confidence": 90,
                "odds": 3,
                "discovered_at": 400,
                "sniper_pool": 4,
            },
            now=1000,
        )
        self.assertEqual(score.task_id, "diff-1")
        self.assertAlmostEqual(score.age_seconds, 600.0)
        self.assertAlmostEqual(score.probability, 0.9)
        self.assertGreater(score.score, 0.0)

    def test_rank_is_deterministic_and_descending(self):
        s = WeibullArbitrageScorer(min_sniper_pool=1)
        tasks = [
            {"id": "b", "impact": 5, "p_success": 0.7, "odds": 2, "age_seconds": 0},
            {"id": "a", "impact": 9, "p_success": 0.7, "odds": 2, "age_seconds": 0},
            {"id": "c", "impact": 9, "p_success": 0.7, "odds": 2, "age_seconds": 0},
        ]
        ranked = s.rank(tasks, sniper_pool=3)
        self.assertEqual([r["task_id"] for r in ranked], ["a", "c", "b"])
        self.assertGreaterEqual(ranked[0]["score"]["score"], ranked[1]["score"]["score"])
        self.assertEqual(ranked, s.rank(list(reversed(tasks)), sniper_pool=3))


class TestDdmin(unittest.TestCase):
    def test_bytes_minimised_to_marker(self):
        payload = b"HEADER noise AAA SECRET BBB more noise CCC"
        pred = lambda p: b"SECRET" in p
        out = ddmin(payload, pred)
        self.assertIn(b"SECRET", out)
        self.assertLess(len(out), len(payload))
        self.assertTrue(is_one_minimal(out, pred))

    def test_string_payload(self):
        out = ddmin("hello ANOMALY world", lambda p: "ANOMALY" in p)
        self.assertEqual(out, "ANOMALY")

    def test_header_list_payload(self):
        headers = [("Host", "x"), ("X-Exploit", "1"), ("X-Noise", "y"), ("Accept", "*/*")]
        pred = lambda hs: dict(hs).get("X-Exploit") == "1"
        out = ddmin(headers, pred)
        self.assertEqual(out, [("X-Exploit", "1")])
        self.assertTrue(is_one_minimal(out, pred))

    def test_no_reproduction_returns_original(self):
        payload = b"unchanged"
        self.assertEqual(ddmin(payload, lambda p: False), payload)
        self.assertEqual(ddmin(payload, lambda p: 1 / 0), payload)

    def test_empty_payload(self):
        self.assertEqual(ddmin(b"", lambda p: True), b"")
        self.assertEqual(ddmin([], lambda p: True), [])

    def test_is_one_minimal_detects_redundancy(self):
        self.assertFalse(is_one_minimal(b"SECRETx", lambda p: b"SECRET" in p))
        self.assertTrue(is_one_minimal(b"SECRET", lambda p: b"SECRET" in p))


class TestMinimalArtifact(unittest.TestCase):
    def finding(self):
        return {
            "kind": "cache_poisoned",
            "host": "shop.example",
            "proxy_label": "exit-17",
            "attribution": {"proxy": "exit-17"},
            "job": "cache-probe",
        }

    def request(self):
        return {
            "method": "GET",
            "host": "shop.example",
            "path": "/api/items/12345",
            "headers": {
                "Host": "shop.example",
                "X-Exploit": "1",
                "X-Noise": "drop-me",
                "Accept": "*/*",
            },
            "body": b"padding AAA MARKER BBB padding",
        }

    def test_minimizes_headers_and_body(self):
        def pred(req):
            return dict(req["headers"]).get("X-Exploit") == "1" and b"MARKER" in req["body"]

        minimal = minimize_request(self.request(), pred)
        self.assertEqual(minimal.headers, [("X-Exploit", "1")])
        self.assertEqual(minimal.body, b"MARKER")

    def test_builds_deterministic_artifact(self):
        def pred(req):
            return dict(req["headers"]).get("X-Exploit") == "1" and b"MARKER" in req["body"]

        art = build_minimal_artifact(self.finding(), self.request(), test_fn=pred)
        self.assertEqual(art["schema"], "omnislash.minimal-artifact/v1")
        self.assertEqual(art["request"]["body_b64"], base64.b64encode(b"MARKER").decode("ascii"))
        self.assertEqual(art["request"]["body_len"], 6)
        self.assertEqual(art["request"]["headers"], [["X-Exploit", "1"]])
        self.assertEqual(art["attribution"]["proxy_label"], "exit-17")
        self.assertEqual(art["response_diff"], [])
        self.assertEqual(len(art["checksum_sha256"]), 64)
        self.assertEqual(art["reproduction"]["tool"], "caido_replay")
        self.assertIn("steps", art["reproduction"])

        again = build_minimal_artifact(self.finding(), self.request(), test_fn=pred)
        self.assertEqual(art, again)

    def test_without_test_fn_keeps_request_intact(self):
        art = build_minimal_artifact(self.finding(), self.request(), response_diff=[{"header": "x-cache"}])
        self.assertEqual(art["request"]["body_len"], len(self.request()["body"]))
        self.assertEqual(len(art["request"]["headers"]), 4)
        self.assertEqual(art["response_diff"], [{"header": "x-cache"}])

    def test_artifact_to_finding_shape(self):
        art = build_minimal_artifact(self.finding(), self.request())
        finding = artifact_to_finding(art, confidence_score=91, cross_proxy_verifications=2)
        self.assertEqual(finding["kind"], "cache_poisoned")
        self.assertEqual(finding["path"], "/api/items/12345")
        self.assertEqual(finding["confidence_score"], 91)
        self.assertEqual(finding["cross_proxy_verifications"], 2)
        self.assertIs(finding["minimal_artifact"], art)
        self.assertIn(art["checksum_sha256"][:16], finding["detail"])

    def test_convenience_wrapper(self):
        art = minimal_artifact_for_finding(self.finding(), request=self.request())
        self.assertEqual(art["host"], "shop.example")

    def test_checksum_changes_with_payload(self):
        a = build_minimal_artifact(self.finding(), self.request())
        req = dict(self.request())
        req["body"] = b"different"
        b = build_minimal_artifact(self.finding(), req)
        self.assertNotEqual(a["checksum_sha256"], b["checksum_sha256"])


if __name__ == "__main__":
    unittest.main()
