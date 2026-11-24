#!/usr/bin/env python3
import os
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from research.semantic_analyzer import (
    ResponseShape,
    TransitionTracker,
    classify_response_shape,
    normalized_compression_distance,
    skeleton_shift,
    structural_skeleton,
)


BASELINE = {
    "status": 200,
    "headers": [
        {"key": "Content-Type", "value": "text/html"},
        {"key": "Server", "value": "nginx"},
    ],
    "body": "<html><body><h1>Lab</h1><p>ok</p></body></html>",
}


class TestResponseShapes(unittest.TestCase):
    def test_queue_shifted_redirect_vs_parser_reject_vs_route_miss(self):
        shifted = {
            "status": 302,
            "headers": [{"key": "Location", "value": "https://exploit.example.test/resources/x"}],
            "body": "",
        }
        strict = {
            "status": 400,
            "headers": [{"key": "Content-Type", "value": "application/json"}],
            "body": '{"error":"Invalid request"}',
        }
        miss = {"status": 404, "headers": {}, "body": "Not Found"}

        result = classify_response_shape(
            shifted, role="victim", target_host="lab.example.test", baseline=BASELINE
        )
        self.assertIs(result.shape, ResponseShape.QUEUE_SHIFTED_REDIRECT)
        self.assertIn("h2_cl_queue_shifted", result.signals)
        self.assertEqual(result.location_host, "exploit.example.test")

        strict_result = classify_response_shape(strict, role="victim", baseline=BASELINE)
        self.assertIs(strict_result.shape, ResponseShape.PARSER_REJECT_STRICT)
        self.assertIn("parser_rejected_framing", strict_result.signals)

        miss_result = classify_response_shape(miss, role="victim", baseline=BASELINE)
        self.assertIs(miss_result.shape, ResponseShape.APP_ROUTE_MISS)
        self.assertIn("route_miss", miss_result.signals)

    def test_same_redirect_on_poison_stream_is_not_a_shift(self):
        shifted = {
            "status": 302,
            "headers": [{"key": "Location", "value": "https://exploit.example.test/resources/"}],
            "body": "",
        }
        result = classify_response_shape(
            shifted, role="poison", target_host="lab.example.test"
        )
        self.assertIsNot(result.shape, ResponseShape.QUEUE_SHIFTED_REDIRECT)

    def test_waf_deception_from_changed_infrastructure_signature(self):
        changed = {
            "status": 200,
            "headers": [{"key": "Server", "value": "honeypot-guard"}],
            "body": "<html><body>Mock admin</body></html>",
        }
        result = classify_response_shape(changed, role="victim", baseline=BASELINE)
        self.assertIs(result.shape, ResponseShape.WAF_OR_DECEPTION)
        self.assertIn("infrastructure_signature_changed", result.signals)

    def test_clean_baseline_stays_clean(self):
        result = classify_response_shape(BASELINE, role="victim", baseline=BASELINE)
        self.assertIs(result.shape, ResponseShape.CLEAN_BASELINE)
        self.assertLessEqual(normalized_compression_distance(BASELINE["body"], BASELINE["body"]), 1.0)


class TestStructuralSkeleton(unittest.TestCase):
    def test_json_keys_keep_structure_but_drop_dynamic_values(self):
        skeleton = structural_skeleton(
            '{"nonce":"abc123","data":[{"id":7,"name":"x","csrf_token":"t"}]}',
            "application/json",
        )
        self.assertEqual(skeleton["type"], "object")
        keys = skeleton["keys"]
        self.assertEqual(keys["nonce"], "dynamic")
        self.assertEqual(keys["data"]["items"][0]["keys"]["csrf_token"], "dynamic")
        self.assertEqual(keys["data"]["items"][0]["keys"]["id"], "num")

    def test_html_skeleton_tracks_tags_not_nonces(self):
        first = structural_skeleton('<html><body><script nonce="a1">x</script></body></html>', "text/html")
        second = structural_skeleton('<html><body><script nonce="b2">y</script></body></html>', "text/html")
        self.assertEqual(first["tags"], ["body", "html", "script"])
        self.assertEqual(first, second)
        self.assertEqual(skeleton_shift(first, second), 0.0)

    def test_skeleton_shift_detects_semantic_change(self):
        left = structural_skeleton('{"a":1,"b":2}', "application/json")
        right = structural_skeleton('{"a":1,"c":2}', "application/json")
        self.assertGreater(skeleton_shift(left, right), 0.0)


class TestTransitionTracker(unittest.TestCase):
    def test_only_confirmed_victim_shift_after_full_chain_is_success(self):
        shifted = {
            "status": 302,
            "headers": [{"key": "Location", "value": "https://exploit.example.test/resources/"}],
            "body": "",
        }
        tracker = TransitionTracker()
        self.assertIsNone(tracker.add("s1", "poison_sent", detail="smuggled CL 5"))
        self.assertIsNone(tracker.add("s1", "response_queued"))
        transition = tracker.add(
            "s1",
            "victim_response",
            response=shifted,
            role="victim",
            target_host="lab.example.test",
        )
        self.assertTrue(transition.confirmed)
        self.assertEqual(transition.chain, ["poison_sent", "response_queued", "victim_shifted"])
        self.assertEqual(transition.shape, ResponseShape.QUEUE_SHIFTED_REDIRECT.value)
        self.assertTrue(tracker.has_confirmed())

    def test_poison_send_alone_is_never_a_success(self):
        shifted = {
            "status": 302,
            "headers": [{"key": "Location", "value": "https://exploit.example.test/resources/"}],
            "body": "",
        }
        tracker = TransitionTracker()
        tracker.add("s2", "poison_sent")
        transition = tracker.add(
            "s2", "victim_response", response=shifted, role="victim", target_host="lab.example.test"
        )
        self.assertFalse(transition.confirmed)
        self.assertFalse(tracker.has_confirmed())

    def test_victim_404_does_not_confirm(self):
        tracker = TransitionTracker()
        tracker.add("s3", "poison_sent")
        tracker.add("s3", "response_queued")
        transition = tracker.add(
            "s3", "victim_response", response={"status": 404, "body": "Not Found"}, role="victim"
        )
        self.assertFalse(transition.confirmed)
        self.assertEqual(transition.shape, ResponseShape.APP_ROUTE_MISS.value)


if __name__ == "__main__":
    unittest.main(verbosity=2)
