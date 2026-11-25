#!/usr/bin/env python3
"""Integration tests for the closed-loop online learner.

The tests use temporary weights/audit files only: ``state/learned_weights.json``
in the repository is never touched.
"""

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from research.online_loop import OnlineLoop
from research.self_learning import (
    ExperienceLearner,
    ParameterInferencer,
    load_weights,
    local_simulations,
    save_weights,
)


def _load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _audit_record(attempt, *, host="sim-h2-a", cl=2, confirmed=False,
                  path="/resources", exit_ip="", proxy="", parser_reject=True):
    responses = []
    if confirmed:
        responses = [
            {"status": 200, "headers": [], "body": "baseline"},
            {
                "status": 302,
                "headers": [{"key": "location", "value": "https://exploit.example.test" + path}],
                "body": "",
            },
        ]
    elif parser_reject:
        responses = [{
            "status": 400,
            "headers": [{"key": "content-type", "value": "application/json"}],
            "body": '{"error":"Invalid request"}',
        }]
    record = {
        "time": "2026-11-25T12:00:%02dZ" % attempt,
        "job": "online-audit",
        "attempt": attempt,
        "target": "127.0.0.1:8443",
        "probe": "h2-cl",
        "tls": "h2",
        "success": confirmed,
        "learning": {"host": host, "tech_stack": "h2", "mutation": "cl=%d" % cl},
        "declared_length": cl,
        "result": {
            "exchanges": [{
                "raw": "GET %s HTTP/1.1\r\nContent-Length: %d\r\n\r\n" % (path, cl),
                "seq": 1,
            }],
            "responses": responses,
        },
    }
    if exit_ip:
        record["attribution"] = {
            "verified": True,
            "exit_ip": exit_ip,
            "proxy": proxy or exit_ip,
        }
    if confirmed:
        record["findings"] = [{
            "kind": "h2_cl_confirmed", "confidence": "high", "detail": "victim shifted"
        }]
    return record


class OnlineLoopTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="omnislash-online-test-")
        self.addCleanup(self.tmp.cleanup)
        root = self.tmp.name
        self.audit = os.path.join(root, "audit.jsonl")
        self.weights_path = os.path.join(root, "learned_weights.json")
        self.jobs_path = os.path.join(root, "jobs_online.json")
        self.offset_path = os.path.join(root, "offset.json")
        self.status_path = os.path.join(root, "status.json")
        self.control_path = os.path.join(root, "control.json")
        save_weights(ExperienceLearner().fit(local_simulations()), self.weights_path)
        self.loop = self.make_loop()
        self.thread = None

    def make_loop(self):
        return OnlineLoop(
            audit_path=self.audit,
            weights_path=self.weights_path,
            jobs_path=self.jobs_path,
            offset_path=self.offset_path,
            status_path=self.status_path,
            control_path=self.control_path,
            interval=0.02,
        )

    def tearDown(self):
        if self.thread is not None:
            self.loop.stop_event.set()
            self.thread.join(timeout=3)
            self.assertFalse(self.thread.is_alive(), "worker did not stop on request")

    def wait_for(self, predicate, timeout=5.0, message="condition"):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.02)
        self.fail("timed out waiting for " + message)

    def append(self, *records):
        with open(self.audit, "a", encoding="utf-8") as f:
            for record in records:
                f.write(json.dumps(record) + "\n")

    def test_streamed_negative_event_updates_weights_and_cl_ranking(self):
        before = load_weights(self.weights_path)
        cl_key = "cl:5"
        path_key = "path:/fresh-negative"
        attempts_before = before["global"][cl_key]["attempts"]
        learner = ExperienceLearner()
        score_before = learner._score_feature(before, path_key, "sim-h2-a", "h2")

        self.thread = threading.Thread(target=self.loop.run, daemon=True)
        self.thread.start()
        self.wait_for(lambda: os.path.exists(self.status_path), message="status file")
        self.append(_audit_record(1, cl=5, path="/fresh-negative"))

        def updated():
            if not os.path.exists(self.offset_path):
                return False
            weights = load_weights(self.weights_path)
            return weights["global"][cl_key]["attempts"] > attempts_before

        self.wait_for(updated, message="weights and offset update from audit")
        weights = load_weights(self.weights_path)
        self.assertIn(5, weights["negative"]["cl"])
        self.assertLess(learner._score_feature(weights, path_key, "sim-h2-a", "h2"), score_before)
        status = _load_json(self.status_path)
        self.assertEqual(status["state"], "ACTIVE")
        self.assertGreaterEqual(status["processed"], 1)
        offset = _load_json(self.offset_path)
        self.assertGreater(offset["offset"], 0)
        ranked = dict(ParameterInferencer(weights, target_host="sim-h2-a", tech_stack=["h2"])
                      .rank_cl_values(low=1, high=8))
        self.assertLess(ranked[5], 0.5)

    def test_confirmation_requires_two_verified_proxy_exits_for_strike_job(self):
        positive = _audit_record(
            1, cl=5, confirmed=True, path="/v2/legacy-redirect",
            exit_ip="198.51.100.7", proxy="proxy-a",
        )
        self.append(positive)
        self.loop.run(once=True)
        weights = load_weights(self.weights_path)
        score = ExperienceLearner()._score_feature(
            weights, "path:/v2/legacy-redirect", "sim-h2-a", "h2"
        )
        self.assertGreater(score, 0.5)
        jobs = _load_json(self.jobs_path)
        self.assertEqual(jobs["jobs"], [])
        self.assertEqual(len(jobs["candidates"]), 1)
        self.assertFalse(jobs["candidates"][0]["strike"])
        self.assertFalse(jobs["candidates"][0]["verified"])

        self.append(_audit_record(
            2, cl=5, confirmed=True, path="/v2/legacy-redirect",
            exit_ip="198.51.100.8", proxy="proxy-b",
        ))
        self.loop.run(once=True)
        jobs = _load_json(self.jobs_path)
        self.assertEqual(len(jobs["jobs"]), 1)
        strike = jobs["jobs"][0]
        self.assertTrue(strike["verified"])
        self.assertTrue(strike["strike"])
        self.assertEqual(len(strike["cross_proxy"]["identities"]), 2)
        self.assertTrue(strike["patch"]["success_finding"])
        self.assertEqual(strike["patch"]["declared_length"], 5)

    def test_holdout_host_never_enters_training_cells(self):
        weights = load_weights(self.weights_path)
        holdout_host = weights["holdout"]["hosts"][0]
        self.assertNotIn(holdout_host, weights["hosts"])
        cl_key = "cl:2"
        attempts_before = weights["global"][cl_key]["attempts"]

        self.append(_audit_record(1, host=holdout_host, cl=2))
        self.loop.run(once=True)
        after = load_weights(self.weights_path)
        self.assertEqual(after["global"][cl_key]["attempts"], attempts_before)
        self.assertNotIn(holdout_host, after["hosts"])
        self.assertEqual(after["online"]["holdout_skipped"], 1)
        self.assertFalse(os.path.exists(self.jobs_path))

    def test_manual_feedback_cli_applies_plus_and_minus_two(self):
        script = os.path.join(REPO_ROOT, "research", "self_learning.py")
        result = subprocess.run(
            [sys.executable, script, "feedback", "--confirm",
             "--features", '{"path:/manual-confirm":"1"}',
             "--weight", "2.0", "--out", self.weights_path],
            check=True, capture_output=True, text=True,
        )
        payload = json.loads(result.stdout)
        self.assertTrue(payload["applied"])
        self.assertEqual(payload["repeats"], 2)
        weights = load_weights(self.weights_path)
        cell = weights["global"]["path:/manual-confirm"]
        self.assertEqual(cell["attempts"], 2)
        self.assertEqual(cell["successes"], 2.0)
        self.assertEqual(weights["online"]["positive"], 2)

        subprocess.run(
            [sys.executable, script, "feedback", "--false-positive",
             "--features", '{"path:/manual-fp":"1"}',
             "--weight", "2.0", "--out", self.weights_path],
            check=True, capture_output=True, text=True,
        )
        weights = load_weights(self.weights_path)
        cell = weights["global"]["path:/manual-fp"]
        self.assertEqual(cell["attempts"], 2)
        self.assertEqual(cell["successes"], 0.0)
        self.assertEqual(cell["sources"], ["manual-false-positive"])
        self.assertEqual(weights["online"]["negative"], 2)


if __name__ == "__main__":
    unittest.main()
