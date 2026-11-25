#!/usr/bin/env python3
"""Beta-posterior integration tests for the Go FSM -> Python learning bridge."""

import json
import os
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from research.online_loop import OnlineLoop, parse_fsm_reward
from research.self_learning import (
    apply_beta_reward,
    load_weights,
    sample_beta,
    save_weights,
)


KEY = "tech:nginx|state:MUTATE_FRAMING|family:header_folding"


class FSMRewardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="omnislash-fsm-test-")
        self.addCleanup(self.tmp.cleanup)
        root = self.tmp.name
        self.audit = os.path.join(root, "audit.jsonl")
        self.weights_path = os.path.join(root, "learned_weights.json")
        save_weights({"global": {}, "hosts": {}, "tech": {}}, self.weights_path)
        self.loop = OnlineLoop(
            audit_path=self.audit,
            weights_path=self.weights_path,
            jobs_path=os.path.join(root, "jobs.json"),
            offset_path=os.path.join(root, "offset.json"),
            status_path=os.path.join(root, "status.json"),
            control_path=os.path.join(root, "control.json"),
        )

    def test_apply_beta_reward_uses_single_currency(self):
        weights = load_weights(self.weights_path)
        confirmed = apply_beta_reward(weights, KEY, alpha_delta=2.0, reward=2.0)
        self.assertEqual(confirmed["alpha"], 3.0)
        self.assertEqual(confirmed["beta"], 1.0)
        blocked = apply_beta_reward(weights, KEY, beta_delta=0.5, reward=-0.5)
        self.assertEqual(blocked["alpha"], 3.0)
        self.assertEqual(blocked["beta"], 1.5)
        cell = weights["beta"][KEY]
        self.assertEqual(cell["attempts"], 2)
        self.assertEqual(cell["last_reward"], -0.5)
        self.assertGreaterEqual(weights["online"]["fsm_rewards"], 2)

    def test_beta_parameters_never_reach_zero(self):
        weights = load_weights(self.weights_path)
        for _ in range(20):
            apply_beta_reward(weights, KEY, beta_delta=-10.0)
        self.assertGreaterEqual(weights["beta"][KEY]["beta"], 0.1)
        self.assertTrue(0.0 < sample_beta(weights, KEY) < 1.0)

    def test_parse_go_fsm_event(self):
        event = {
            "time": "2026-11-26T12:00:00Z",
            "attempt": 1,
            "orchestrator_state": "StateVerify",
            "fsm_phase": "VERIFY_VICTIM",
            "chosen_mutation": "header_folding",
            "reward": 2.0,
            "alpha_delta": 2.0,
            "beta_delta": 0.0,
            "learning": {"host": "lab.test", "tech_stack": "nginx"},
        }
        parsed = parse_fsm_reward(event)
        self.assertEqual(parsed["reward"], 2.0)
        self.assertTrue(parsed["key"].endswith("family:header_folding"))
        self.assertEqual(parsed["host"], "lab.test")
        self.assertIsNone(parse_fsm_reward({"time": "x", "attempt": 1}))
        # A follow-up transition with no reward must never move the posterior.
        self.assertIsNone(parse_fsm_reward({
            "time": "2026-11-26T12:00:01Z", "attempt": 1,
            "orchestrator_state": "StateVerify", "fsm_phase": "VERIFY_VICTIM",
            "chosen_mutation": "header_folding", "posterior_key": KEY,
        }))

    def test_online_loop_persists_go_rewards_atomically(self):
        events = [
            {
                "time": "2026-11-26T12:00:00Z", "job": "smuggle", "attempt": 1,
                "orchestrator_state": "StateFeedback", "fsm_phase": "MUTATE_FRAMING",
                "posterior_key": KEY, "chosen_mutation": "header_folding",
                "reward": 2.0, "alpha_delta": 2.0, "beta_delta": 0.0,
                "learning": {"host": "lab.test", "tech_stack": "nginx"},
            },
            {
                "time": "2026-11-26T12:00:01Z", "job": "smuggle", "attempt": 2,
                "orchestrator_state": "StateFeedback", "fsm_phase": "MUTATE_FRAMING",
                "posterior_key": KEY, "chosen_mutation": "header_folding",
                "reward": -0.5, "alpha_delta": 0.0, "beta_delta": 0.5,
                "learning": {"host": "lab.test", "tech_stack": "nginx"},
            },
        ]
        with open(self.audit, "w", encoding="utf-8") as handle:
            for event in events:
                handle.write(json.dumps(event) + "\n")
        self.assertEqual(self.loop.process_pending(), len(events))

        weights = load_weights(self.weights_path)
        cell = weights["beta"][KEY]
        self.assertEqual(cell["alpha"], 3.0)
        self.assertEqual(cell["beta"], 1.5)
        self.assertEqual(weights["online"]["fsm_rewards"], 2)
        self.assertEqual(load_weights(self.weights_path)["beta"][KEY], cell)


if __name__ == "__main__":
    unittest.main()
