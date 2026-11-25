#!/usr/bin/env python3
import json
import os
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from research.semantic_analyzer import ResponseShape
from research.self_learning import (
    OUTCOME_PROXY_FAILED,
    OUTCOME_TARGET_REJECTED,
    OUTCOME_WAF_BLOCKED,
    TrainingExample,
    ExperienceLearner,
    LinUCB,
    ParameterInferencer,
    apply_online_example,
    build_calibration_examples,
    examples_from_audit,
    local_simulations,
    outcome_label,
    split_by_host,
    trainable_outcome,
)


class TestAutonomousParameterInference(unittest.TestCase):
    def setUp(self):
        self.examples = local_simulations()
        self.weights = ExperienceLearner().fit(self.examples)

    def test_simulations_are_independent_of_curated_playbook(self):
        for example in self.examples:
            self.assertFalse("solution-derived" in example.source.lower())
            self.assertFalse(any("playbook:" in str(v).lower() for v in example.features.values()))
        self.assertTrue(any(ex.label > 0 for ex in self.examples))

    def test_infers_working_cl_4_to_8_and_rejects_negative_cl_1_to_3(self):
        inferencer = ParameterInferencer(self.weights, target_host="sim-h2-a", tech_stack=["h2"])
        ranking = dict(inferencer.rank_cl_values(low=1, high=8))
        top = [cl for cl, _ in inferencer.rank_cl_values(low=1, high=8)[:5]]

        self.assertTrue(set(top).issubset(set(range(4, 9))))
        self.assertTrue(all(ranking[cl] > 0.5 for cl in range(4, 9)))
        self.assertTrue(all(ranking[cl] < 0.0 for cl in (1, 2, 3)))
        self.assertIn("duplicate_cl:1", self.weights["negative"]["timing"])
        self.assertIn("timing.victim_delay:5s", self.weights["negative"]["timing"])

    def test_adaptive_search_walks_parser_reject_to_queue_shift(self):
        def evaluate(cl):
            if cl <= 3:
                return ResponseShape.PARSER_REJECT_STRICT.value
            if cl <= 8:
                return ResponseShape.QUEUE_SHIFTED_REDIRECT.value
            return ResponseShape.CLEAN_BASELINE.value

        observations = ParameterInferencer.adaptive_cl_search(evaluate, low=1, high=16)
        shapes = [shape for _, shape in observations]
        self.assertIn(ResponseShape.PARSER_REJECT_STRICT.value, shapes)
        self.assertIn(ResponseShape.QUEUE_SHIFTED_REDIRECT.value, shapes)
        self.assertLessEqual(len(observations), 4)

    def test_inference_emits_autonomous_provenance_and_no_negative_cl(self):
        inferencer = ParameterInferencer(self.weights, target_host="sim-h2-a", tech_stack=["h2"])
        hypotheses = inferencer.infer([], max_hypotheses=6)
        self.assertTrue(hypotheses)
        self.assertTrue(all(h["provenance"] == "autonomous-inferred" for h in hypotheses))
        self.assertEqual(hypotheses[0]["smuggled_path"], "/resources")
        self.assertTrue(4 <= hypotheses[0]["smuggled_cl"] <= 8)
        self.assertTrue(all(h["smuggled_cl"] >= 4 for h in hypotheses))
        self.assertLessEqual(len(hypotheses), 6)
        self.assertGreaterEqual(len(hypotheses), 1)


class TestExperienceLearning(unittest.TestCase):
    def test_exact_host_experience_overrides_global_seed_prior(self):
        weights = {
            "global": {
                "path:/resources": {
                    "attempts": 5,
                    "successes": 0.0,
                    "ema": 0.0,
                    "sources": ["solution-derived"],
                }
            },
            "hosts": {
                "lab-a": {
                    "path:/resources": {
                        "attempts": 4,
                        "successes": 4.0,
                        "ema": 1.0,
                        "sources": ["caido-confirmed"],
                    }
                }
            },
            "tech": {},
        }
        learner = ExperienceLearner(exact_weight=0.8)
        prior_score = learner.score(weights, ["path:/resources"], host="other-lab")
        exact_score = learner.score(weights, ["path:/resources"], host="lab-a")
        self.assertLessEqual(prior_score, 0.5)
        self.assertGreater(exact_score, 0.8)
        self.assertGreater(exact_score, prior_score)

    def test_host_holdout_has_no_overlap_with_training(self):
        examples = local_simulations()
        train, validation, holdout_hosts = split_by_host(examples, holdout_fraction=0.2)
        train_hosts = {ex.host for ex in train if ex.host != "*"}
        validation_hosts = {ex.host for ex in validation}

        self.assertTrue(holdout_hosts)
        self.assertFalse(train_hosts & validation_hosts)
        self.assertEqual(validation_hosts, set(holdout_hosts))

        weights = ExperienceLearner().fit(examples, holdout_fraction=0.2)
        self.assertFalse(set(weights["hosts"]) & set(holdout_hosts))
        metrics = weights["holdout"]["metrics"]
        self.assertEqual(metrics["hosts"], holdout_hosts)
        self.assertGreaterEqual(metrics["accuracy"], 0.0)

    def test_fit_reports_train_example_count_excluding_holdout(self):
        examples = local_simulations()
        train, validation, _holdout = split_by_host(examples, 0.2)
        weights = ExperienceLearner().fit(examples, 0.2)
        self.assertEqual(len(train), weights["examples"])
        self.assertEqual(len(validation), weights["holdout"]["validation_examples"])

    def test_audit_ingestion_uses_confirmed_transition_and_negative_cl(self):
        record = {
            "job": "h2-cl-resources-cl5",
            "attempt": 1,
            "probe": "h2-cl",
            "tls": "h2",
            "learning": {"host": "lab-a", "tech_stack": "h2"},
            "result": {
                "exchanges": [{"raw": "POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nx=1"}],
                "responses": [
                    {"status": 200, "body": "ok"},
                    {
                        "status": 302,
                        "headers": [{"key": "Location", "value": "https://exploit.test/resources/"}],
                        "body": "",
                    },
                ],
            },
        }
        negative = dict(record)
        negative["job"] = "h2-cl-resources-cl1"
        negative["result"] = {
            "exchanges": [{"raw": "POST / HTTP/1.1\r\nContent-Length: 1\r\n\r\nx"}],
            "responses": [{"status": 400, "body": '{"error":"Invalid request"}'}],
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "daemon-audit.jsonl")
            with open(path, "w", encoding="utf-8") as handle:
                for rec in (record, negative):
                    handle.write(json.dumps(rec) + "\n")
            examples = examples_from_audit(path, fallback_host="lab-a")

        positives = [ex for ex in examples if ex.label > 0]
        negatives = [ex for ex in examples if ex.label <= 0]
        self.assertTrue(positives)
        self.assertTrue(negatives)
        self.assertTrue(any(ex.features.get("negative_reason") == "cl_too_short" for ex in negatives))
        self.assertTrue(all(ex.source.startswith("audit:") for ex in examples))

    def test_build_calibration_examples_combines_audits_and_simulations(self):
        with tempfile.TemporaryDirectory() as tmp:
            audit = os.path.join(tmp, "daemon-audit.jsonl")
            with open(audit, "w", encoding="utf-8") as handle:
                handle.write(json.dumps({"probe": "h2-cl", "result": {"responses": [{"status": 200, "body": "ok"}]}}) + "\n")
            examples = build_calibration_examples([audit], simulate=True)
        self.assertTrue(any(ex.source.startswith("audit:") for ex in examples))
        self.assertTrue(any(ex.source.startswith("local-simulator:") for ex in examples))

    def test_linucb_ranks_rewarded_arm_first(self):
        bandit = LinUCB(dimension=32, alpha=1.0)
        context = {"probe": "h2-cl", "cl": 5}
        bandit.update("cl:5", context, 1.0)
        bandit.update("cl:1", context, 0.0)
        ranked = bandit.rank(["cl:1", "cl:5"], context)
        self.assertEqual(ranked[0], "cl:5")


class TestOutcomeAwareLearning(unittest.TestCase):
    def test_outcome_label_separates_transport_failures_from_target_responses(self):
        self.assertEqual(outcome_label({"error": "no usable proxy"}), OUTCOME_PROXY_FAILED)
        self.assertEqual(
            outcome_label({"outcome": "Proxy Failed", "result": {"responses": [{"status": 200}]}}),
            OUTCOME_PROXY_FAILED,
        )
        self.assertEqual(
            outcome_label({"result": {"responses": [
                {"status": 403, "body": "captcha challenge", "headers": [{"key": "cf-ray", "value": "x"}]},
            ]}}),
            OUTCOME_WAF_BLOCKED,
        )
        self.assertEqual(
            outcome_label({"result": {"responses": [
                {"status": 400, "body": '{"error":"Invalid request"}'},
            ]}}),
            OUTCOME_TARGET_REJECTED,
        )
        self.assertEqual(
            outcome_label({"result": {"responses": [{"status": 200, "body": "ok"}]}}),
            "Target Response",
        )
        self.assertFalse(trainable_outcome(OUTCOME_PROXY_FAILED))
        self.assertTrue(trainable_outcome(OUTCOME_WAF_BLOCKED))

    def test_proxy_failure_audit_events_never_become_training_examples(self):
        with tempfile.TemporaryDirectory() as tmp:
            audit = os.path.join(tmp, "audit.jsonl")
            records = [
                {"probe": "h2-cl", "outcome": "Proxy Failed", "error": "dial failed"},
                {"probe": "h2-cl", "error": "connection reset"},
            ]
            with open(audit, "w", encoding="utf-8") as handle:
                for record in records:
                    handle.write(json.dumps(record) + "\n")
            self.assertEqual(examples_from_audit(audit, fallback_host="lab-a"), [])
            with open(audit, "w", encoding="utf-8") as handle:
                handle.write(json.dumps({"probe": "h2-cl", "outcome": "WAF Blocked",
                                         "result": {"responses": [{"status": 403, "body": "captcha"}]}}) + "\n")
            examples = examples_from_audit(audit, fallback_host="lab-a")
            self.assertEqual(len(examples), 1)
            self.assertTrue(examples[0].label < 0.5)

    def test_weak_strength_nudges_weights_without_faking_observations(self):
        weights = ExperienceLearner(alpha=0.3).fit(local_simulations())
        examples_before = weights["examples"]
        example = TrainingExample(
            host="weak-lab", tech="h2",
            features={"path:/weak-signal": "1", "cl:5": "1"},
            label=1.0, source="online-audit",
        )
        result = apply_online_example(weights, example, strength=0.25)
        self.assertTrue(result["applied"])
        self.assertEqual(result["strength"], 0.25)
        cell = weights["global"]["path:/weak-signal"]
        self.assertEqual(cell["attempts"], 1)
        self.assertAlmostEqual(cell["successes"], 0.25)
        self.assertLess(cell["ema"], 0.5)
        self.assertEqual(weights["online"]["last_strength"], 0.25)
        self.assertEqual(weights["examples"], examples_before + 1)

        full = ExperienceLearner(alpha=0.3).fit(local_simulations())
        apply_online_example(full, example, strength=1.0)
        strong = full["global"]["path:/weak-signal"]
        self.assertEqual(strong["attempts"], cell["attempts"])
        self.assertAlmostEqual(strong["successes"], 1.0)
        self.assertGreater(strong["ema"], cell["ema"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
