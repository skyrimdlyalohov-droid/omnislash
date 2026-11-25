#!/usr/bin/env python3
"""Tests for the Docker-free localhost proxy/backend calibration corpus."""

import json
import os
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from research.native_pair_corpus import (  # noqa: E402
    BACKEND_SCENARIOS,
    GO_SCENARIOS,
    GO_VARIANTS,
    VARIANTS,
    build_native_pair_records,
    write_jsonl,
)
from research.self_learning import (  # noqa: E402
    ExperienceLearner,
    build_calibration_examples,
    examples_from_training_jsonl,
    split_by_host,
)
from research.waf_negative_templates import waf_negative_jsonl_records  # noqa: E402


class TestWafNegativeTemplates(unittest.TestCase):
    def test_all_canonical_stubs_and_clean_noise_are_forced_negative(self):
        records = waf_negative_jsonl_records()
        vendors = {
            key.split(":", 1)[1]
            for record in records
            for key in record["features"]
            if key.startswith("waf_vendor:")
        }
        templates = {
            key.split(":", 1)[1]
            for record in records
            for key in record["features"]
            if key.startswith("waf_template:")
        }
        self.assertTrue({"cloudflare", "akamai", "aws-waf", "qrator", "nginx"}.issubset(vendors))
        self.assertTrue({"clean-noise", "route-miss-noise"}.issubset(templates))
        for record in records:
            self.assertEqual(0.0, float(record["label"]))
            self.assertIn("negative", record["tags"])
            self.assertIn("negative-template", record["tags"])
            self.assertEqual("0", record["features"]["confirmed_finding"])
            self.assertEqual("1", record["features"]["not_finding"])
            self.assertEqual("1", record["features"]["enforced_negative"])

    def test_forced_negative_tags_override_a_positive_jsonl_label(self):
        forced = {
            "host": "waf-stub-cloudflare",
            "tech": "waf",
            "features": {
                "shape": "QUEUE_SHIFTED_REDIRECT",
                "finding:smuggle_confirmed": "1",
                "waf_vendor:cloudflare": "1",
            },
            "label": 1.0,
            "source": "manual",
            "confidence": 1.0,
            "tags": ["waf-stub"],
        }
        ordinary = {
            "host": "native-pair-queue",
            "tech": "h2",
            "features": {"shape": "QUEUE_SHIFTED_REDIRECT", "cl:5": "1"},
            "label": 1.0,
            "source": "native-pair:proxy-backend",
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "training.jsonl")
            with open(path, "w", encoding="utf-8") as handle:
                for record in (forced, ordinary):
                    handle.write(json.dumps(record) + "\n")
            examples = examples_from_training_jsonl(path)

        self.assertEqual(0.0, examples[0].label)
        self.assertEqual("waf_stub", examples[0].features["negative_reason"])
        self.assertEqual("0", examples[0].features["confirmed_finding"])
        self.assertEqual("1", examples[0].features["not_finding"])
        self.assertEqual(1.0, examples[1].label)
        self.assertNotIn("enforced_negative", examples[1].features)


class TestNativePairCorpus(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = build_native_pair_records()

    def test_local_pair_corpus_is_deterministic_and_contrastive(self):
        self.assertEqual(self.records, build_native_pair_records())
        positives = [r for r in self.records if r["label"] > 0]
        negatives = [r for r in self.records if r["label"] <= 0]
        self.assertTrue(positives)
        self.assertGreater(len(negatives), len(positives))

        self.assertTrue(all(r["features"].get("role:victim") == "1" for r in positives))
        self.assertTrue(any(r["features"].get("shape") == "QUEUE_SHIFTED_REDIRECT" for r in positives))
        self.assertTrue(any(r["features"].get("negative_reason") == "parser_reject" for r in negatives))
        self.assertTrue(any(int(r["features"].get("status:502", "0")) == 1 for r in negatives))

        scenarios = {
            key.split(":", 1)[1]
            for record in self.records
            for key in record["features"]
            if key.startswith("scenario:")
        }
        self.assertTrue(set(BACKEND_SCENARIOS).issubset(scenarios))
        self.assertTrue(set(GO_SCENARIOS).issubset(scenarios))
        variants = {
            key.split(":", 1)[1]
            for record in self.records
            for key in record["features"]
            if key.startswith("variant:")
        }
        self.assertTrue(set(VARIANTS).issubset(variants))
        self.assertTrue(set(GO_VARIANTS).issubset(variants))
        self.assertTrue(any(r["host"].startswith("pair-backend-") for r in self.records))
        self.assertTrue(any(r["host"].startswith("pair-go-") for r in self.records))
        self.assertTrue(any("go-net/http" in r["metadata"]["backend"] for r in self.records))
        self.assertTrue(any("python-http.server" in r["metadata"]["backend"] for r in self.records))
        self.assertTrue(any(r["host"].startswith("native-pair-waf-") for r in self.records))

        waf_records = [r for r in self.records if "waf-stub" in r.get("tags", [])]
        self.assertTrue(waf_records)
        self.assertTrue(all(float(r["label"]) == 0.0 for r in waf_records))

    def test_jsonl_ingestion_keeps_strict_host_holdout_and_train_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "native_pair_corpus.jsonl")
            write_jsonl(self.records, path)
            examples = build_calibration_examples([], training_jsonl=[path], simulate=True)
            ingested = examples_from_training_jsonl(path)

        self.assertEqual(len(self.records), len(ingested))
        self.assertTrue(all(
            e.label == 0.0 for e in ingested
            if any(k.startswith("waf_vendor:") for k in e.features)
        ))

        train, validation, holdout = split_by_host(examples, 0.2)
        train_hosts = {e.host for e in train if e.host not in {"*", ""}}
        validation_hosts = {e.host for e in validation}
        self.assertTrue(holdout)
        self.assertFalse(train_hosts & validation_hosts)
        self.assertEqual(set(holdout), validation_hosts)
        self.assertTrue(all(host.startswith(("pair-backend-", "pair-go-", "native-pair-waf-", "sim-h2-")) for host in holdout))

        weights = ExperienceLearner().fit(examples, 0.2)
        self.assertEqual(len(train), weights["examples"])
        self.assertFalse(set(weights["hosts"]) & set(holdout))
        self.assertEqual(len(validation), weights["holdout"]["validation_examples"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
