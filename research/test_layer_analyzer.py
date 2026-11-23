import os
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from research.layer_analyzer import LayerSpectrometer, MetadataDDT, NormalizationSynthesizer
from research.waf_inference import WAFProfile


class TestLayerSpectrometer(unittest.TestCase):
    def test_classifies_cdn_envoy_nginx_stack(self):
        spec = LayerSpectrometer()
        spec.observe(
            "baseline",
            200,
            {
                "Server": "nginx",
                "Via": "1.1 envoy",
                "X-Envoy-Upstream-Service-Time": "7",
                "CF-Ray": "8f1a-SJC",
                "X-Cache": "HIT",
                "Age": "3",
            },
        )
        probs = spec.classify()
        self.assertAlmostEqual(sum(probs.values()), 1.0, places=6)
        self.assertEqual(list(probs.values()), sorted(probs.values(), reverse=True))
        self.assertGreater(probs["cdn"], probs["haproxy"])
        self.assertGreater(probs["envoy"], 0.0)
        self.assertGreater(probs["nginx"], 0.0)

    def test_information_gain_from_marker_split(self):
        spec = LayerSpectrometer()
        spec.observe("waf-check", 403, {"Server": "cloudflare"})
        spec.observe("waf-check", 403, {"Server": "cloudflare"})
        spec.observe("app-read", 200, {"Server": "nginx"})
        spec.observe("app-read", 200, {"Server": "nginx"})
        self.assertGreater(spec.information_gain(), 0.9)
        self.assertEqual(spec.information_gain([]), 0.0)

    def test_information_gain_zero_when_status_uniform(self):
        spec = LayerSpectrometer()
        for marker in ("a", "b", "c"):
            spec.observe(marker, 200, {})
        self.assertEqual(spec.information_gain(), 0.0)

    def test_empty_classification(self):
        self.assertEqual(LayerSpectrometer().classify(), {})


class TestMetadataDDT(unittest.TestCase):
    def test_detects_changed_and_unkeyed_headers(self):
        ddt = MetadataDDT()
        baseline = {
            "X-Request-ID": "req-1",
            "ETag": "etag-a",
            "Vary": "Accept-Encoding",
            "Age": "0",
        }
        variant = {
            "x-request-id": "req-2",
            "etag": "etag-b",
            "vary": "Accept-Encoding",
            "age": "12",
            "x-cache": "HIT",
        }
        diff = ddt.compare(baseline, variant)
        self.assertEqual(diff["changed"]["x-request-id"]["baseline"], "req-1")
        self.assertEqual(diff["changed"]["etag"]["variant"], "etag-b")
        self.assertEqual(diff["added"]["x-cache"], "HIT")
        self.assertIn("x-request-id", diff["unkeyed_candidates"])
        self.assertIn("etag", diff["unkeyed_candidates"])
        self.assertIn("age", diff["unkeyed_candidates"])

    def test_unkeyed_inputs_over_sequence(self):
        ddt = MetadataDDT()
        seq = [
            {"ETag": "a", "X-Request-ID": "1"},
            {"ETag": "b", "X-Request-ID": "2"},
            {"ETag": "c", "X-Request-ID": "3"},
        ]
        self.assertEqual(ddt.unkeyed_inputs(seq), ["etag", "x-request-id"])
        self.assertEqual(len(ddt.analyze_sequence(seq)), 2)

    def test_removed_headers(self):
        diff = MetadataDDT().compare({"X-Cache": "HIT", "Age": "1"}, {})
        self.assertIn("x-cache", diff["removed"])
        self.assertIn("age", diff["removed"])


class TestNormalizationSynthesizer(unittest.TestCase):
    def test_synthesizes_parser_divergence_cases(self):
        profile = WAFProfile(
            host="example.com",
            blocked_tokens={
                "space_before_colon": True,
                "tab": True,
                "nul": True,
                "chunk_ext": True,
            },
            allowed_alt_whitespace=[" "],
        )
        tests = NormalizationSynthesizer(profile).synthesize()
        names = {t["name"] for t in tests}
        self.assertIn("colon_no_space", names)
        self.assertIn("colon_tab", names)
        self.assertIn("tab_to_space", names)
        self.assertIn("nul_removed", names)
        self.assertIn("chunk_ext_alt", names)
        for t in tests:
            self.assertTrue(t["rationale"])
        self.assertEqual(NormalizationSynthesizer(profile).equivalent_whitespace(), [" "])

    def test_baseline_when_no_blocked_tokens(self):
        profile = WAFProfile(host="example.com")
        tests = NormalizationSynthesizer(profile).synthesize()
        self.assertEqual([t["name"] for t in tests], ["baseline_identity"])

    def test_accepts_serialized_profile_dict(self):
        profile = {
            "host": "example.com",
            "blocked_tokens": {"nul": True},
            "allowed_alt_whitespace": ["\t"],
        }
        synth = NormalizationSynthesizer(profile)
        self.assertEqual([t["name"] for t in synth.synthesize()], ["nul_removed"])
        self.assertEqual(synth.equivalent_whitespace(), ["\t"])

    def test_equivalent_whitespace_defaults(self):
        self.assertEqual(NormalizationSynthesizer(WAFProfile(host="x")).equivalent_whitespace(), [" "])


if __name__ == "__main__":
    unittest.main()
