#!/usr/bin/env python3
"""Omnislash OSIS — unit tests for scoring/sanitization/cache logic."""

import importlib.util
import ipaddress
import os
import sys
import tempfile
import unittest


def _load_engine():
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    engine_path = os.path.join(repo_root, "osint", "engine.py")
    spec = importlib.util.spec_from_file_location("omnislash_osint_engine", engine_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


engine = _load_engine()


class TestSanitizeHosts(unittest.TestCase):
    def test_strips_canary_and_wildcard(self):
        found = {"crtsh": {"good.example.com", "canarytokens.com", "*.wild.example.com"}}
        out = engine.sanitize_hosts(found)
        self.assertEqual(out["crtsh"], {"good.example.com"})


class TestScoring(unittest.TestCase):
    def test_two_verified_sources_confirmed(self):
        score = engine.score_confidence(["shodan", "censys"], [], False)
        self.assertEqual(score, 2)

    def test_single_source_weakly_confirmed(self):
        score = engine.score_confidence(["shodan"], [], False)
        self.assertEqual(score, 1)

    def test_honeypot_penalized(self):
        score = engine.score_confidence([], ["shodan"], False)
        self.assertEqual(score, -5)

    def test_waf_reduces_score(self):
        score = engine.score_confidence(["shodan"], [], True)
        self.assertEqual(score, -2)  # +1 confirmation - 3 behind_waf

    def test_behind_waf_detection(self):
        self.assertTrue(engine.is_behind_waf("104.16.0.5"))
        self.assertFalse(engine.is_behind_waf("8.8.8.8"))
        self.assertFalse(engine.is_behind_waf("not-an-ip"))


class TestCache(unittest.TestCase):
    def test_set_get_roundtrip_with_ttl(self):
        with tempfile.TemporaryDirectory() as td:
            engine.DB_PATH = os.path.join(td, "cache.sqlite3")
            engine.TTL_DAYS = 7
            engine.cache_set("k", {"crtsh": ["a.example.com"]})
            self.assertEqual(engine.cache_get("k"), {"crtsh": ["a.example.com"]})
            self.assertIsNone(engine.cache_get("missing"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
