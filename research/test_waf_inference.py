import os
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from research.waf_inference import ActiveGrammarInferencer, WAFProfile, adapt_payload_for_waf, get_profile, load_profiles, save_profiles, upsert_profile


class TestWAFInference(unittest.TestCase):
    def test_reconstruct_rules(self):
        inf = ActiveGrammarInferencer("example.com")
        inf.record("space", "space", 200)
        inf.record("tab", "tab", 403)
        inf.record("nul", "nul", 400)
        inf.record("space_before_colon", "space_before_colon", 403)
        prof = inf.infer(headers={"server": "cloudflare"})
        self.assertEqual(prof.host, "example.com")
        self.assertTrue(prof.allowed_tokens.get("space"))
        self.assertTrue(prof.blocked_tokens.get("tab"))
        self.assertTrue(prof.blocked_tokens.get("nul"))
        self.assertFalse(prof.allowed_space_before_colon)
        self.assertEqual(prof.vendor, "cloudflare")

    def test_adapt_payload(self):
        prof = WAFProfile(
            host="example.com",
            blocked_tokens={"nul": True, "space_before_colon": True},
            allowed_tokens={"space": True},
            allowed_alt_whitespace=[" "],
        )
        payload = b"GET / HTTP/1.1\r\nHost : example.com\r\nX-Test: a\x00b\r\n\r\n"
        adapted = adapt_payload_for_waf(payload, prof)
        self.assertNotIn(b"\x00", adapted)
        self.assertNotIn(b"Host : example.com", adapted)
        self.assertIn(b"Host: example.com", adapted)

    def test_save_load_profiles(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "waf.json")
            store = load_profiles(path)
            prof = WAFProfile(host="example.com", vendor="akamai", blocked_tokens={"tab": True})
            upsert_profile(store, prof)
            save_profiles(store, path)
            loaded = load_profiles(path)
            got = get_profile(loaded, "example.com")
            self.assertIsNotNone(got)
            self.assertEqual(got.vendor, "akamai")
            self.assertTrue(got.blocked_tokens.get("tab"))


if __name__ == "__main__":
    unittest.main()
