#!/usr/bin/env python3
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import caido_bridge  # noqa: E402


class FakeClient:
    def __init__(self):
        self.calls = []

    def graphql(self, query, variables=None):
        self.calls.append((query, variables))
        return {"session": {"id": "s1"}}


class TestCaidoBridge(unittest.TestCase):
    def test_confirmed_finding_creates_replay_payload(self):
        rec = {
            "time": "2026-11-22T00:00:00Z",
            "job": "lab-clte",
            "target": "example.com:443",
            "probe": "smuggle-chain",
            "tls": "h1",
            "success": True,
            "statuses": [200],
            "attribution": {"proxy": "socks5://p1:1080"},
            "findings": [{"kind": "smuggle_confirmed", "confidence": "high"}],
            "result": {"responses": [{"raw": "HTTP/1.1 200 OK\r\n\r\nok"}]},
        }
        client = FakeClient()
        out = caido_bridge.process_records([rec], client)
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0]["ok"])
        self.assertEqual(out[0]["payload"]["proxy_label"], "socks5://p1:1080")
        self.assertEqual(out[0]["payload"]["finding"]["kind"], "smuggle_confirmed")

    def test_unverified_finding_skipped(self):
        rec = {
            "success": True,
            "job": "j1",
            "target": "t",
            "attribution": {"proxy": "p"},
            "findings": [{"kind": "cache_poisoned", "unverified": True}],
        }
        client = FakeClient()
        out = caido_bridge.process_records([rec], client)
        self.assertEqual(out, [])
        self.assertEqual(client.calls, [])

    def test_dedup_same_finding(self):
        rec = {
            "time": "t1",
            "success": True,
            "job": "j1",
            "target": "t",
            "attribution": {"proxy": "p"},
            "findings": [{"kind": "smuggle_confirmed"}],
        }
        client = FakeClient()
        seen = set()
        out1 = caido_bridge.process_records([rec], client, seen=seen)
        out2 = caido_bridge.process_records([rec], client, seen=seen)
        self.assertEqual(len(out1), 1)
        self.assertEqual(len(out2), 0)

    def test_unsuccessful_record_ignored(self):
        rec = {
            "success": False,
            "job": "j1",
            "target": "t",
            "attribution": {"proxy": "p"},
            "findings": [{"kind": "smuggle_confirmed"}],
        }
        client = FakeClient()
        out = caido_bridge.process_records([rec], client)
        self.assertEqual(out, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)