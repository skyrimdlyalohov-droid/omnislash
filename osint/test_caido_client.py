#!/usr/bin/env python3
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import caido_client  # noqa: E402


class FakeResp:
    def __init__(self, payload):
        self._b = json.dumps(payload).encode("utf-8")

    def read(self):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class TestCaidoClient(unittest.TestCase):
    def test_export_unified_normalizes_findings(self):
        c = caido_client.CaidoClient(url="http://127.0.0.1:8080/graphql", pat="test")
        payloads = [
            {"data": {"findings": {"nodes": [{"id": "1", "title": "X", "severity": "HIGH", "host": "example.com", "path": "/admin"}]}}},
            {"data": {"requestsByHTTPQL": {"nodes": [{"id": "r1", "host": "example.com", "path": "/admin"}]}}},
        ]

        def fake_urlopen(req, timeout=30):
            return FakeResp(payloads.pop(0))

        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            report = c.export_unified(httpql="host:\"example.com\"", limit=10)
        self.assertEqual(report["source"], "caido")
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["findings"][0]["severity"], "high")
        self.assertEqual(report["requests"][0]["id"], "r1")

    def test_graphql_error_raises(self):
        c = caido_client.CaidoClient(url="http://127.0.0.1:8080/graphql", pat="bad")
        with mock.patch("urllib.request.urlopen", return_value=FakeResp({"errors": [{"message": "nope"}]})):
            with self.assertRaises(caido_client.CaidoAPIError):
                c.graphql("query{__typename}")


if __name__ == "__main__":
    unittest.main(verbosity=2)