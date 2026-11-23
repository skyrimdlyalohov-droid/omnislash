import json
import os
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from research.state_and_chains import (
    HAVE_Z3,
    ChainSynthesizer,
    StateGraphMiner,
    normalize_path,
    parse_raw_request,
    synthesize_chain,
)


LOGIN_RAW = "POST /api/login HTTP/1.1\r\nHost: shop.example\r\nContent-Length: 2\r\n\r\n"


def shop_records():
    return [
        {"id": "r1", "raw": LOGIN_RAW, "statusCode": 200, "timestamp": 1.0, "session": "s1"},
        {
            "id": "r2",
            "method": "POST",
            "path": "/api/cart/items/12345",
            "host": "shop.example",
            "statusCode": 200,
            "timestamp": 2.0,
            "session": "s1",
            "state_delta": {"cart": "+1"},
        },
        {
            "id": "r3",
            "method": "POST",
            "path": "/api/checkout",
            "host": "shop.example",
            "statusCode": 201,
            "timestamp": 3.0,
            "session": "s1",
            "delta": {"cart": "checked_out"},
        },
    ]


class TestStateGraphMiner(unittest.TestCase):
    def test_parses_raw_request(self):
        parsed = parse_raw_request(LOGIN_RAW)
        self.assertEqual(parsed["method"], "POST")
        self.assertEqual(parsed["path"], "/api/login")
        self.assertEqual(parsed["host"], "shop.example")
        self.assertEqual(parsed["headers"]["content-length"], "2")

    def test_normalizes_volatile_ids(self):
        self.assertEqual(normalize_path("/api/items/12345?x=1#frag"), "/api/items/{id}")
        self.assertEqual(normalize_path("/u/550e8400-e29b-41d4-a716-446655440000"), "/u/{uuid}")
        self.assertEqual(normalize_path("/blob/deadbeefcafebabe00"), "/blob/{hex}")

    def test_builds_state_graph_and_critical_transitions(self):
        miner = StateGraphMiner().add_records(shop_records())
        doc = miner.to_dict()
        self.assertEqual(doc["sessions"], 1)
        self.assertEqual(doc["records"], 3)
        self.assertEqual(doc["nodes"], ["S_0", "S_1", "S_2", "S_3"])
        self.assertEqual(len(doc["transitions"]), 3)
        self.assertEqual(len(doc["critical"]), 3)
        self.assertEqual(miner.node_labels()["S_1"], {"session": "authenticated"})
        self.assertEqual(miner.node_labels()["S_3"], {"cart": "checked_out"})
        checkout = miner.critical_transitions()[-1]
        self.assertEqual(checkout.path, "/api/checkout")
        self.assertTrue(checkout.critical)
        self.assertEqual(checkout.request_ids, ["r3"])

    def test_race_tasks_have_last_byte_sync_and_preconditions(self):
        miner = StateGraphMiner().add_records(shop_records())
        tasks = miner.race_tasks()
        self.assertEqual(len(tasks), 3)
        task = next(t for t in tasks if t["race"]["path"] == "/api/checkout")
        self.assertEqual(task["kind"], "cross-state-race")
        self.assertEqual(task["sync"], "last-byte")
        self.assertEqual(task["replicas"], 2)
        preconditions = [p["path"] for p in task["preconditions"]]
        self.assertEqual(preconditions, ["/api/login", "/api/cart/items/{id}"])

    def test_deterministic_output(self):
        a = StateGraphMiner().add_records(shop_records()).to_json()
        b = StateGraphMiner().add_records(list(reversed(shop_records()))).to_json()
        self.assertEqual(a, b)
        json.loads(a)

    def test_sessions_merge_and_count_edges(self):
        base = shop_records()
        recs = list(base)
        recs += [
            dict(rec, id="s2-" + str(rec["id"]), session="s2", timestamp=float(rec["timestamp"]) + 10.0)
            for rec in base
        ]
        miner = StateGraphMiner().add_records(recs)
        doc = miner.to_dict()
        self.assertEqual(doc["sessions"], 2)
        self.assertEqual(doc["nodes"], ["S_0", "S_1", "S_2", "S_3"])
        cart_edges = [t for t in miner.transitions() if t.path == "/api/cart/items/{id}"]
        self.assertEqual(len(cart_edges), 1)  # both sessions share the same state edge
        self.assertEqual(cart_edges[0].count, 2)
        checkout = next(t for t in miner.transitions() if t.path == "/api/checkout")
        self.assertEqual(checkout.count, 2)

    def test_state_goal_lookup(self):
        miner = StateGraphMiner().add_records(shop_records())
        goal = miner.find_state_goal("cart", "checked_out")
        self.assertIsNotNone(goal)
        self.assertEqual(goal["state"], "S_3")
        self.assertIsNone(miner.find_state_goal("cart", "unknown"))

    def test_skips_invalid_records(self):
        miner = StateGraphMiner().add_records([{"id": "bad"}, {"id": "bad2", "raw": ""}])
        self.assertEqual(miner.to_dict()["nodes"], ["S_0"])
        self.assertEqual(miner.critical_transitions(), [])

    def test_parses_json_state_delta(self):
        miner = StateGraphMiner().add_records([
            {
                "id": "j1",
                "method": "POST",
                "path": "/api/cart/items/9",
                "statusCode": 200,
                "state_delta": '{"cart": "+1"}',
            }
        ])
        self.assertEqual(miner.node_labels()["S_1"], {"cart": "+1"})
        self.assertEqual(len(miner.critical_transitions()), 1)

    def test_export_shape(self):
        miner = StateGraphMiner()
        miner.add_export({"requests": shop_records()})
        self.assertEqual(miner.to_dict()["records"], 3)
        miner2 = StateGraphMiner()
        miner2.add_export(shop_records())
        self.assertEqual(miner2.to_dict()["records"], 3)


class TestChainSynthesizer(unittest.TestCase):
    def findings(self):
        return [
            {"id": "f1", "kind": "parse_discrepancy", "host": "shop.example", "path": "/"},
            {"id": "f2", "kind": "unkeyed_header", "host": "shop.example", "path": "/"},
            {"id": "f3", "kind": "origin_ip", "host": "shop.example", "path": "/"},
            {"id": "f4", "kind": "unrelated_rule", "host": "shop.example", "path": "/"},
        ]

    def test_combines_three_anomalies_into_content_control(self):
        result = synthesize_chain(self.findings(), "origin_content_control")
        self.assertTrue(result["reachable"])
        self.assertEqual([f["id"] for f in result["findings"]], ["f1", "f2", "f3"])
        self.assertEqual(result["chain"], result["findings"])
        self.assertIn("cache_poison", result["derived"])
        self.assertIn("origin_content_control", result["derived"])
        self.assertEqual(result["engine"], "z3" if HAVE_Z3 else "bfs")
        rules = [s["rule"] for s in result["steps"]]
        self.assertIn("parser_divergence+cache_key_gap -> cache_poison", rules)
        self.assertIn("cache_poison+origin_reachable -> origin_content_control", rules)
        self.assertEqual(result["skipped"], [])

    def test_any_of_goal_and_minimal_subset(self):
        result = synthesize_chain(self.findings(), ["origin_takeover", "origin_desync"])
        self.assertTrue(result["reachable"])
        self.assertEqual(sorted(f["id"] for f in result["findings"]), ["f1", "f3"])
        self.assertIn("origin_desync", result["derived"])

    def test_quarantined_findings_are_skipped(self):
        findings = self.findings()
        findings[0]["unverified"] = True
        result = synthesize_chain(findings, "origin_content_control")
        self.assertFalse(result["reachable"])
        self.assertEqual(len(result["skipped"]), 1)
        self.assertEqual(result["skipped"][0]["reason"], "quarantined")

    def test_unreachable_goal(self):
        result = synthesize_chain(self.findings(), "database_dump")
        self.assertFalse(result["reachable"])
        self.assertEqual(result["findings"], [])

    def test_empty_findings(self):
        result = ChainSynthesizer().synthesize("origin_content_control")
        self.assertFalse(result["reachable"])
        self.assertEqual(result["capabilities"], [])

    def test_explicit_capabilities_override_kind(self):
        result = synthesize_chain(
            [{"id": "x1", "kind": "custom", "capabilities": ["parser_divergence", "cache_key_gap", "origin_reachable"]}],
            "origin_content_control",
        )
        self.assertTrue(result["reachable"])
        self.assertEqual([f["id"] for f in result["findings"]], ["x1"])

    def test_state_transition_is_attached(self):
        miner = StateGraphMiner().add_records(shop_records())
        synth = ChainSynthesizer(self.findings())
        result = synth.synthesize(
            "origin_content_control",
            miner=miner,
            state_key="cart",
            state_value="checked_out",
        )
        self.assertTrue(result["reachable"])
        self.assertIsNotNone(result["state_transition"])
        self.assertEqual(result["state_transition"]["state"], "S_3")

    def test_deterministic_json(self):
        a = synthesize_chain(self.findings(), "origin_content_control")
        b = synthesize_chain(list(reversed(self.findings())), "origin_content_control")
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
