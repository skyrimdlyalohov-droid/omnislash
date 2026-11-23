import json
import os
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from research.knowledge_base import add_universal_key, find_keys_for_stack, load_vault, save_vault, tech_stack_hash
from osint.planner import build_daemon_config


class TestKnowledgeBase(unittest.TestCase):
    def test_save_and_find_key(self):
        with tempfile.TemporaryDirectory() as td:
            vault_path = os.path.join(td, "vault.json")
            vault = load_vault(vault_path)
            entry = add_universal_key(
                vault,
                raw_payload=b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
                mutation_type="cl_te",
                protocol_edge="h1->h1",
                tech_stack=["envoy", "gunicorn"],
                source="incubator",
                confidence=0.95,
            )
            save_vault(vault, vault_path)
            loaded = load_vault(vault_path)
            self.assertEqual(len(loaded.get("keys", [])), 1)
            found = find_keys_for_stack(loaded, ["envoy", "gunicorn"])
            self.assertEqual(found[0]["id"], entry["id"])
            self.assertEqual(found[0]["tech_stack_hash"], "envoy+gunicorn")

    def test_transfer_to_planner(self):
        with tempfile.TemporaryDirectory() as td:
            vault_path = os.path.join(td, "vault.json")
            vault = load_vault(vault_path)
            add_universal_key(
                vault,
                raw_payload=b"GET / HTTP/1.1\r\nHost: target\r\n\r\n",
                mutation_type="cl_te",
                protocol_edge="h1",
                tech_stack=["nginx", "python", "h1.1"],
                metadata={"success_contains": "marker"},
            )
            save_vault(vault, vault_path)
            loaded = load_vault(vault_path)
            targets = [{
                "target": "example.com",
                "ip": "1.2.3.4",
                "known_ports": [443],
                "tech": ["nginx", "python", "h1.1"],
                "is_honeypot": False,
                "deception_risk": "low",
            }]
            cfg = build_daemon_config(targets, vault=loaded)
            jobs = cfg.get("jobs", [])
            self.assertTrue(jobs, "planner should emit universal key job")
            self.assertEqual(jobs[0]["probe"], "raw-replay")
            self.assertTrue(jobs[0].get("raw_payload_b64"))
            self.assertEqual(jobs[0]["metadata"]["universal_key"]["tech_stack_hash"], "nginx+python+h1.1")
            self.assertEqual(jobs[0]["metadata"]["gittins_index"], 9999.0)

    def test_tech_stack_hash(self):
        self.assertEqual(tech_stack_hash(["Envoy", "Gunicorn"]), "envoy+gunicorn")


if __name__ == "__main__":
    unittest.main()
