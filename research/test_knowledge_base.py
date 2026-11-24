import json
import os
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from research.knowledge_base import (
    add_universal_key,
    find_keys_for_stack,
    import_playbook,
    load_vault,
    save_vault,
    tech_stack_hash,
)
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

    def test_import_playbook_emits_h2_cl_job(self):
        case_path = os.path.join(REPO_ROOT, "playbooks", "h2-cl-resources-redirect.json")
        with open(case_path, "r", encoding="utf-8") as f:
            case = json.load(f)
        with tempfile.TemporaryDirectory() as td:
            vault_path = os.path.join(td, "vault.json")
            vault = load_vault(vault_path)
            entry = import_playbook(vault, case, template="verify")
            save_vault(vault, vault_path)
            loaded = load_vault(vault_path)
            self.assertEqual(entry["technique"], "h2-cl")
            self.assertEqual(entry["tls"], "h2")
            self.assertEqual(entry["provenance"], "solution-derived")
            self.assertFalse(entry["metadata"]["autonomous_discovery"])
            self.assertEqual(entry["metadata"]["case_id"], "h2-cl-resources-redirect")

            targets = [{
                "target": "h2.example.com",
                "known_ports": [443],
                "tech": ["nginx", "h2"],
                "exploit_host": "exploit.example.net",
                "is_honeypot": False,
                "deception_risk": "low",
            }]
            cfg = build_daemon_config(targets, vault=loaded)
            jobs = [j for j in cfg["jobs"] if j["probe"] == "h2-cl"]
            self.assertEqual(len(jobs), 1)
            job = jobs[0]
            self.assertEqual(job["tls"], "h2")
            self.assertEqual(job["declared_length"], 0)
            self.assertIn("Host: exploit.example.net", job["body"])
            self.assertFalse(job["skip_victim"])
            self.assertEqual(job["success_contains"], "alert(document.cookie)")
            self.assertEqual(job["metadata"]["universal_key"]["provenance"], "solution-derived")

    def test_tech_stack_hash(self):
        self.assertEqual(tech_stack_hash(["Envoy", "Gunicorn"]), "envoy+gunicorn")


if __name__ == "__main__":
    unittest.main()
