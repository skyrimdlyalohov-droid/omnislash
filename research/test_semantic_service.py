import json
import os
import socket
import subprocess
import sys
import time
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
SERVICE = os.path.join(HERE, "semantic_service.py")


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class SemanticServiceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.port = free_port()
        self.addr = f"127.0.0.1:{self.port}"
        self.proc = subprocess.Popen(
            [sys.executable, SERVICE, "--addr", self.addr],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.time() + 5
        while time.time() < deadline:
            if self.proc.poll() is not None:
                self.fail("semantic service exited during startup")
            try:
                with urllib.request.urlopen(f"http://{self.addr}/healthz", timeout=0.2) as resp:
                    if resp.status == 200:
                        return
            except OSError:
                time.sleep(0.02)
        self.fail("semantic service did not become healthy")

    def tearDown(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=3)

    def _post(self, payload: dict) -> dict:
        req = urllib.request.Request(
            f"http://{self.addr}/skeleton",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=1) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def test_healthz(self) -> None:
        with urllib.request.urlopen(f"http://{self.addr}/healthz", timeout=1) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(json.loads(resp.read())["status"], "ok")

    def test_skeleton_is_value_free_and_stable(self) -> None:
        first = self._post({
            "body": '{"admin_panel":true,"token":"SECRET_ABC123456","count":42}',
            "content_type": "application/json",
        })
        second = self._post({
            "body": '{"admin_panel":true,"token":"OTHER_XYZ987654","count":7}',
            "content_type": "application/json",
        })
        self.assertEqual(first["skeleton"], second["skeleton"])
        self.assertNotIn("SECRET_ABC123456", first["skeleton"])
        self.assertNotIn("OTHER_XYZ987654", second["skeleton"])
        self.assertIn("dynamic", first["skeleton"])  # count was normalized

    def test_rejects_oversized_body(self) -> None:
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self._post({"body": "x" * ((1 << 20) + 1)})
        self.assertEqual(ctx.exception.code, 413)
        ctx.exception.close()


if __name__ == "__main__":
    unittest.main()
