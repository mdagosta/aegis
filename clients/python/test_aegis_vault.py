"""Tests for aegis_vault.py against a fake vault on a Unix socket. Stdlib only:

    python3 -m unittest discover -s clients/python

The Rust integration tests (crates/aegis-vault/tests/cli.rs) also run this client against the real
daemon.
"""

import http.server
import json
import os
import shutil
import socketserver
import tempfile
import threading
import unittest

import aegis_vault


class _FakeVault(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def __init__(self, path, reply):
        self.reply = reply  # callable(path) -> (status, body bytes)
        self.requests = []
        super().__init__(path, _Handler)


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.requests.append(self.path)
        status, body = self.server.reply(self.path)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def address_string(self):
        return "unix"

    def log_message(self, format, *args):
        pass


class FetchScopeTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="aegis-py-")
        self.socket = os.path.join(self.dir, "read.sock")
        self.server = None

    def tearDown(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        shutil.rmtree(self.dir)

    def serve(self, reply):
        self.server = _FakeVault(self.socket, reply)
        threading.Thread(target=self.server.serve_forever, args=(0.05,), daemon=True).start()

    def serve_json(self, status, obj):
        self.serve(lambda path: (status, json.dumps(obj).encode()))

    def test_fetch(self):
        self.serve_json(200, {"scope": "epiphyte/prod", "secrets": {"DB": "pw", "API": "ü"}})
        secrets = aegis_vault.fetch_scope("epiphyte/prod", socket_path=self.socket)
        self.assertEqual(secrets, {"DB": "pw", "API": "ü"})
        self.assertEqual(self.server.requests, ["/v1/scope/epiphyte/prod"])

    def test_socket_from_environment(self):
        self.serve_json(200, {"scope": "a", "secrets": {}})
        old = os.environ.get("AEGIS_VAULT_SOCKET")
        os.environ["AEGIS_VAULT_SOCKET"] = self.socket
        try:
            self.assertEqual(aegis_vault.fetch_scope("a"), {})
        finally:
            if old is None:
                del os.environ["AEGIS_VAULT_SOCKET"]
            else:
                os.environ["AEGIS_VAULT_SOCKET"] = old

    def test_refusal(self):
        self.serve_json(403, {"error": "not allowed"})
        with self.assertRaises(aegis_vault.VaultError) as caught:
            aegis_vault.fetch_scope("epiphyte/prod", socket_path=self.socket)
        self.assertEqual(caught.exception.status, 403)
        self.assertIn("not allowed", str(caught.exception))

    def test_vault_down(self):
        with self.assertRaises(aegis_vault.VaultError) as caught:
            aegis_vault.fetch_scope("a", socket_path=self.socket)
        self.assertIsNone(caught.exception.status)
        self.assertIn(self.socket, str(caught.exception))

    def test_malformed_answers(self):
        for body in [b"not json", b"[]", b'{"secrets": []}', b'{"secrets": {"K": 5}}', b"{}"]:
            with self.subTest(body=body):
                self.serve(lambda path, body=body: (200, body))
                with self.assertRaises(aegis_vault.VaultError) as caught:
                    aegis_vault.fetch_scope("a", socket_path=self.socket)
                # A malformed answer is never quoted back.
                self.assertNotIn("K", str(caught.exception))
                self.server.shutdown()
                self.server.server_close()
                os.unlink(self.socket)
                self.server = None

    def test_bad_scope_names_never_reach_the_socket(self):
        self.serve_json(200, {"scope": "a", "secrets": {}})
        for scope in ["", "Epiphyte", "a//b", "a/../b", "a?x=1", "a b", "a#b", "x" * 129, None, 5]:
            with self.subTest(scope=scope):
                with self.assertRaises(ValueError):
                    aegis_vault.fetch_scope(scope, socket_path=self.socket)
        self.assertEqual(self.server.requests, [])


if __name__ == "__main__":
    unittest.main()
