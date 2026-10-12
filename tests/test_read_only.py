"""Read-only by construction: a recording server sees only GET and HEAD from a run that exercises
every kind of request the tool makes."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from fakeserver import FakeServer
from helpers import make_jwt

ROOT = Path(__file__).resolve().parent.parent
OPENAPI = json.dumps({"paths": {"/": {}, "/orders": {}, "/rpc/do_something": {}}}).encode()


class TestReadOnly(unittest.TestCase):
    def test_a_full_run_sends_only_get_and_head(self) -> None:
        routes = {
            "/": (302, {"Location": "/home"}, b""),
            "/home": (200, {}, b""),
            "/http": (301, {"Location": "/http2"}, b""),
            "/http2": (405, {}, b""),   # refuses HEAD, so the redirect check falls back to GET
            "/rest/v1/": (200, {}, OPENAPI),
            "/rest/v1/orders?select=*&limit=1": (200, {}, b'[{"id": 1}]'),
            "/api/orders": (200, {}, b"[]"),
        }
        with tempfile.TemporaryDirectory() as tmp, FakeServer(routes) as server:
            Path(tmp, "surfaces.json").write_text(json.dumps({"surfaces": [{
                "name": "a", "urls": [server.url("/")], "http_url": server.url("/http"),
                "postgrest_url": server.url(""), "anon_key": make_jwt("anon"),
                "must_refuse": [server.url("/api/orders")],
            }]}), encoding="utf-8")
            done = subprocess.run([sys.executable, "-m", "surface_audit", "run", "surfaces.json"], cwd=tmp,
                                  capture_output=True, text=True, env=dict(os.environ, PYTHONPATH=str(ROOT)))
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertEqual(set(server.verbs()), {"GET", "HEAD"})
        self.assertEqual(len(server.requests), 8)

    def test_the_server_would_have_recorded_any_other_verb(self) -> None:
        with FakeServer({}) as server:
            request = urllib.request.Request(server.url("/"), method="DELETE")
            with self.assertRaises(urllib.error.HTTPError) as refused:   # 501: no handler, but it was recorded
                urllib.request.urlopen(request, timeout=5)
            refused.exception.close()
        self.assertEqual(server.verbs(), ["DELETE"])


if __name__ == "__main__":
    unittest.main()
