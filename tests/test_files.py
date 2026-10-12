"""S1 and G1. Every planted secret is built at test time from pieces, so no file in this
repository holds one and no secret scanner is set off by the fixtures."""
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from unittest import mock

from helpers import make_jwt, surface
from surface_audit import files
from surface_audit.files import scan_file, secret_rows, tracked_rows, tracked_secret

ANON = make_jwt("anon")
PLANTED = {
    "service-role JWT": make_jwt("service_role"),
    "Anthropic API key": "sk" + "-ant-" + "api03-" + "x" * 40,
    "Stripe live secret key": "sk" + "_live_" + "4eC39HqLyjWDarjtT1zdp7dc",
    "AWS access key id": "AK" + "IA" + "IOSFODNN7EXAMPLE",
    "GitHub token": "gh" + "p_" + "a" * 36,
    "private key": "-----BEGIN " + "RSA PRIVATE KEY-----",
    "Supabase secret key": "sb_" + "secret_" + "N7xQ" * 8,
}
PUBLISHABLE = "sb_" + "publishable_" + "N7xQ" * 8


class FolderCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name

    def put(self, name: str, content: str) -> str:
        path = os.path.join(self.root, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path


class TestShapes(FolderCase):
    def test_each_shape_is_found_and_named_never_quoted(self) -> None:
        for shape, secret in PLANTED.items():
            with self.subTest(shape=shape):
                self.put("assets/app.js", 'const config = {"k": "%s"};' % secret)
                rows = secret_rows(surface(built_dir=self.root))
                self.assertEqual([(r.result, r.detail) for r in rows],
                                 [("fail", "%s in assets/app.js, a file the browser can download" % shape)])
                self.assertEqual(rows[0].answer, "%s at byte 22" % shape)
                self.assertNotIn(secret, repr(rows))

    def test_the_public_anon_key_and_near_misses_pass(self) -> None:
        self.put("app.js", "\n".join([
            'const anon = "%s";' % ANON,                       # role anon: public by design
            "const x = '%s';" % ("sk_" + "test_" + "4eC39HqLyjWDarjtT1zdp7dc"),   # a test-mode key is not live; assembled so a host's push scan does not read this line as a key
            "const y = 'Z%sZ';" % PLANTED["AWS access key id"],   # inside a longer word
            "-----BEGIN PUBLIC KEY-----",
        ]))
        rows = secret_rows(surface(built_dir=self.root, anon_key=ANON))
        self.assertEqual([(r.result, r.answer) for r in rows], [("pass", "no secret shape")])
        self.assertEqual(rows[0].request, "read 1 files under %s" % self.root)

    def test_a_supabase_publishable_key_is_not_a_secret(self) -> None:
        self.put("app.js", 'const key = "%s";' % PUBLISHABLE)
        for key in (None, PUBLISHABLE):
            with self.subTest(configured=key):
                self.assertEqual(secret_rows(surface(built_dir=self.root, anon_key=key))[0].result, "pass")

    def test_the_configured_key_is_allow_listed_by_its_hash(self) -> None:
        stripe = PLANTED["Stripe live secret key"]
        self.put("app.js", stripe)
        self.assertEqual(secret_rows(surface(built_dir=self.root))[0].result, "fail")
        self.assertEqual(secret_rows(surface(built_dir=self.root, anon_key=stripe))[0].result, "pass")

    def test_every_file_is_read_whatever_its_name(self) -> None:
        self.put("_next/static/chunks/a.js", "")
        self.put("deep/er/data.json.map", PLANTED["AWS access key id"])
        rows = secret_rows(surface(built_dir=self.root))
        self.assertEqual(rows[0].detail, "AWS access key id in deep/er/data.json.map, a file the browser can download")


class TestChunks(FolderCase):
    def test_a_secret_across_a_chunk_edge_is_found_once(self) -> None:
        secret = PLANTED["service-role JWT"]
        with mock.patch.object(files, "CHUNK", 64), mock.patch.object(files, "OVERLAP", 400):
            for start in range(0, 200, 7):
                with self.subTest(start=start):
                    path = self.put("a.js", "x" * start + secret + "y" * 300)
                    self.assertEqual(scan_file(path, set()), [(start, "service-role JWT")])

    def test_a_ten_megabyte_file_with_a_key_at_the_end(self) -> None:
        path = os.path.join(self.root, "big.js")
        with open(path, "w", encoding="utf-8") as f:
            f.write(("var a=1;" * 128 + "\n") * 10240)
            f.write(PLANTED["GitHub token"])
        self.assertGreater(os.path.getsize(path), 10 * 1024 * 1024)
        self.assertEqual(scan_file(path, set()), [(os.path.getsize(path) - 40, "GitHub token")])


class TestTrackedFiles(FolderCase):
    def git(self, *args: str) -> None:
        subprocess.run(["git", "-C", self.root, *args], check=True, capture_output=True)

    def repo(self, *names: str) -> list:
        self.git("init", "-q")
        for name in names:
            self.put(name, "x")
        self.git("add", "--", *names)
        return tracked_rows(surface(repo_dir=self.root))

    def test_env_and_key_files_fail(self) -> None:
        rows = self.repo("README.md", ".env", "config/.env.production", "certs/server.pem", "id.key",
                         "store.p12", "cert.PFX")
        self.assertEqual([(r.result, r.answer) for r in rows], [
            ("fail", "tracked: .env"), ("fail", "tracked: cert.PFX"), ("fail", "tracked: certs/server.pem"),
            ("fail", "tracked: config/.env.production"), ("fail", "tracked: id.key"), ("fail", "tracked: store.p12"),
        ])
        self.assertEqual(rows[0].detail, "an environment file is committed to git")

    def test_templates_and_untracked_files_pass(self) -> None:
        self.put(".env", "SECRET=1")   # on disk but not tracked
        rows = self.repo(".env.example", ".env.sample", "app/env.ts", "keys.md")
        self.assertEqual([(r.result, r.answer) for r in rows], [("pass", "4 tracked files")])

    def test_a_folder_that_is_not_a_repository_is_an_error(self) -> None:
        rows = tracked_rows(surface(repo_dir=self.root))
        self.assertEqual(rows[0].result, "error")
        self.assertIn("not a git repository", rows[0].answer)

    def test_the_name_rules(self) -> None:
        for name, flagged in ((".env", True), (".env.local", True), (".env.example", False), ("env", False),
                              ("a/.ENV", True), ("tls.key", True), ("key.txt", False), ("x.p12", True)):
            with self.subTest(name=name):
                self.assertEqual(tracked_secret(name) is not None, flagged)


if __name__ == "__main__":
    unittest.main()
