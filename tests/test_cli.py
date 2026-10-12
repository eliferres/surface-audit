"""The run command end to end: exit codes, the dated report, --json, and one-line errors."""
from __future__ import annotations

import contextlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import surface_audit
from fakeserver import FakeServer, closed_port
from helpers import make_jwt

ROOT = Path(__file__).resolve().parent.parent
REPORT_NAME = re.compile(r"^\d{4}-\d{2}-\d{2}-\d{4}-[0-9a-f]{6}\.md$")
GOOD = {
    "Strict-Transport-Security": "max-age=63072000",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=()",
}
REDIRECT = (301, {"Location": "https://a.example.com/"}, b"")


class RunCase(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def config(self, *surfaces: dict) -> str:
        (self.dir / "surfaces.json").write_text(json.dumps({"surfaces": list(surfaces)}), encoding="utf-8")
        return "surfaces.json"

    def run_tool(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, "-m", "surface_audit", *args], cwd=str(self.dir),
                              capture_output=True, text=True,
                              env=dict(os.environ, PYTHONPATH=str(ROOT)))

    def reports(self) -> list:
        folder = self.dir / "reports"
        return sorted(os.listdir(str(folder))) if folder.is_dir() else []


class TestExitCodes(RunCase):
    def test_a_clean_surface_exits_0_and_prints_only_the_verdict(self) -> None:
        with FakeServer({"/": (200, GOOD, b""), "/http": REDIRECT}) as server:
            r = self.run_tool("run", self.config({"name": "a", "urls": [server.url("/")],
                                                  "http_url": server.url("/http")}))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        [name] = self.reports()
        self.assertRegex(name, REPORT_NAME)
        self.assertEqual(r.stdout, "PASS: 0 failing, 0 warning, 7 passing, 0 errors; "
                                   "report reports/%s\n" % name)

    def test_a_failure_exits_1_with_one_line_per_finding(self) -> None:
        bare = dict(GOOD)
        del bare["Content-Security-Policy"], bare["Referrer-Policy"]
        with FakeServer({"/": (200, bare, b""), "/http": REDIRECT}) as server:
            r = self.run_tool("run", self.config({"name": "a", "urls": [server.url("/")],
                                                  "http_url": server.url("/http")}))
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertEqual(r.stdout.splitlines()[:3], [
            "fail  H2  a  no Content-Security-Policy header (GET %s)" % server.url("/"),
            "fail  H3  a  any site can frame the page (clickjacking) (GET %s)" % server.url("/"),
            "warn  H5  a  the browser default decides how much of the URL other sites see (GET %s)" % server.url("/"),
        ])
        self.assertTrue(r.stdout.splitlines()[3].startswith("FAIL: 2 failing, 1 warning, 4 passing"))

    def test_warnings_alone_exit_0(self) -> None:
        soft = dict(GOOD, **{"Strict-Transport-Security": "max-age=15552000"})
        with FakeServer({"/": (200, soft, b""), "/http": REDIRECT}) as server:
            r = self.run_tool("run", self.config({"name": "a", "urls": [server.url("/")],
                                                  "http_url": server.url("/http")}))
        self.assertEqual(r.returncode, 0)
        self.assertTrue(r.stdout.startswith("warn  H1  a  max-age 15552000 is below 31536000"))

    def test_an_unreachable_surface_exits_2_and_the_row_says_so(self) -> None:
        url = "http://127.0.0.1:%d/" % closed_port()
        r = self.run_tool("run", self.config({"name": "down", "urls": [url], "http_url": url}))
        self.assertEqual(r.returncode, 2)
        self.assertIn("error H1  down  unreachable: connection refused (GET %s)" % url, r.stdout)
        self.assertIn("ERROR: 0 failing, 0 warning, 0 passing, 7 errors", r.stdout)
        report = (self.dir / "reports" / self.reports()[0]).read_text(encoding="utf-8")
        self.assertIn("| down | H1 | error | GET %s | unreachable: connection refused |" % url, report)

    def test_unreachable_outranks_a_failure(self) -> None:
        with FakeServer({"/": (200, {}, b"")}) as server:
            r = self.run_tool("run", self.config(
                {"name": "a", "urls": [server.url("/")], "http_url": server.url("/")},
                {"name": "b", "must_refuse": ["http://127.0.0.1:%d/api" % closed_port()]}))
        self.assertEqual(r.returncode, 2)


class TestConfigErrors(RunCase):
    def test_each_is_one_line_on_stderr_and_exit_2_with_no_report(self) -> None:
        cases = {
            "": "surface-audit: surfaces.json is empty",
            "{": "surface-audit: surfaces.json is not valid JSON: ",
            '{"surfaces": []}': "surface-audit: surfaces.json lists no surfaces",
        }
        for text, message in cases.items():
            with self.subTest(text=text):
                (self.dir / "surfaces.json").write_text(text, encoding="utf-8")
                r = self.run_tool("run", "surfaces.json")
                self.assertEqual((r.returncode, r.stdout), (2, ""))
                self.assertTrue(r.stderr.startswith(message), r.stderr)
                self.assertEqual(len(r.stderr.splitlines()), 1)
        self.assertEqual(self.reports(), [])

    def test_a_service_role_key_is_refused_before_any_request(self) -> None:
        with FakeServer({}) as server:
            r = self.run_tool("run", self.config({"name": "a", "urls": [server.url("/")],
                                                  "postgrest_url": server.url(""),
                                                  "anon_key": make_jwt("service_role")}))
        self.assertEqual(r.returncode, 2)
        self.assertIn("anon_key carries the service_role claim", r.stderr)
        self.assertEqual(server.requests, [])

    def test_a_supabase_secret_key_is_refused_before_any_request(self) -> None:
        with FakeServer({}) as server:
            r = self.run_tool("run", self.config({"name": "a", "urls": [server.url("/")],
                                                  "postgrest_url": server.url(""),
                                                  "anon_key": "sb_" + "secret_" + "N7xQ" * 8}))
        self.assertEqual(r.returncode, 2)
        self.assertIn("anon_key is a Supabase secret key (sb_secret_)", r.stderr)
        self.assertEqual(server.requests, [])

    def test_bad_usage_is_one_line_and_exit_2(self) -> None:
        for args in ((), ("run",), ("scan", "x.json"), ("run", "x.json", "--bogus")):
            with self.subTest(args=args):
                r = self.run_tool(*args)
                self.assertEqual(r.returncode, 2)
                self.assertEqual(len(r.stderr.splitlines()), 1, r.stderr)

    def test_an_unwritable_report_folder_is_one_line_and_exit_2(self) -> None:
        (self.dir / "blocked").write_text("a file, not a folder", encoding="utf-8")
        with FakeServer({"/": (200, GOOD, b""), "/http": REDIRECT}) as server:
            r = self.run_tool("run", self.config({"name": "a", "urls": [server.url("/")],
                                                  "http_url": server.url("/http")}), "--out", "blocked")
        self.assertEqual(r.returncode, 2)
        self.assertTrue(r.stderr.startswith("surface-audit: cannot write the report in blocked: "), r.stderr)

    def test_an_unexpected_error_is_one_line_and_exit_2(self) -> None:
        err = io.StringIO()
        config = self.config({"name": "a", "urls": ["https://a.example.com/"]})
        with mock.patch("surface_audit.cli.audit", side_effect=RuntimeError("something broke")), \
                contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as stop:
            surface_audit.main(["run", str(self.dir / config)])
        self.assertEqual(stop.exception.code, 2)
        self.assertEqual(err.getvalue(), "surface-audit: internal error: RuntimeError: something broke\n")

    def test_version(self) -> None:
        r = self.run_tool("--version")
        self.assertEqual((r.returncode, r.stdout), (0, "surface-audit 0.1.0\n"))


class TestReport(RunCase):
    def serve_and_run(self, *extra: str) -> subprocess.CompletedProcess:
        with FakeServer({"/": (200, GOOD, b""), "/http": REDIRECT}) as server:
            self.url = server.url("/")
            return self.run_tool("run", self.config({"name": "a", "urls": [self.url],
                                                     "http_url": server.url("/http")}), *extra)

    def test_every_rule_is_a_row_with_its_request_and_answer(self) -> None:
        self.serve_and_run()
        text = (self.dir / "reports" / self.reports()[0]).read_text(encoding="utf-8")
        self.assertIn("| Surface | Rule | Result | Request | Answer | Why |", text)
        self.assertIn("| a | H1 | pass | GET %s | 200 strict-transport-security: max-age=63072000 | "
                      "max-age 63072000 |" % self.url, text)
        self.assertIn("| a | H7 | pass | HEAD %shttp | 301 location: https://a.example.com/ |" % self.url, text)
        self.assertEqual(len(re.findall(r"^\| a \| H\d \|", text, re.M)), 7)

    def test_a_second_run_writes_a_new_file(self) -> None:
        self.serve_and_run()
        self.serve_and_run()
        self.assertEqual(len(self.reports()), 2)

    def test_out_chooses_the_folder(self) -> None:
        r = self.serve_and_run("--out", "audits/site")
        [name] = os.listdir(str(self.dir / "audits" / "site"))
        self.assertIn("report audits/site/%s" % name, r.stdout)

    def test_json_carries_every_row_and_the_report_path(self) -> None:
        r = self.serve_and_run("--json")
        data = json.loads(r.stdout)
        self.assertEqual((data["verdict"], data["version"], len(data["rows"])), ("PASS", "0.1.0", 7))
        self.assertEqual(data["counts"], {"fail": 0, "error": 0, "warn": 0, "pass": 7})
        self.assertEqual(set(data["rows"][0]), {"surface", "rule", "result", "request", "answer", "detail"})
        self.assertTrue(os.path.isfile(str(self.dir / data["report"])))

    def test_a_pipe_in_a_header_value_does_not_break_the_table(self) -> None:
        with FakeServer({"/": (200, dict(GOOD, **{"Referrer-Policy": "a|b"}), b"")}) as server:
            self.run_tool("run", self.config({"name": "a", "urls": [server.url("/")], "skip": ["H7"]}))
        text = (self.dir / "reports" / self.reports()[0]).read_text(encoding="utf-8")
        self.assertIn("referrer-policy: a\\|b", text)


if __name__ == "__main__":
    unittest.main()
