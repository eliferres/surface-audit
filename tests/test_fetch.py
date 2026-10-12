"""The HTTP layer: read-only verbs, redirects by hand, one retry on a reset, and no answer as an error."""
from __future__ import annotations

import time
import unittest
from unittest import mock

from fakeserver import FakeServer, closed_port, hang_up, slow
from surface_audit import Unreachable, fetch
from surface_audit.net import Malformed
from surface_audit import net


class TestVerbs(unittest.TestCase):
    def test_only_get_and_head_can_be_sent(self) -> None:
        for verb in ("POST", "PUT", "PATCH", "DELETE", "OPTIONS", "get"):
            with self.subTest(verb=verb), self.assertRaises(ValueError):
                fetch(verb, "http://127.0.0.1:1/")

    def test_head_sends_head_and_reads_no_body(self) -> None:
        with FakeServer({"/": (200, {"X-Test": "1"}, b"body")}) as server:
            answer = fetch("HEAD", server.url("/"), read_body=True)
        self.assertEqual((answer.status, answer.body, answer.headers["X-Test"]), (200, b"", "1"))
        self.assertEqual(server.verbs(), ["HEAD"])

    def test_no_cookie_is_sent_back(self) -> None:
        with FakeServer({"/a": (302, {"Location": "/b", "Set-Cookie": "session=abc"}, b""),
                         "/b": (200, {}, b"")}) as server:
            fetch("GET", server.url("/a"))
        self.assertNotIn("Cookie", server.requests[1][2])


class TestRedirects(unittest.TestCase):
    def test_a_chain_is_followed_and_the_final_url_reported(self) -> None:
        with FakeServer({"/1": (301, {"Location": "/2"}, b""), "/2": (308, {"Location": "/3"}, b""),
                         "/3": (200, {}, b"")}) as server:
            answer = fetch("GET", server.url("/1"))
        self.assertEqual((answer.status, answer.url, answer.hops), (200, server.url("/3"), 2))

    def test_five_hops_are_followed_and_a_sixth_is_an_error(self) -> None:
        routes = {"/%d" % n: (302, {"Location": "/%d" % (n + 1)}, b"") for n in range(6)}
        routes["/5"] = (200, {}, b"")
        with FakeServer(routes) as server:
            self.assertEqual(fetch("GET", server.url("/0")).hops, 5)
            server.routes["/5"] = (302, {"Location": "/6"}, b"")
            with self.assertRaisesRegex(Unreachable, "more than 5 redirects"):
                fetch("GET", server.url("/0"))

    def test_follow_false_returns_the_redirect_itself(self) -> None:
        with FakeServer({"/": (302, {"Location": "/login"}, b"")}) as server:
            answer = fetch("GET", server.url("/"), follow=False)
        self.assertEqual((answer.status, answer.headers["Location"]), (302, "/login"))

    def test_an_error_status_is_an_answer(self) -> None:
        with FakeServer({"/": (401, {"WWW-Authenticate": "Bearer"}, b"no")}) as server:
            answer = fetch("GET", server.url("/"), read_body=True)
        self.assertEqual((answer.status, answer.body), (401, b"no"))


class TestNoAnswer(unittest.TestCase):
    def test_a_refused_connection_is_unreachable(self) -> None:
        with self.assertRaisesRegex(Unreachable, "connection refused"):
            fetch("GET", "http://127.0.0.1:%d/" % closed_port())

    def test_one_reset_is_retried(self) -> None:
        calls = []

        def reset_once(handler: object) -> None:
            calls.append(1)
            if len(calls) == 1:
                hang_up(handler)  # type: ignore[arg-type]
            else:
                handler.send_response(200)  # type: ignore[attr-defined]
                handler.send_header("Content-Length", "0")  # type: ignore[attr-defined]
                handler.end_headers()  # type: ignore[attr-defined]

        with FakeServer({"/": reset_once}) as server:
            self.assertEqual(fetch("GET", server.url("/")).status, 200)
        self.assertEqual(server.verbs(), ["GET", "GET"])

    def test_a_second_reset_is_unreachable(self) -> None:
        with FakeServer({"/": hang_up}) as server:
            with self.assertRaises(Unreachable):
                fetch("GET", server.url("/"))
        self.assertEqual(server.verbs(), ["GET", "GET"])

    def test_a_slow_server_times_out(self) -> None:
        with FakeServer({"/": slow(1.0)}) as server, mock.patch.object(net, "TIMEOUT", 0.2):
            with self.assertRaisesRegex(Unreachable, "timed out after 0.2 s"):
                fetch("GET", server.url("/"))

    def test_a_malformed_answer_is_one_line(self) -> None:
        def garbage(handler: object) -> None:
            handler.wfile.write(b"\r\n")  # type: ignore[attr-defined]
            handler.close_connection = True  # type: ignore[attr-defined]

        with FakeServer({"/": garbage}) as server:
            with self.assertRaises(Malformed) as caught:
                fetch("HEAD", server.url("/"))
        self.assertEqual(str(caught.exception), "malformed answer (BadStatusLine: '\\r\\n')")

    def test_a_server_dripping_bytes_is_cut_off_at_the_deadline(self) -> None:
        # One byte a second never trips the per-read socket timeout; only the whole-request deadline stops it.
        def drip(handler: object) -> None:
            handler.wfile.write(b"HTTP/1.1 200 OK\r\nX-Drip: ")  # type: ignore[attr-defined]
            for _ in range(8):
                handler.wfile.write(b"a")  # type: ignore[attr-defined]
                handler.wfile.flush()  # type: ignore[attr-defined]
                time.sleep(1.0)
            handler.close_connection = True  # type: ignore[attr-defined]

        with FakeServer({"/": drip}) as server, mock.patch.object(net, "TIMEOUT", 2.0):
            started = time.monotonic()
            with self.assertRaisesRegex(Unreachable, "^timed out after 2 s$"):
                fetch("GET", server.url("/"))
        self.assertLess(time.monotonic() - started, 3.5)
        self.assertEqual(server.verbs(), ["GET"])   # a deadline is not a reset, so no retry

    def test_the_timeout_is_fifteen_seconds(self) -> None:
        self.assertEqual(net.TIMEOUT, 15.0)


if __name__ == "__main__":
    unittest.main()
