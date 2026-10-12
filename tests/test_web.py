"""H1 to H7 and R1: each rule with an answer that fails it and one that passes it."""
from __future__ import annotations

import unittest

from fakeserver import FakeServer, closed_port
from helpers import headers, surface
from surface_audit.web import (h1_hsts, h2_csp, h3_framing, h4_nosniff, h5_referrer, h6_permissions, http_urls,
                               page_rows, redirect_row, refusal_row)

STRICT_CSP = "default-src 'self'; script-src 'self'; frame-ancestors 'none'; object-src 'none'"
FULL_SET = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Content-Security-Policy": STRICT_CSP,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


class TestH1Hsts(unittest.TestCase):
    def test_grades(self) -> None:
        cases = [
            ({}, "fail", "no HSTS header"),
            ({"Strict_Transport_Security": "includeSubDomains"}, "fail", "no readable max-age"),
            ({"Strict_Transport_Security": "max-age=0"}, "fail", "max-age 0 is below 15552000"),
            ({"Strict_Transport_Security": "max-age=15551999"}, "fail", "below 15552000"),
            ({"Strict_Transport_Security": "max-age=15552000"}, "warn", "max-age 15552000 is below 31536000"),
            ({"Strict_Transport_Security": 'MAX-AGE="31536000"'}, "pass", "max-age 31536000"),
            ({"Strict_Transport_Security": "max-age=63072000; preload"}, "pass", "max-age 63072000"),
        ]
        for values, result, why in cases:
            with self.subTest(values=values):
                got = h1_hsts(headers(**values))
                self.assertEqual(got[0], result)
                self.assertIn(why, got[2])

    def test_the_answer_shows_the_value_or_its_absence(self) -> None:
        self.assertEqual(h1_hsts(headers())[1], "no strict-transport-security header")
        self.assertEqual(h1_hsts(headers(Strict_Transport_Security="max-age=63072000"))[1],
                         "strict-transport-security: max-age=63072000")


class TestH2Csp(unittest.TestCase):
    def grade(self, policy: str) -> tuple:
        return h2_csp(headers(Content_Security_Policy=policy))

    def test_missing_fails(self) -> None:
        self.assertEqual(h2_csp(headers())[:2], ("fail", "no content-security-policy header"))

    def test_report_only_is_not_a_policy(self) -> None:
        result, _, why = h2_csp(headers(Content_Security_Policy_Report_Only="default-src 'self'"))
        self.assertEqual(result, "fail")
        self.assertIn("Report-Only", why)

    def test_a_strict_policy_passes(self) -> None:
        self.assertEqual(self.grade(STRICT_CSP)[0], "pass")

    def test_unsafe_script_sources_warn(self) -> None:
        cases = [
            ("script-src 'self' 'unsafe-inline'", "the policy allows 'unsafe-inline'"),
            ("script-src 'self' 'unsafe-eval'", "the policy allows 'unsafe-eval'"),
            ("default-src 'self' 'unsafe-inline'", "'unsafe-inline'"),   # default-src stands in for script-src
            ("default-src *", "default-src *"),
            ("default-src 'self'; script-src 'UNSAFE-INLINE' 'unsafe-eval'",
             "the policy allows 'unsafe-eval' and 'unsafe-inline'"),
        ]
        for policy, why in cases:
            with self.subTest(policy=policy):
                result, _, got = self.grade(policy)
                self.assertEqual(result, "warn")
                self.assertIn(why, got)

    def test_unsafe_inline_for_styles_only_passes(self) -> None:
        self.assertEqual(self.grade("default-src 'self'; style-src 'self' 'unsafe-inline'")[0], "pass")

    def test_a_script_src_overrides_default_src(self) -> None:
        self.assertEqual(self.grade("default-src 'self' 'unsafe-inline'; script-src 'self'")[0], "pass")


class TestH3Framing(unittest.TestCase):
    def test_grades(self) -> None:
        cases = [
            ({}, "fail"),
            ({"X_Frame_Options": "ALLOW-FROM https://a.example.com"}, "fail"),
            ({"X_Frame_Options": "deny"}, "pass"),
            ({"X_Frame_Options": "SAMEORIGIN"}, "pass"),
            ({"Content_Security_Policy": "default-src 'self'"}, "fail"),
            ({"Content_Security_Policy": "default-src 'self'; frame-ancestors 'self'"}, "pass"),
        ]
        for values, result in cases:
            with self.subTest(values=values):
                self.assertEqual(h3_framing(headers(**values))[0], result)

    def test_a_frame_ancestors_that_lets_any_site_frame_fails(self) -> None:
        for sources in ("*", "https:", "http: 'self'", "https://*", "'self' *", ""):
            with self.subTest(sources=sources):
                result, _, why = h3_framing(headers(Content_Security_Policy="default-src 'self'; frame-ancestors "
                                                                            + sources, X_Frame_Options="DENY"))
                self.assertEqual(result, "fail")
                self.assertIn("frame-ancestors", why)

    def test_a_frame_ancestors_naming_who_may_frame_passes(self) -> None:
        for sources in ("'none'", "'self'", "'self' https://app.example.com", "https://*.example.com"):
            with self.subTest(sources=sources):
                result, _, why = h3_framing(headers(Content_Security_Policy="frame-ancestors " + sources))
                self.assertEqual((result, why), ("pass", "frame-ancestors limits who may frame the page"))

    def test_the_answer_names_what_decided_it(self) -> None:
        self.assertEqual(h3_framing(headers(Content_Security_Policy="frame-ancestors 'none'"))[1],
                         "content-security-policy: frame-ancestors 'none'")
        self.assertEqual(h3_framing(headers())[1], "no x-frame-options header and no frame-ancestors")


class TestH4ToH6(unittest.TestCase):
    def test_nosniff(self) -> None:
        self.assertEqual(h4_nosniff(headers())[0], "fail")
        self.assertEqual(h4_nosniff(headers(X_Content_Type_Options="sniff"))[0], "fail")
        self.assertEqual(h4_nosniff(headers(X_Content_Type_Options=" NoSniff "))[0], "pass")

    def test_referrer_and_permissions_policies_warn_when_missing(self) -> None:
        for rule, name in ((h5_referrer, "Referrer_Policy"), (h6_permissions, "Permissions_Policy")):
            with self.subTest(name=name):
                self.assertEqual(rule(headers())[0], "warn")
                self.assertEqual(rule(headers(**{name: "no-referrer"}))[0], "pass")


class TestPageRows(unittest.TestCase):
    def test_one_row_per_rule_with_the_request_and_answer(self) -> None:
        with FakeServer({"/": (200, FULL_SET, b"")}) as server:
            rows = page_rows(surface(urls=[server.url("/")]), server.url("/"))
        self.assertEqual([(r.rule, r.result) for r in rows],
                         [("H1", "pass"), ("H2", "pass"), ("H3", "pass"), ("H4", "pass"), ("H5", "pass"),
                          ("H6", "pass")])
        self.assertEqual(rows[0].request, "GET " + server.url("/"))
        self.assertEqual(rows[0].answer, "200 strict-transport-security: max-age=63072000; includeSubDomains; preload")
        self.assertEqual(server.verbs(), ["GET"])

    def test_the_headers_of_the_final_redirect_are_graded_and_the_final_url_named(self) -> None:
        with FakeServer({"/": (301, {"Location": "/home"}, b""), "/home": (200, FULL_SET, b"")}) as server:
            rows = page_rows(surface(), server.url("/"))
        self.assertEqual({r.result for r in rows}, {"pass"})
        self.assertEqual(rows[0].request, "GET %s -> %s (1 redirect)" % (server.url("/"), server.url("/home")))

    def test_skipped_rules_are_shown_as_skipped(self) -> None:
        with FakeServer({"/": (200, {}, b"")}) as server:
            rows = page_rows(surface(skip=["H5", "H6"]), server.url("/"))
        self.assertEqual([r.result for r in rows], ["fail", "fail", "fail", "fail", "skip", "skip"])

    def test_an_unreachable_page_is_an_error_on_every_rule(self) -> None:
        url = "http://127.0.0.1:%d/" % closed_port()
        rows = page_rows(surface(), url)
        self.assertEqual({r.result for r in rows}, {"error"})
        self.assertEqual(rows[0].answer, "unreachable: connection refused")


class TestH7Redirect(unittest.TestCase):
    def row(self, routes: dict, path: str = "/") -> tuple:
        with FakeServer(routes) as server:
            row = redirect_row(surface(), server.url(path))
        return row, server

    def test_a_redirect_to_https_passes_without_fetching_the_https_page(self) -> None:
        row, server = self.row({"/": (301, {"Location": "https://a.example.com/"}, b"")})
        self.assertEqual((row.result, row.answer), ("pass", "301 location: https://a.example.com/"))
        self.assertEqual(server.verbs(), ["HEAD"])

    def test_an_http_hop_before_https_passes(self) -> None:
        row, _ = self.row({"/": (301, {"Location": "/www"}, b""),
                           "/www": (308, {"Location": "https://www.a.example.com/"}, b"")})
        self.assertEqual(row.result, "pass")
        self.assertIn("(1 redirect)", row.request)

    def test_plain_http_served_fails(self) -> None:
        row, _ = self.row({"/": (200, {}, b"hello")})
        self.assertEqual((row.result, row.answer), ("fail", "200 no location header"))

    def test_a_redirect_that_stays_on_http_fails(self) -> None:
        row, _ = self.row({"/": (302, {"Location": "/"}, b"")})
        self.assertEqual(row.result, "fail")
        self.assertIn("still on plain http after 5 redirects", row.detail)

    def test_a_server_refusing_head_is_asked_with_get(self) -> None:
        row, server = self.row({"/": (405, {}, b"")})
        self.assertEqual(server.verbs(), ["HEAD", "GET"])   # GET also answers 405 here
        self.assertEqual(row.result, "fail")

    def test_a_malformed_answer_to_head_is_asked_again_with_get(self) -> None:
        def head_garbage(handler: object) -> None:
            if handler.command == "HEAD":  # type: ignore[attr-defined]
                handler.wfile.write(b"\r\n")  # type: ignore[attr-defined]
                handler.close_connection = True  # type: ignore[attr-defined]
                return
            handler.send_response(308)  # type: ignore[attr-defined]
            handler.send_header("Location", "https://a.example.com/")  # type: ignore[attr-defined]
            handler.send_header("Content-Length", "0")  # type: ignore[attr-defined]
            handler.end_headers()  # type: ignore[attr-defined]

        row, server = self.row({"/": head_garbage})
        self.assertEqual(row.result, "pass")
        self.assertEqual(server.verbs(), ["HEAD", "GET"])
        self.assertEqual(row.request, "GET " + server.url("/"))   # the request that decided the row

    def test_skip(self) -> None:
        self.assertEqual(redirect_row(surface(skip=["H7"]), "http://a.example.com/").result, "skip")

    def test_one_http_door_per_host_unless_the_config_names_one(self) -> None:
        s = surface(urls=["https://a.example.com/", "https://a.example.com/login", "https://www.a.example.com/"])
        self.assertEqual(http_urls(s), ["http://a.example.com/", "http://www.a.example.com/"])
        self.assertEqual(http_urls(s._replace(http_url="http://127.0.0.1:8000/")), ["http://127.0.0.1:8000/"])


class TestR1Refusal(unittest.TestCase):
    def grade(self, route: tuple) -> tuple:
        with FakeServer({"/api/orders": route}) as server:
            row = refusal_row(surface(), server.url("/api/orders"))
        return row.result, row.answer

    def test_401_and_403_pass(self) -> None:
        self.assertEqual(self.grade((401, {}, b"")), ("pass", "401"))
        self.assertEqual(self.grade((403, {}, b"")), ("pass", "403"))

    def test_200_fails(self) -> None:
        self.assertEqual(self.grade((200, {}, b"[]")), ("fail", "200"))

    def test_anything_else_is_reported_as_it_is_and_never_followed(self) -> None:
        self.assertEqual(self.grade((302, {"Location": "/login"}, b"")), ("warn", "302 location: /login"))
        self.assertEqual(self.grade((404, {}, b"")), ("warn", "404"))


if __name__ == "__main__":
    unittest.main()
