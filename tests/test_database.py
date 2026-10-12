"""T1 and T2 against a fake PostgREST: the table list, then each table asked with the public key."""
from __future__ import annotations

import json
import unittest

from fakeserver import FakeServer, closed_port
from helpers import make_jwt, surface
from surface_audit.database import database_rows, key_headers

ANON = make_jwt("anon")
ROOT = "/rest/v1/"
OPENAPI = (200, {"Content-Type": "application/openapi+json"}, json.dumps({
    "swagger": "2.0",
    "paths": {"/": {}, "/orders": {}, "/products": {}, "/profiles": {}, "/rpc/search": {}},
}).encode())
ONE_ROW = (200, {"Content-Type": "application/json"}, b'[{"id": 1, "email": "a@example.com"}]')
NO_ROWS = (200, {"Content-Type": "application/json"}, b"[]")
DENIED = (401, {"Content-Type": "application/json"}, b'{"code": "42501", "message": "permission denied"}')


def table(name: str) -> str:
    return "/rest/v1/%s?select=*&limit=1" % name


class DatabaseCase(unittest.TestCase):
    def run_rows(self, routes: dict, **fields: object) -> list:
        with FakeServer(routes) as server:
            self.server = server
            return database_rows(surface(postgrest_url=server.url(""), anon_key=ANON, **fields))

    def results(self, rows: list) -> list:
        return [(r.rule, r.result, r.detail) for r in rows]


class TestTables(DatabaseCase):
    def test_every_listed_table_is_asked_and_graded(self) -> None:
        rows = self.run_rows({ROOT: OPENAPI, table("orders"): ONE_ROW, table("products"): ONE_ROW,
                              table("profiles"): NO_ROWS}, public_tables=["products"])
        self.assertEqual(self.results(rows), [
            ("T1", "pass", "the service lists 3 tables"),
            ("T2", "fail", "orders: open to anonymous reads"),
            ("T2", "pass", "products: open to anonymous reads, listed in public_tables"),
            ("T2", "pass", "profiles: closed to anonymous reads (no row came back)"),
        ])

    def test_the_row_names_the_request_and_never_the_data(self) -> None:
        rows = self.run_rows({ROOT: OPENAPI, table("orders"): ONE_ROW, table("products"): DENIED,
                              table("profiles"): DENIED})
        orders = rows[1]
        self.assertEqual(orders.request, "GET %s (public key, no session)" % self.server.url(table("orders")))
        self.assertEqual(orders.answer, "200, 1 row")
        self.assertNotIn("a@example.com", repr(rows))
        self.assertEqual((rows[2].result, rows[2].answer, rows[2].detail),
                         ("pass", "401", "products: closed to anonymous reads"))

    def test_the_key_goes_in_apikey_and_as_a_bearer_token_and_no_cookie(self) -> None:
        self.run_rows({ROOT: OPENAPI})
        for _, _, sent in self.server.requests:
            self.assertEqual(sent["apikey"], ANON)
            self.assertEqual(sent["Authorization"], "Bearer " + ANON)
            self.assertNotIn("Cookie", sent)

    def test_a_key_that_is_not_a_jwt_goes_in_apikey_only(self) -> None:
        self.assertEqual(key_headers("publishable-key"), {"apikey": "publishable-key", "Accept": "application/json"})

    def test_the_wording_never_claims_the_setting(self) -> None:
        rows = self.run_rows({ROOT: OPENAPI, table("orders"): ONE_ROW, table("profiles"): NO_ROWS})
        for row in rows:
            self.assertNotIn("RLS", row.detail + row.answer)

    def test_an_unexpected_answer_is_reported_as_it_is(self) -> None:
        rows = self.run_rows({ROOT: OPENAPI, table("orders"): (500, {}, b"oops"),
                              table("products"): (200, {}, b'{"not": "a list"}')})
        self.assertEqual(self.results(rows)[1:3], [
            ("T2", "warn", "orders: answered 500, neither rows nor a refusal"),
            ("T2", "warn", "products: answered 200, neither rows nor a refusal"),
        ])
        self.assertEqual(rows[3].result, "warn")   # profiles: no route, 404

    def test_config_tables_are_added_to_the_service_list(self) -> None:
        rows = self.run_rows({ROOT: OPENAPI}, tables=["audit_log"])
        self.assertIn(("T2", "warn", "audit_log: answered 404, neither rows nor a refusal"), self.results(rows))
        self.assertEqual(len(rows), 5)


class TestTableList(DatabaseCase):
    def test_a_closed_description_falls_back_to_the_config_and_says_so(self) -> None:
        rows = self.run_rows({ROOT: DENIED, table("orders"): NO_ROWS}, tables=["orders"])
        self.assertEqual(self.results(rows), [
            ("T1", "warn", "no table list from the service; checked the 1 tables in the config"),
            ("T2", "pass", "orders: closed to anonymous reads (no row came back)"),
        ])
        self.assertEqual(rows[0].answer, "401, no OpenAPI description")

    def test_no_list_anywhere_fails_rather_than_passing_on_nothing(self) -> None:
        rows = self.run_rows({ROOT: (200, {}, b"<html>")})
        self.assertEqual(self.results(rows), [
            ("T1", "fail", "no table list from the service and no tables in the config, so no table was checked")])

    def test_rpc_functions_are_not_tables(self) -> None:
        rows = self.run_rows({ROOT: OPENAPI})
        self.assertNotIn("rpc", repr([r.detail for r in rows]))

    def test_an_unreachable_service_is_an_error(self) -> None:
        rows = database_rows(surface(postgrest_url="http://127.0.0.1:%d" % closed_port(), anon_key=ANON))
        self.assertEqual([(r.rule, r.result, r.answer) for r in rows],
                         [("T1", "error", "unreachable (connection refused)")])


if __name__ == "__main__":
    unittest.main()
