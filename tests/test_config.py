"""The config is checked in full before any request; every problem is one sentence naming it."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from typing import Any

from helpers import make_jwt
from surface_audit import ConfigError, jwt_claims, load


class ConfigCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "surfaces.json")

    def write(self, data: Any) -> str:
        with open(self.path, "w", encoding="utf-8") as f:
            f.write(data if isinstance(data, str) else json.dumps(data))
        return self.path

    def error(self, data: Any) -> str:
        with self.assertRaises(ConfigError) as caught:
            load(self.write(data))
        return str(caught.exception)


class TestLoad(ConfigCase):
    def test_a_full_surface_loads_with_paths_resolved_beside_the_config(self) -> None:
        os.mkdir(os.path.join(self.tmp.name, "out"))
        [s] = load(self.write({"surfaces": [{
            "name": "shop", "urls": ["https://shop.example.com/"], "skip": ["H6"],
            "http_url": "http://shop.example.com/", "postgrest_url": "https://db.example.com",
            "anon_key": make_jwt("anon"), "tables": ["orders"], "public_tables": ["products"],
            "must_refuse": ["https://shop.example.com/api/orders"], "built_dir": "out"}]}))
        self.assertEqual(s.name, "shop")
        self.assertEqual(s.built_dir, os.path.join(self.tmp.name, "out"))
        self.assertEqual((s.skip, s.tables, s.public_tables), (["H6"], ["orders"], ["products"]))

    def test_optional_lists_default_to_empty(self) -> None:
        [s] = load(self.write({"surfaces": [{"name": "a", "urls": ["https://a.example.com/"]}]}))
        self.assertEqual((s.skip, s.must_refuse, s.built_dir, s.anon_key), ([], [], None, None))


class TestRefused(ConfigCase):
    def test_a_missing_file(self) -> None:
        with self.assertRaisesRegex(ConfigError, "^cannot read .*nope.json: No such file or directory$"):
            load(os.path.join(self.tmp.name, "nope.json"))

    def test_an_empty_file(self) -> None:
        self.assertRegex(self.error("  \n"), "surfaces.json is empty$")

    def test_invalid_json(self) -> None:
        self.assertRegex(self.error("{surfaces: }"), "surfaces.json is not valid JSON: ")

    def test_no_surfaces(self) -> None:
        for data in ({"surfaces": []}, {"surfaces": {}}):
            with self.subTest(data=data):
                self.assertRegex(self.error(data), "lists no surfaces$")

    def test_a_top_level_that_is_not_one_surfaces_field(self) -> None:
        for data in ([], {}, {"surfaces": [], "extra": 1}):
            with self.subTest(data=data):
                self.assertIn('must be an object with one field, "surfaces"', self.error(data))

    def test_an_unknown_field_is_named(self) -> None:
        # A typo such as public_table would otherwise fail a table the user meant to allow.
        msg = self.error({"surfaces": [{"name": "a", "urls": ["https://a.example.com/"], "public_table": []}]})
        self.assertTrue(msg.startswith("surface 'a': unknown field 'public_table'"), msg)

    def test_a_surface_with_nothing_to_check(self) -> None:
        self.assertIn("nothing to check", self.error({"surfaces": [{"name": "a"}]}))

    def test_a_surface_with_no_name(self) -> None:
        self.assertEqual(self.error({"surfaces": [{"urls": ["https://a.example.com/"]}]}), "surface 1 has no name")

    def test_a_repeated_name(self) -> None:
        one = {"name": "a", "urls": ["https://a.example.com/"]}
        self.assertEqual(self.error({"surfaces": [one, one]}), "surface name 'a' is used twice")

    def test_a_url_that_is_not_web(self) -> None:
        for field, value in (("urls", ["ftp://a.example.com/"]), ("must_refuse", ["/api/x"])):
            with self.subTest(field=field):
                self.assertIn("is not an http or https URL", self.error({"surfaces": [{"name": "a", field: value}]}))

    def test_a_list_field_holding_something_else(self) -> None:
        self.assertEqual(self.error({"surfaces": [{"name": "a", "urls": "https://a.example.com/"}]}),
                         "surface 'a': urls must be a list of strings")

    def test_skip_takes_only_header_rules(self) -> None:
        msg = self.error({"surfaces": [{"name": "a", "urls": ["https://a.example.com/"], "skip": ["T2"]}]})
        self.assertIn("skip names 'T2'; only the header rules H1, H2, H3, H4, H5, H6, H7 can be skipped", msg)

    def test_a_database_url_needs_its_key(self) -> None:
        self.assertIn("postgrest_url and anon_key go together",
                      self.error({"surfaces": [{"name": "a", "postgrest_url": "https://db.example.com"}]}))

    def test_tables_need_a_database(self) -> None:
        self.assertIn("need a postgrest_url",
                      self.error({"surfaces": [{"name": "a", "urls": ["https://a.example.com/"],
                                                "tables": ["t"]}]}))

    def test_a_missing_folder(self) -> None:
        self.assertIn("built_dir is not a folder", self.error({"surfaces": [{"name": "a", "built_dir": "out"}]}))

    def test_a_service_role_key_is_refused(self) -> None:
        msg = self.error({"surfaces": [{"name": "a", "postgrest_url": "https://db.example.com",
                                        "anon_key": make_jwt("service_role")}]})
        self.assertEqual(msg, "surface 'a': anon_key carries the service_role claim; give the public anon or "
                              "publishable key, never a key that bypasses row security")

    def test_a_supabase_secret_key_is_refused(self) -> None:
        msg = self.error({"surfaces": [{"name": "a", "postgrest_url": "https://db.example.com",
                                        "anon_key": "sb_secret_" + "N7xQ" * 8}]})
        self.assertEqual(msg, "surface 'a': anon_key is a Supabase secret key (sb_secret_); give the public anon "
                              "or publishable key, never a key that bypasses row security")

    def test_a_supabase_publishable_key_is_accepted(self) -> None:
        key = "sb_publishable_" + "N7xQ" * 8
        [s] = load(self.write({"surfaces": [{"name": "a", "postgrest_url": "https://db.example.com",
                                             "anon_key": key}]}))
        self.assertEqual(s.anon_key, key)

    def test_a_key_that_is_not_a_jwt_is_accepted(self) -> None:
        [s] = load(self.write({"surfaces": [{"name": "a", "postgrest_url": "https://db.example.com",
                                             "anon_key": "publishable-key-123"}]}))
        self.assertEqual(s.anon_key, "publishable-key-123")


class TestJwtClaims(unittest.TestCase):
    def test_reads_the_payload(self) -> None:
        self.assertEqual(jwt_claims(make_jwt("anon"))["role"], "anon")

    def test_anything_else_is_none(self) -> None:
        for text in ("", "a.b", "a.b.c", "x.!!!.y", "a.bnVsbA.c", "a.W10.c"):   # null and [] decode, not objects
            with self.subTest(text=text):
                self.assertIsNone(jwt_claims(text))


if __name__ == "__main__":
    unittest.main()
