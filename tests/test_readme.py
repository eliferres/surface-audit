"""The README's tables and its shown output match the code and the recorded demo."""
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

from surface_audit import RULES
from surface_audit.config import FIELDS

ROOT = Path(__file__).resolve().parent.parent
README = (ROOT / "README.md").read_text(encoding="utf-8")


class TestReadme(unittest.TestCase):
    def test_the_rule_table_lists_the_rules_in_the_code_in_order(self) -> None:
        self.assertEqual(re.findall(r"^\| `([A-Z]\d)` \|", README, re.M), list(RULES))

    def test_the_config_table_documents_every_field_in_the_code(self) -> None:
        documented = re.findall(r"^\| `([a-z_]+)` \| ", README, re.M)
        self.assertEqual(sorted(documented), sorted(FIELDS))

    def test_the_first_run_output_is_the_recorded_demo_output(self) -> None:
        shown = re.search(r"run demo/surfaces.json\n```\n\n```text\n(.*?)\n```", README, re.S).group(1)
        recorded = json.loads((ROOT / "demo" / "transcript.json").read_text(encoding="utf-8"))[0]["out"]
        self.assertEqual(shown, recorded.rsplit("\nexit ", 1)[0])

    def test_the_one_rule_comes_before_everything_else(self) -> None:
        rule = README.index("**Run it only against surfaces you own or have written permission to test.**")
        self.assertLess(rule, README.index("[![ci]"))


if __name__ == "__main__":
    unittest.main()
