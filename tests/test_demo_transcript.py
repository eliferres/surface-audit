"""demo/transcript.json is replayed for real, and demo/terminal.svg is
checked against it, so the README picture cannot drift from what the tool
prints.

Each recorded command runs with bash inside a fresh copy of the checkout;
its combined stdout and stderr and its exit status must equal the record,
apart from the report's file name, which carries the minute and a random
suffix by design. UPDATE_DEMO_TRANSCRIPT=1 rewrites the transcript from that
real run, which is the only way it is ever regenerated.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TRANSCRIPT = ROOT / "demo" / "transcript.json"
PICTURE = ROOT / "demo" / "terminal.svg"
PLACEHOLDER = "/path/to/checkout"
SVG = "{http://www.w3.org/2000/svg}"
ELLIPSIS = "…"
REPORT_NAME = re.compile(r"reports/\d{4}-\d{2}-\d{2}-\d{4}-[0-9a-f]{6}\.md")


def same_run(out: str) -> str:
    """The output with the report's file name, different on every run, made constant."""
    return REPORT_NAME.sub("reports/<report>.md", out)


def replay(entries: list) -> list:
    """Run every command in a throwaway copy and return what it really did."""
    with tempfile.TemporaryDirectory() as tmp:
        copy = Path(tmp) / "surface-audit"
        shutil.copytree(ROOT, copy, ignore=shutil.ignore_patterns(
            ".git", "__pycache__", "*.egg-info", "build", "dist", ".venv", "reports"))
        results = []
        for entry in entries:
            proc = subprocess.run(["bash", "-c", entry["cmd"]], cwd=str(copy), text=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            out = proc.stdout
            for form in (str(copy.resolve()), str(copy)):   # macOS: /var is /private/var
                out = out.replace(form, PLACEHOLDER)
            results.append({"cmd": entry["cmd"], "out": out.rstrip("\n"), "status": proc.returncode})
        return results


def picture_rows() -> list:
    """(kind, text) for every terminal row in the picture, title bar aside.
    A command row is a prompt tspan followed by the command; a wrapped
    command continues on a row of class "cmd", indented four spaces."""
    rows = []
    for text in ET.parse(str(PICTURE)).getroot().iter(SVG + "text"):
        if text.get("font-size"):
            continue
        spans = list(text.iter(SVG + "tspan"))
        if spans:
            rows.append(("cmd", spans[-1].text or ""))
        elif text.get("class") == "cmd":
            rows.append(("cmd", (text.text or "")[4:]))
        else:
            rows.append(("out", text.text or ""))
    return rows


def command_chunks(cmd: str) -> list:
    """How a long command can appear: its words joined back up in any run,
    so a row of a wrapped command is a prefix of some suffix of it."""
    words = cmd.split(" ")
    return [" ".join(words[i:]) for i in range(len(words))]


class TestDemoTranscript(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.recorded = json.loads(TRANSCRIPT.read_text(encoding="utf-8"))
        cls.replayed = replay(cls.recorded)
        if os.environ.get("UPDATE_DEMO_TRANSCRIPT") == "1":
            TRANSCRIPT.write_text(json.dumps(cls.replayed, indent=2) + "\n", encoding="utf-8")
            cls.recorded = cls.replayed

    def test_each_command_prints_exactly_what_was_recorded(self) -> None:
        self.assertEqual(len(self.replayed), len(self.recorded))
        for want, got in zip(self.recorded, self.replayed):
            with self.subTest(cmd=want["cmd"]):
                self.assertEqual(same_run(got["out"]), same_run(want["out"]), "output differs for: " + want["cmd"])
                self.assertEqual(got["status"], want["status"], "exit status differs for: " + want["cmd"])

    def test_the_transcript_holds_no_machine_path(self) -> None:
        text = TRANSCRIPT.read_text(encoding="utf-8")
        self.assertNotRegex(text, r"/(Users|home|tmp)/|/var/folders|/private/var")

    def test_every_picture_row_comes_from_the_transcript(self) -> None:
        """Each drawn row, with one trailing ellipsis removed, starts a
        recorded output line or a piece of a recorded command."""
        out_lines = [line for e in self.recorded for line in e["out"].splitlines()]
        pieces = [c for e in self.recorded for c in command_chunks(e["cmd"])]
        rows = picture_rows()
        self.assertTrue(rows, "the picture has no rows")
        for kind, row in rows:
            shown = row[:-len(ELLIPSIS)] if row.endswith(ELLIPSIS) else row
            if kind == "cmd" and shown.endswith(" \\"):
                shown = shown[:-2]
            candidates = pieces if kind == "cmd" else out_lines
            with self.subTest(row=row):
                self.assertTrue(any(c.startswith(shown) for c in candidates),
                                "%s row not traceable to the transcript: %r" % (kind, row))


if __name__ == "__main__":
    unittest.main()
