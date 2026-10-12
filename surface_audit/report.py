"""The dated report file, the console lines and the JSON."""
from __future__ import annotations

import json
import os
import secrets
import time
from typing import Dict, List

from . import __version__
from .rules import ERROR, FAIL, PASS, SKIP, WARN, Row

RESULT_ORDER = (FAIL, ERROR, WARN, PASS)


def counts(rows: List[Row]) -> Dict[str, int]:
    return {result: sum(1 for r in rows if r.result == result) for result in RESULT_ORDER}


def verdict(rows: List[Row]) -> str:
    """ERROR when any row had no answer (never a pass), else FAIL on any failure, else PASS."""
    c = counts(rows)
    return "ERROR" if c[ERROR] else "FAIL" if c[FAIL] else "PASS"


def exit_code(rows: List[Row]) -> int:
    return {"PASS": 0, "FAIL": 1, "ERROR": 2}[verdict(rows)]


def summary(rows: List[Row]) -> str:
    c = counts(rows)
    return "%s: %d failing, %d warning, %d passing, %d errors" % (
        verdict(rows), c[FAIL], c[WARN], c[PASS], c[ERROR])


def _cell(text: str) -> str:
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ") or " "


def render_markdown(rows: List[Row], config: str, started: str) -> str:
    lines = [
        "# surface-audit report",
        "",
        "- Run: %s" % started,
        "- Tool: surface-audit %s" % __version__,
        "- Config: %s" % config,
        "- %s" % summary(rows),
        "",
        "Each row can be re-run by hand. The request column is the exact method and URL sent, with no cookie "
        "and no session; database requests carry only the public key from the config, in the `apikey` "
        "header and, when the key is a JWT, as a bearer token. No row content from any table is recorded.",
        "",
        "| Surface | Rule | Result | Request | Answer | Why |",
        "|---|---|---|---|---|---|",
    ]
    lines += ["| %s |" % " | ".join(_cell(x) for x in row) for row in rows]
    return "\n".join(lines) + "\n"


def render_text(rows: List[Row], report_path: str) -> str:
    """One line per row that is not a pass, then the verdict and where the full report is."""
    lines = ["%-5s %s  %s  %s (%s)" % (r.result, r.rule, r.surface, r.detail if r.result != ERROR else r.answer,
                                       r.request)
             for r in rows if r.result not in (PASS, SKIP)]
    lines.append("%s; report %s" % (summary(rows), report_path))
    return "\n".join(lines)


def render_json(rows: List[Row], report_path: str) -> str:
    return json.dumps({
        "version": __version__,
        "verdict": verdict(rows),
        "counts": counts(rows),
        "report": report_path,
        "rows": [row._asdict() for row in rows],
    }, indent=2)


def write_report(directory: str, text: str) -> str:
    """Write to <directory>/<YYYY-MM-DD>-<HHMM>-<6 hex>.md and return the path. Never overwrites a file."""
    os.makedirs(directory, exist_ok=True)
    minute = time.strftime("%Y-%m-%d-%H%M")
    while True:
        path = os.path.join(directory, "%s-%s.md" % (minute, secrets.token_hex(3)))
        try:
            with open(path, "x", encoding="utf-8") as f:   # "x": fail rather than overwrite
                f.write(text)
            return path
        except FileExistsError:
            continue
