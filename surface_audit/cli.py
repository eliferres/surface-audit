"""The command line: read the config, run every rule on every surface, write the report, exit."""
from __future__ import annotations

import argparse
import sys
import time
from typing import List, Optional

from . import __version__
from .config import ConfigError, Surface, load
from .database import database_rows
from .files import secret_rows, tracked_rows
from .report import exit_code, render_json, render_markdown, render_text, write_report
from .rules import Row
from .web import http_urls, page_rows, redirect_row, refusal_row


def audit(surface: Surface) -> List[Row]:
    """Every rule that the surface's config gives something to check, in rule order."""
    rows: List[Row] = []
    for url in surface.urls:
        rows += page_rows(surface, url)
    if surface.urls or surface.http_url:
        rows += [redirect_row(surface, url) for url in http_urls(surface)]
    if surface.postgrest_url:
        rows += database_rows(surface)
    rows += [refusal_row(surface, url) for url in surface.must_refuse]
    if surface.built_dir:
        rows += secret_rows(surface)
    if surface.repo_dir:
        rows += tracked_rows(surface)
    return rows


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:   # one line on stderr, exit 2
        self.exit(2, "%s: %s (see --help)\n" % (self.prog, message))


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = _Parser(prog="surface-audit",
                     description="Read-only security checks of the public surfaces you run.")
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    commands = parser.add_subparsers(dest="command", metavar="run", parser_class=_Parser)
    commands.required = True
    run = commands.add_parser("run", help="audit every surface in a config file and write a dated report")
    run.add_argument("config", help="the surfaces.json file")
    run.add_argument("--json", action="store_true", help="print every row as JSON instead of the summary lines")
    run.add_argument("--out", default="reports", metavar="DIR",
                     help="folder for the dated report (default: reports, in the current directory)")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> None:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        surfaces = load(args.config)   # every config problem, a service-role key included, stops here
        started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        rows = [row for surface in surfaces for row in audit(surface)]
        path = write_report(args.out, render_markdown(rows, args.config, started))
    except ConfigError as error:
        print("surface-audit: %s" % error, file=sys.stderr)
        sys.exit(2)
    except OSError as error:
        print("surface-audit: cannot write the report in %s: %s" % (args.out, error.strerror or error),
              file=sys.stderr)
        sys.exit(2)
    except Exception as error:   # a bug must still end in one line and exit 2, never a traceback
        print("surface-audit: internal error: %s: %s" % (type(error).__name__, error), file=sys.stderr)
        sys.exit(2)
    print(render_json(rows, path) if args.json else render_text(rows, path))
    sys.exit(exit_code(rows))
