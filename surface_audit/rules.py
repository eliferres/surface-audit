"""The rule set and the one record every check produces."""
from __future__ import annotations

from typing import NamedTuple

# id -> (what it checks, why). The README's rule table is tested against this.
RULES = {
    "H1": ("Strict-Transport-Security", "max-age of at least 15552000 (180 days); below 31536000 is a warning"),
    "H2": ("Content-Security-Policy", "present; 'unsafe-inline' or 'unsafe-eval' for scripts, or default-src *, "
                                      "is a warning"),
    "H3": ("Framing", "frame-ancestors in the policy, or X-Frame-Options DENY or SAMEORIGIN"),
    "H4": ("X-Content-Type-Options", "nosniff"),
    "H5": ("Referrer-Policy", "present; a warning when missing"),
    "H6": ("Permissions-Policy", "present; a warning when missing"),
    "H7": ("HTTPS redirect", "a plain http:// request to the host is redirected to https://"),
    "T1": ("Table list", "the REST service describes its tables, or the config lists them"),
    "T2": ("Anonymous reads", "each table answers no rows to the public key with no session"),
    "R1": ("Refusal", "each must_refuse URL answers 401 or 403 with no session"),
    "S1": ("Secrets in built files", "no service-role token, provider key or private key in a file a browser "
                                     "can download"),
    "G1": ("Tracked env and key files", "git tracks no .env file and no .pem, .key, .p12 or .pfx file"),
}

HEADER_RULES = ("H1", "H2", "H3", "H4", "H5", "H6", "H7")

PASS, WARN, FAIL, ERROR, SKIP = "pass", "warn", "fail", "error", "skip"


class Row(NamedTuple):
    """One rule's verdict on one surface: what was asked and the answer that decided it."""
    surface: str
    rule: str
    result: str    # pass, warn, fail, error (no answer, so no verdict) or skip (turned off in the config)
    request: str   # the exact request, e.g. "GET https://example.com/", or the file read
    answer: str    # the status and the header value, or its absence
    detail: str    # one plain sentence on why this result
