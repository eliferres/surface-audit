"""surface-audit: read-only security checks of the public surfaces you run.

For each surface in a config file it grades the security headers of the
listed pages, the plain-http redirect, whether each database table answers
rows to the public key with no session, whether data routes refuse a request
with no session, whether the built files carry a secret, and whether git
tracks an env or key file. It sends only GET and HEAD, and writes a dated
report in which every row names the exact request and the answer that
decided it.
"""
from __future__ import annotations

__version__ = "0.1.0"

from .rules import HEADER_RULES, RULES, Row  # noqa: E402
from .config import ConfigError, Surface, jwt_claims, load  # noqa: E402
from .net import Answer, Unreachable, fetch  # noqa: E402

__all__ = ["Answer", "ConfigError", "HEADER_RULES", "RULES", "Row", "Surface", "Unreachable", "fetch", "jwt_claims",
           "load"]
