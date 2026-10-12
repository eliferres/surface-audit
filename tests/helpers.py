"""Small builders shared by the tests."""
from __future__ import annotations

import base64
import json
from email.message import Message
from typing import Any, Dict

from surface_audit import Surface


def headers(**values: str) -> Message:
    """A header block; Content_Security_Policy becomes Content-Security-Policy."""
    message = Message()
    for name, value in values.items():
        message[name.replace("_", "-")] = value
    return message


def surface(**fields: Any) -> Surface:
    base: Dict[str, Any] = dict(name="site", urls=[], skip=[], http_url=None, postgrest_url=None, anon_key=None,
                                tables=[], public_tables=[], must_refuse=[], built_dir=None, repo_dir=None)
    base.update(fields)
    return Surface(**base)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def make_jwt(role: str) -> str:
    """An unsigned-looking token with the given role claim. Nothing verifies the signature."""
    head = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = _b64(json.dumps({"iss": "example", "role": role, "exp": 4102444800}).encode())
    return "%s.%s.%s" % (head, body, _b64(b"test-signature-not-real"))
