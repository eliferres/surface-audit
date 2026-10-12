"""Reading and checking surfaces.json before a single request is sent."""
from __future__ import annotations

import base64
import binascii
import json
import os
from typing import Any, Dict, List, NamedTuple, Optional
from urllib.parse import urlsplit

from .rules import HEADER_RULES


class ConfigError(Exception):
    """The config cannot be run as written: exit 2."""


class Surface(NamedTuple):
    name: str
    urls: List[str]
    skip: List[str]
    http_url: Optional[str]
    postgrest_url: Optional[str]
    anon_key: Optional[str]
    tables: List[str]
    public_tables: List[str]
    must_refuse: List[str]
    built_dir: Optional[str]   # resolved against the config file's folder
    repo_dir: Optional[str]


LIST_FIELDS = ("urls", "skip", "tables", "public_tables", "must_refuse")
TEXT_FIELDS = ("http_url", "postgrest_url", "anon_key", "built_dir", "repo_dir")
FIELDS = ("name",) + LIST_FIELDS + TEXT_FIELDS
CHECK_FIELDS = ("urls", "postgrest_url", "must_refuse", "built_dir", "repo_dir")


def jwt_claims(token: str) -> Optional[Dict[str, Any]]:
    """The payload of a JSON Web Token, or None when the text is not one. The signature is not checked."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        payload = base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
        claims = json.loads(payload)
    except (binascii.Error, ValueError):
        return None
    return claims if isinstance(claims, dict) else None


def _is_web_url(value: str) -> bool:
    parts = urlsplit(value)
    return parts.scheme in ("http", "https") and bool(parts.netloc)


def _surface(raw: Any, index: int, base: str) -> Surface:
    if not isinstance(raw, dict):
        raise ConfigError("surface %d is not an object" % index)
    name = raw.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ConfigError("surface %d has no name" % index)
    where = "surface %r" % name
    unknown = sorted(set(raw) - set(FIELDS))
    if unknown:
        raise ConfigError("%s: unknown field %r (known: %s)" % (where, unknown[0], ", ".join(FIELDS)))
    for field in LIST_FIELDS:
        value = raw.get(field, [])
        if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
            raise ConfigError("%s: %s must be a list of strings" % (where, field))
    for field in TEXT_FIELDS:
        if field in raw and (not isinstance(raw[field], str) or not raw[field]):
            raise ConfigError("%s: %s must be a non-empty string" % (where, field))
    if not any(raw.get(field) for field in CHECK_FIELDS):
        raise ConfigError("%s: nothing to check (give at least one of %s)" % (where, ", ".join(CHECK_FIELDS)))
    for field in ("urls", "must_refuse"):
        for url in raw.get(field, []):
            if not _is_web_url(url):
                raise ConfigError("%s: %s entry is not an http or https URL: %s" % (where, field, url))
    for field in ("http_url", "postgrest_url"):
        if field in raw and not _is_web_url(raw[field]):
            raise ConfigError("%s: %s is not an http or https URL: %s" % (where, field, raw[field]))
    bad_skip = [r for r in raw.get("skip", []) if r not in HEADER_RULES]
    if bad_skip:
        raise ConfigError("%s: skip names %r; only the header rules %s can be skipped"
                          % (where, bad_skip[0], ", ".join(HEADER_RULES)))
    if ("postgrest_url" in raw) != ("anon_key" in raw):
        raise ConfigError("%s: postgrest_url and anon_key go together" % where)
    if ("tables" in raw or "public_tables" in raw) and "postgrest_url" not in raw:
        raise ConfigError("%s: tables and public_tables need a postgrest_url" % where)
    if "anon_key" in raw:
        # A key that bypasses row security would turn the audit into a reader of private data. Supabase has
        # two formats: the older JWT keys carry a role claim, the newer ones a sb_secret_ or sb_publishable_ prefix.
        claims = jwt_claims(raw["anon_key"])
        if claims and claims.get("role") == "service_role":
            secret = "carries the service_role claim"
        elif raw["anon_key"].startswith("sb_secret_"):
            secret = "is a Supabase secret key (sb_secret_)"
        else:
            secret = ""
        if secret:
            raise ConfigError("%s: anon_key %s; give the public anon or publishable key, "
                              "never a key that bypasses row security" % (where, secret))
    paths = {}
    for field in ("built_dir", "repo_dir"):
        if field in raw:
            path = os.path.normpath(os.path.join(base, raw[field]))
            if not os.path.isdir(path):
                raise ConfigError("%s: %s is not a folder: %s" % (where, field, path))
            paths[field] = path
    return Surface(
        name=name, urls=raw.get("urls", []), skip=raw.get("skip", []), http_url=raw.get("http_url"),
        postgrest_url=raw.get("postgrest_url"), anon_key=raw.get("anon_key"), tables=raw.get("tables", []),
        public_tables=raw.get("public_tables", []), must_refuse=raw.get("must_refuse", []),
        built_dir=paths.get("built_dir"), repo_dir=paths.get("repo_dir"),
    )


def load(path: str) -> List[Surface]:
    """Every surface in the config, checked in full; any problem raises ConfigError naming it."""
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except OSError as error:
        raise ConfigError("cannot read %s: %s" % (path, error.strerror or error)) from None
    if not text.strip():
        raise ConfigError("%s is empty" % path)
    try:
        data = json.loads(text)
    except ValueError as error:
        raise ConfigError("%s is not valid JSON: %s" % (path, error)) from None
    if not isinstance(data, dict) or set(data) != {"surfaces"}:
        raise ConfigError('%s must be an object with one field, "surfaces"' % path)
    raw = data["surfaces"]
    if not isinstance(raw, list) or not raw:
        raise ConfigError("%s lists no surfaces" % path)
    base = os.path.dirname(path)
    surfaces = [_surface(item, n, base) for n, item in enumerate(raw, 1)]
    names = [s.name for s in surfaces]
    duplicate = next((n for n in names if names.count(n) > 1), None)
    if duplicate:
        raise ConfigError("surface name %r is used twice" % duplicate)
    return surfaces
