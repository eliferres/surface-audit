"""The file rules: secrets in the built site (S1) and env or key files tracked by git (G1)."""
from __future__ import annotations

import fnmatch
import hashlib
import os
import re
import subprocess
from typing import List, Optional, Pattern, Set, Tuple

from .config import Surface, jwt_claims
from .rules import ERROR, FAIL, PASS, Row

CHUNK = 1024 * 1024    # bytes read at a time, so a ten-megabyte bundle never sits in memory whole
OVERLAP = 8192         # carried into the next chunk; longer than any shape below, so none is cut in two

# Prefixes are written as character classes ([-], [po]) so this file does not match its own patterns.
SHAPES: List[Tuple[str, Pattern[bytes]]] = [
    ("service-role JWT", re.compile(rb"eyJ[A-Za-z0-9_-]{8,2000}\.eyJ[A-Za-z0-9_-]{8,4000}\.[A-Za-z0-9_-]{0,1000}")),
    ("Anthropic API key", re.compile(rb"sk[-]ant[-][A-Za-z0-9_-]{20,200}")),
    ("Stripe live secret key", re.compile(rb"(?<![A-Za-z0-9])sk_live_[A-Za-z0-9]{20,200}")),
    ("AWS access key id", re.compile(rb"(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}(?![A-Za-z0-9])")),
    ("GitHub token", re.compile(rb"(?<![A-Za-z0-9])gh[po]_[A-Za-z0-9]{36}(?![A-Za-z0-9])")),
    ("private key", re.compile(rb"-----BEGIN ([A-Z0-9]+ )*PRIVATE KEY-----")),
]

ENV_ALLOWED = (".env.example", ".env.sample")
KEY_PATTERNS = ("*.pem", "*.key", "*.p12", "*.pfx")


def _is_secret(shape: str, text: bytes, allowed: Set[str]) -> bool:
    if hashlib.sha256(text).hexdigest() in allowed:
        return False
    if shape == "service-role JWT":   # any other JWT, such as the public anon key, is meant to be public
        claims = jwt_claims(text.decode("ascii"))
        return bool(claims) and claims.get("role") == "service_role"
    return True


def scan_file(path: str, allowed: Set[str]) -> List[Tuple[int, str]]:
    """(byte offset, shape) of every secret shape in the file, read in overlapping chunks.

    A match that starts inside the overlap is left for the next round, where
    it is read whole, so a secret across a chunk edge is found exactly once.
    """
    found = []
    with open(path, "rb") as f:
        buf, offset = b"", 0
        while True:
            chunk = f.read(CHUNK)
            final = not chunk
            buf += chunk
            cut = len(buf) if final else max(0, len(buf) - OVERLAP)
            for shape, pattern in SHAPES:
                found += [(offset + m.start(), shape) for m in pattern.finditer(buf)
                          if m.start() < cut and _is_secret(shape, m.group(), allowed)]
            if final:
                return sorted(found)
            offset += cut
            buf = buf[cut:]


def _files(root: str) -> List[str]:
    paths = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        paths += [os.path.join(dirpath, name) for name in sorted(filenames)]
    return paths


def secret_rows(surface: Surface) -> List[Row]:
    """S1: every file under built_dir; the configured anon key is allow-listed by its SHA-256."""
    root = surface.built_dir or ""
    allowed = {hashlib.sha256(surface.anon_key.encode()).hexdigest()} if surface.anon_key else set()
    rows, files = [], _files(root)
    for path in files:
        shown = os.path.relpath(path, root).replace(os.sep, "/")
        try:
            hits = scan_file(path, allowed)
        except OSError as error:
            rows.append(Row(surface.name, "S1", ERROR, "read %s" % path, "cannot read: %s" % error.strerror,
                            "a file that cannot be read cannot be cleared"))
            continue
        rows += [Row(surface.name, "S1", FAIL, "read %s" % path, "%s at byte %d" % (shape, at),
                     "%s in %s, a file the browser can download" % (shape, shown)) for at, shape in hits]
    if not rows:
        rows.append(Row(surface.name, "S1", PASS, "read %d files under %s" % (len(files), root),
                        "no secret shape", "no service-role token, provider key or private key"))
    return rows


def tracked_secret(path: str) -> Optional[str]:
    """Why a tracked path should not be in git, or None."""
    name = os.path.basename(path).lower()
    if name == ".env" or (name.startswith(".env.") and name not in ENV_ALLOWED):
        return "an environment file"
    if any(fnmatch.fnmatch(name, pattern) for pattern in KEY_PATTERNS):
        return "a key or certificate file"
    return None


def tracked_rows(surface: Surface) -> List[Row]:
    """G1: what git ls-files lists in repo_dir."""
    root = surface.repo_dir or ""
    request = "git ls-files in %s" % root
    try:
        done = subprocess.run(["git", "-C", root, "ls-files", "-z"], capture_output=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as error:
        return [Row(surface.name, "G1", ERROR, request, "git did not run: %s" % error, "no file list, so no verdict")]
    if done.returncode != 0:
        message = done.stderr.decode("utf-8", "replace").strip().splitlines()
        return [Row(surface.name, "G1", ERROR, request, message[0] if message else "git failed",
                    "no file list, so no verdict")]
    paths = [p for p in done.stdout.decode("utf-8", "replace").split("\0") if p]
    rows = [Row(surface.name, "G1", FAIL, request, "tracked: %s" % p, "%s is committed to git" % why)
            for p in paths for why in [tracked_secret(p)] if why]
    return rows or [Row(surface.name, "G1", PASS, request, "%d tracked files" % len(paths),
                        "no .env, .pem, .key, .p12 or .pfx file is tracked")]
