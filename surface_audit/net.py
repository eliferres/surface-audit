"""HTTP for the audit: GET and HEAD only, no cookies, redirects followed by hand.

Every request the tool makes goes through fetch(), which refuses any other
verb, so the audit cannot change anything on the surfaces it reads.
"""
from __future__ import annotations

import http.client
import socket
import ssl
import urllib.error
import urllib.request
from email.message import Message
from typing import Dict, NamedTuple, Optional
from urllib.parse import urljoin

from . import __version__

TIMEOUT = 15.0                    # seconds per request
MAX_HOPS = 5                      # redirects followed before giving up
MAX_BODY = 10 * 1024 * 1024       # bytes read from a body; an OpenAPI description of a large schema fits
READ_ONLY = ("GET", "HEAD")
REDIRECTS = (301, 302, 303, 307, 308)
USER_AGENT = "surface-audit/%s (+https://github.com/eliferres/surface-audit)" % __version__


class Unreachable(Exception):
    """No HTTP answer to grade: refused, reset twice, timed out, a TLS failure, or a redirect loop."""


class Malformed(Unreachable):
    """The server answered, but not with a readable HTTP response."""


class Answer(NamedTuple):
    status: int
    headers: Message
    body: bytes
    url: str     # the URL that gave this answer, after any redirects
    hops: int    # redirects followed to reach it


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Hand every 3xx back to fetch(), which counts the hops and reports the final URL."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


# build_opener adds no cookie handler, so no session is ever carried between requests.
_OPENER = urllib.request.build_opener(_NoRedirect)


def _describe(cause: object) -> str:
    if isinstance(cause, (socket.timeout, TimeoutError)):
        return "no answer within %g seconds" % TIMEOUT
    if isinstance(cause, ConnectionRefusedError):
        return "connection refused"
    if isinstance(cause, socket.gaierror):
        return "host name not found"
    if isinstance(cause, ssl.SSLCertVerificationError):
        return "TLS certificate not trusted: %s" % cause.verify_message
    if isinstance(cause, http.client.HTTPException):
        return "malformed answer (%s: %r)" % (type(cause).__name__, str(cause)[:80])
    return " ".join(str(cause).split()) or type(cause).__name__   # one line, whatever the cause holds


def _once(method: str, url: str, headers: Dict[str, str], read_body: bool) -> Answer:
    request = urllib.request.Request(url, method=method, headers={"User-Agent": USER_AGENT, **headers})
    try:
        response = _OPENER.open(request, timeout=TIMEOUT)
    except urllib.error.HTTPError as error:   # a 3xx, 4xx or 5xx is an answer, not a failure
        response = error
    try:
        body = response.read(MAX_BODY) if read_body and method == "GET" else b""
    finally:
        response.close()
    return Answer(response.getcode(), response.headers, body, url, 0)


_NETWORK_ERRORS = (urllib.error.URLError, OSError, http.client.HTTPException)


def _cause(error: Exception) -> object:
    return error.reason if isinstance(error, urllib.error.URLError) else error


def _unreachable(cause: object) -> Unreachable:
    kind = Malformed if isinstance(cause, http.client.HTTPException) else Unreachable
    return kind(_describe(cause))


def _with_retry(method: str, url: str, headers: Dict[str, str], read_body: bool) -> Answer:
    """One request, retried once when the connection is reset (a CDN edge recycling a socket)."""
    try:
        return _once(method, url, headers, read_body)
    except _NETWORK_ERRORS as error:
        if not isinstance(_cause(error), ConnectionResetError):
            raise _unreachable(_cause(error)) from None
    try:
        return _once(method, url, headers, read_body)
    except _NETWORK_ERRORS as error:
        raise _unreachable(_cause(error)) from None


def fetch(method: str, url: str, headers: Optional[Dict[str, str]] = None, *,
          follow: bool = True, read_body: bool = False) -> Answer:
    """Send one GET or HEAD and return the answer, following up to MAX_HOPS redirects.

    With follow=False a 3xx is returned as the answer. Raises Unreachable when
    no answer arrives or the redirects do not end within MAX_HOPS.
    """
    if method not in READ_ONLY:
        raise ValueError("surface-audit only sends GET and HEAD, not %s" % method)
    hops = 0
    while True:
        answer = _with_retry(method, url, headers or {}, read_body)
        location = answer.headers.get("Location")
        if not follow or answer.status not in REDIRECTS or not location:
            return answer._replace(hops=hops)
        if hops == MAX_HOPS:
            raise Unreachable("more than %d redirects, last at %s" % (MAX_HOPS, url))
        url = urljoin(url, location)
        hops += 1
