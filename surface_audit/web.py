"""The page rules (H1 to H7) and the refusal rule (R1)."""
from __future__ import annotations

import re
from email.message import Message
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlsplit

from .config import Surface
from .net import MAX_HOPS, REDIRECTS, Answer, Malformed, Unreachable, fetch
from .rules import ERROR, FAIL, PASS, SKIP, WARN, Row

HSTS_MIN = 15552000      # 180 days: the shortest max-age worth having
HSTS_GOOD = 31536000     # one year: the HSTS preload list's minimum

Verdict = Tuple[str, str, str]   # (result, the header line or its absence, why)

# A frame-ancestors source that matches any site: *, a bare scheme such as https:, or a wildcard host.
_ANY_SITE = re.compile(r"\*|[a-z][a-z0-9+.-]*:|([a-z][a-z0-9+.-]*://)?\*(:[0-9*]+)?(/.*)?")


def _value(headers: Message, name: str) -> Optional[str]:
    values = headers.get_all(name)
    return ", ".join(v.strip() for v in values) if values else None


def _shown(name: str, value: Optional[str]) -> str:
    return "%s: %s" % (name.lower(), value) if value is not None else "no %s header" % name.lower()


def csp_policies(headers: Message) -> List[Dict[str, List[str]]]:
    """Each Content-Security-Policy header as {directive: [sources]}; the first of a repeated directive wins."""
    policies = []
    for header in headers.get_all("Content-Security-Policy") or []:
        for policy in header.split(","):   # a comma separates policies sent in one header
            directives: Dict[str, List[str]] = {}
            for part in policy.split(";"):
                words = part.split()
                if words:
                    directives.setdefault(words[0].lower(), [w.lower() for w in words[1:]])
            if directives:
                policies.append(directives)
    return policies


def h1_hsts(headers: Message) -> Verdict:
    value = _value(headers, "Strict-Transport-Security")
    shown = _shown("Strict-Transport-Security", value)
    if value is None:
        return FAIL, shown, "no HSTS header, so a browser may still try plain http first"
    match = re.search(r'max-age\s*=\s*"?(\d+)"?', value, re.I)
    if not match:
        return FAIL, shown, "HSTS header has no readable max-age"
    age = int(match.group(1))
    if age < HSTS_MIN:
        return FAIL, shown, "max-age %d is below %d (180 days)" % (age, HSTS_MIN)
    if age < HSTS_GOOD:
        return WARN, shown, "max-age %d is below %d (one year)" % (age, HSTS_GOOD)
    return PASS, shown, "max-age %d" % age


def h2_csp(headers: Message) -> Verdict:
    value = _value(headers, "Content-Security-Policy")
    shown = _shown("Content-Security-Policy", value)
    if value is None:
        if _value(headers, "Content-Security-Policy-Report-Only") is not None:
            return FAIL, shown, "only Content-Security-Policy-Report-Only is set, which blocks nothing"
        return FAIL, shown, "no Content-Security-Policy header"
    weak = []
    for policy in csp_policies(headers):
        scripts = policy.get("script-src", policy.get("default-src", []))
        weak += [s for s in ("'unsafe-inline'", "'unsafe-eval'") if s in scripts]
        if "*" in policy.get("default-src", []):
            weak.append("default-src *")
    if weak:
        return WARN, shown, "the policy allows %s" % " and ".join(sorted(set(weak)))
    return PASS, shown, "a policy is set and scripts are not opened up"


def h3_framing(headers: Message) -> Verdict:
    for policy in csp_policies(headers):
        if "frame-ancestors" in policy:
            sources = policy["frame-ancestors"]
            line = ("content-security-policy: frame-ancestors %s" % " ".join(sources)).rstrip()
            # Browsers obey frame-ancestors over X-Frame-Options, so an open one decides the rule alone.
            opened = [s for s in sources if _ANY_SITE.fullmatch(s)]
            if opened:
                return FAIL, line, "frame-ancestors %s lets any site frame the page" % " ".join(opened)
            if not sources or sources == ["'none'"]:   # the CSP spec reads an empty list as "no source"
                return PASS, line, "'none' or an empty list blocks all framing"
            return PASS, line, "frame-ancestors limits who may frame the page"
    value = _value(headers, "X-Frame-Options")
    shown = _shown("X-Frame-Options", value)
    if value is not None and value.strip().upper() in ("DENY", "SAMEORIGIN"):
        return PASS, shown, "X-Frame-Options %s" % value.strip().upper()
    return FAIL, shown + " and no frame-ancestors", "any site can frame the page (clickjacking)"


def h4_nosniff(headers: Message) -> Verdict:
    value = _value(headers, "X-Content-Type-Options")
    shown = _shown("X-Content-Type-Options", value)
    if value is not None and value.strip().lower() == "nosniff":
        return PASS, shown, "nosniff"
    return FAIL, shown, "browsers may guess a file's type and run it as script"


def _present(name: str, why: str) -> Callable[[Message], Verdict]:
    def rule(headers: Message) -> Verdict:
        value = _value(headers, name)
        if value is None:
            return WARN, _shown(name, value), why
        return PASS, _shown(name, value), "present"
    return rule


h5_referrer = _present("Referrer-Policy", "the browser default decides how much of the URL other sites see")
h6_permissions = _present("Permissions-Policy", "camera, microphone and location are not turned off for "
                                                "embedded content")

PAGE_RULES = (("H1", h1_hsts), ("H2", h2_csp), ("H3", h3_framing), ("H4", h4_nosniff),
              ("H5", h5_referrer), ("H6", h6_permissions))


def _request(method: str, url: str, answer: Optional[Answer] = None) -> str:
    line = "%s %s" % (method, url)
    if answer is not None and answer.url != url:
        line += " -> %s (%d redirect%s)" % (answer.url, answer.hops, "" if answer.hops == 1 else "s")
    return line


def page_rows(surface: Surface, url: str) -> List[Row]:
    """H1 to H6 for one URL, from the headers of a GET that follows redirects."""
    rules = [(rule, grade) for rule, grade in PAGE_RULES if rule not in surface.skip]
    rows = [Row(surface.name, rule, SKIP, "GET " + url, "", "skipped by the config")
            for rule, _ in PAGE_RULES if rule in surface.skip]
    if not rules:
        return rows
    try:
        answer = fetch("GET", url)
    except Unreachable as error:
        rows += [Row(surface.name, rule, ERROR, "GET " + url, "unreachable (%s)" % error, "no answer, so no verdict")
                 for rule, _ in rules]
    else:
        request = _request("GET", url, answer)
        for rule, grade in rules:
            result, line, why = grade(answer.headers)
            rows.append(Row(surface.name, rule, result, request, "%d %s" % (answer.status, line), why))
    return sorted(rows, key=lambda r: r.rule)


def http_urls(surface: Surface) -> List[str]:
    """Where H7 knocks: the config's http_url, else the root of each host over plain http."""
    if surface.http_url:
        return [surface.http_url]
    hosts = []
    for url in surface.urls:
        host = urlsplit(url).hostname or ""
        if host not in hosts:
            hosts.append(host)
    return ["http://%s/" % (("[%s]" % h) if ":" in h else h) for h in hosts]


def _head_or_get(url: str) -> Answer:
    """HEAD is enough to read a redirect; GET when a server refuses HEAD or answers it malformed."""
    try:
        answer = fetch("HEAD", url, follow=False)
    except Malformed:
        return fetch("GET", url, follow=False)
    return fetch("GET", url, follow=False) if answer.status in (405, 501) else answer


def _https_hop(url: str) -> Answer:
    """Follow plain-http redirects until one points at https."""
    hops = 0
    while True:
        answer = _head_or_get(url)
        location = answer.headers.get("Location")
        if answer.status not in REDIRECTS or not location:
            return answer._replace(hops=hops)
        target = urljoin(url, location)
        if urlsplit(target).scheme == "https" or hops == MAX_HOPS:
            return answer._replace(hops=hops)
        url, hops = target, hops + 1


def redirect_row(surface: Surface, url: str) -> Row:
    """H7: the plain-http door must send the browser to https."""
    if "H7" in surface.skip:
        return Row(surface.name, "H7", SKIP, "HEAD " + url, "", "skipped by the config")
    try:
        answer = _https_hop(url)
    except Unreachable as error:
        return Row(surface.name, "H7", ERROR, "HEAD " + url, "unreachable (%s)" % error, "no answer, so no verdict")
    request = _request(answer.method, url, answer)
    location = answer.headers.get("Location")
    line = "%d %s" % (answer.status, _shown("Location", location))
    if location and urlsplit(urljoin(answer.url, location)).scheme == "https":
        return Row(surface.name, "H7", PASS, request, line, "plain http is redirected to https")
    if answer.status in REDIRECTS:
        return Row(surface.name, "H7", FAIL, request, line, "still on plain http after %d redirects" % MAX_HOPS)
    return Row(surface.name, "H7", FAIL, request, line, "plain http is served without a redirect to https")


def refusal_row(surface: Surface, url: str) -> Row:
    """R1: a data route asked with no session must refuse. Redirects are not followed: a 302 to a login
    page is reported as it is, never graded by the login page's 200."""
    request = "GET " + url
    try:
        answer = fetch("GET", url, follow=False)
    except Unreachable as error:
        return Row(surface.name, "R1", ERROR, request, "unreachable (%s)" % error, "no answer, so no verdict")
    line = str(answer.status)
    if answer.headers.get("Location"):
        line += " location: %s" % answer.headers["Location"]
    if answer.status in (401, 403):
        return Row(surface.name, "R1", PASS, request, line, "refuses a request with no session")
    if 200 <= answer.status < 300:   # 204 and 206 are answers too; only a refusal keeps the data in
        return Row(surface.name, "R1", FAIL, request, line,
                   "answers %d to a request with no session" % answer.status)
    return Row(surface.name, "R1", WARN, request, line, "answers %d, not 401 or 403" % answer.status)
