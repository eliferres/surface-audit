"""Serve the two demo surfaces on 127.0.0.1:47613 while one command runs, then stop.

    python3 demo/fake_site.py python3 -m surface_audit run demo/surfaces.json

"shop" is configured well. "blog" has a short HSTS max-age, no
Content-Security-Policy, no framing rule, no referrer policy, serves plain
http without a redirect, and a subscribers table that answers rows to the
public key. Exits with the command's exit status.
"""
import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 47613
JSON = {"Content-Type": "application/json"}
SHOP_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; frame-ancestors 'none'; object-src 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}
BLOG_HEADERS = {
    "Strict-Transport-Security": "max-age=15552000",
    "X-Content-Type-Options": "nosniff",
    "Permissions-Policy": "camera=()",
}
DENIED = (401, JSON, b'{"code":"42501","message":"permission denied"}')


def openapi(*tables):
    paths = {"/": {}, **{"/" + t: {} for t in tables}}
    return 200, {"Content-Type": "application/openapi+json"}, json.dumps({"swagger": "2.0", "paths": paths}).encode()


ROUTES = {
    "/shop/": (200, SHOP_HEADERS, b"<h1>Shop</h1>"),
    "/shop-http/": (301, {"Location": "https://shop.example.com/"}, b""),
    "/shop/api/orders": DENIED,
    "/shop-db/rest/v1/": openapi("orders", "profiles"),
    "/shop-db/rest/v1/orders": (200, JSON, b"[]"),
    "/shop-db/rest/v1/profiles": DENIED,
    "/blog/": (200, BLOG_HEADERS, b"<h1>Blog</h1>"),
    "/blog/api/drafts": DENIED,
    "/blog-db/rest/v1/": openapi("posts", "subscribers"),
    "/blog-db/rest/v1/posts": (200, JSON, b'[{"id":1,"title":"Hello"}]'),
    "/blog-db/rest/v1/subscribers": (200, JSON, b'[{"id":1,"email":"reader@example.com"}]'),
}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        status, headers, body = ROUTES.get(self.path.split("?")[0], (404, {}, b"not found"))
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command == "GET":
            self.wfile.write(body)

    do_HEAD = do_GET

    def log_message(self, *args):
        pass


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: python3 demo/fake_site.py COMMAND [ARG ...]")
    try:
        server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    except OSError as error:
        sys.exit("fake_site: cannot listen on 127.0.0.1:%d: %s" % (PORT, error.strerror))
    threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True).start()
    try:
        status = subprocess.call(sys.argv[1:])
    finally:
        server.shutdown()
        server.server_close()
    sys.exit(status)


if __name__ == "__main__":
    main()
