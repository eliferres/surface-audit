"""A local HTTP server in a thread that answers from a table and records every request it receives."""
from __future__ import annotations

import socket
import threading
import time
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Dict, List, Tuple, Union

# path (with its query) -> (status, headers, body), or a callable taking the handler that answers by itself
Route = Union[Tuple[int, Dict[str, str], bytes], Callable[[BaseHTTPRequestHandler], None]]


class FakeServer:
    def __init__(self, routes: Dict[str, Route]) -> None:
        self.routes = routes
        self.requests: List[Tuple[str, str, Message]] = []   # (verb, path, headers)
        server = self

        class Handler(BaseHTTPRequestHandler):
            def parse_request(self) -> bool:   # runs for every verb, including ones with no do_ method
                ok = super().parse_request()
                if ok:
                    server.requests.append((self.command, self.path, self.headers))
                return ok

            def _answer(self, with_body: bool) -> None:
                route = server.routes.get(self.path, server.routes.get(self.path.split("?")[0]))
                if callable(route):
                    route(self)
                    return
                status, headers, body = route or (404, {}, b"not found")
                self.send_response(status)
                for name, value in headers.items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if with_body:
                    self.wfile.write(body)

            def do_GET(self) -> None:
                self._answer(True)

            def do_HEAD(self) -> None:
                self._answer(False)

            def log_message(self, *args: object) -> None:
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.httpd.handle_error = lambda request, address: None   # a client that hung up is expected in tests
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, args=(0.02,), daemon=True)

    def url(self, path: str = "/") -> str:
        return "http://127.0.0.1:%d%s" % (self.port, path)

    def verbs(self) -> List[str]:
        return [verb for verb, _, _ in self.requests]

    def __enter__(self) -> "FakeServer":
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def hang_up(handler: BaseHTTPRequestHandler) -> None:
    """Close the connection without an answer, which the client sees as a reset."""
    handler.close_connection = True


def slow(seconds: float) -> Callable[[BaseHTTPRequestHandler], None]:
    def answer(handler: BaseHTTPRequestHandler) -> None:
        time.sleep(seconds)
        handler.close_connection = True
    return answer


def closed_port() -> int:
    """A port with nothing listening on it."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
