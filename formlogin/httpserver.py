"""formlogin for apps built on http.server.BaseHTTPRequestHandler:

    import formlogin, formlogin.httpserver
    LOGIN = formlogin.Login.from_env("CONTROL", "miner", "/state", title="Miner")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            path = self.path.split("?")[0]
            if formlogin.httpserver.handle(self, LOGIN, path):
                return
            ...

Call it first in every do_* method. Use formlogin.SECURITY_HEADERS in your own responses.
Run the server as a ThreadingHTTPServer: a sign-in attempt blocks its thread for a moment.
"""
from . import MAX_FORM, SECURITY_HEADERS, Login


def handle(handler, login: Login, path: str) -> bool:
    """Answers the request if formlogin should (sign-in page, refusals, redirects) and
    returns True; returns False when the app should handle it. path: the app's own path."""
    method = handler.command
    body = b""
    if login.needs_body(method, path):
        n = int(handler.headers.get("content-length") or 0)
        # Read at most one byte past the limit so an oversized form is refused, not read.
        body = handler.rfile.read(min(n, MAX_FORM + 1)) if n > 0 else b""
        if n > MAX_FORM:
            handler.close_connection = True
    r = login.handle(method, path, handler.headers, handler.client_address[0], body)
    if r is None:
        return False
    handler.send_response(r.status)
    handler.send_header("Content-Type", r.content_type)
    handler.send_header("Content-Length", str(len(r.body)))
    handler.send_header("Cache-Control", "no-store")
    for k, v in SECURITY_HEADERS + [h for h in r.headers if h[0] != "Cache-Control"]:
        handler.send_header(k, v)
    handler.end_headers()
    if method != "HEAD":
        handler.wfile.write(r.body)
    return True
