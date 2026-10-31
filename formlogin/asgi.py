"""formlogin for FastAPI / Starlette apps:

    import formlogin, formlogin.asgi
    login = formlogin.Login.from_env("LEDGER", "ledger", "/data/session.key", title="Ledger")
    formlogin.asgi.install(app, login)

Adds a middleware that answers /login and /logout, gates everything else, and adds the
security headers to every response.
"""
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import Response as StarletteResponse

from . import SECURITY_HEADERS, Login, Response


def _send(r: Response) -> StarletteResponse:
    resp = StarletteResponse(r.body, r.status, media_type=r.content_type)
    for k, v in r.headers:
        resp.headers.append(k, v)
    return resp


def install(app, login: Login) -> None:
    @app.middleware("http")
    async def formlogin_gate(request: Request, call_next):
        method, path = request.method, request.url.path
        peer = request.client.host if request.client else ""
        if login.needs_body(method, path):
            body = await request.body()
            # The password check is slow on purpose; keep it off the event loop.
            r = await run_in_threadpool(login.handle, method, path, request.headers, peer, body)
        else:
            r = login.handle(method, path, request.headers, peer)
        resp = _send(r) if r else await call_next(request)
        for k, v in SECURITY_HEADERS:
            resp.headers[k] = v
        return resp
