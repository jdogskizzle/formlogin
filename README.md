# formlogin

Form login for small single-user web apps behind a reverse proxy: a sign-in page, a signed
session cookie, a limit on failed logins, and a cross-site check on changes. Standard
library only. Used by mcpanel, miner, ledger and musicflow.

## Setting the password

In the app's running container, the same command for every app:

    docker compose exec <service> python -m formlogin passwd

It asks for the password (and a username, unless the app's environment fixes one) and
saves the hash in `login.json` in the app's state folder. The running app uses it right
away, no restart, and every device is signed out.

A new app with no password yet shows a set-password page instead of the sign-in page.
It needs the one-time setup code the app prints to its log (`docker logs <container>`),
so nobody else can claim it first. Forgot the password? Run `passwd` again, or delete
`login.json` to get the setup page back.

## What it does

- Every request needs a session except the sign-in page (and whatever the app marks
  public). API calls (`/api/...`) without one get `401`; pages are redirected to `login`.
- It answers `GET`/`POST /login` and `POST /logout` itself.
- Sessions last 30 days, in an `HttpOnly`, `SameSite=Lax` cookie (`Secure` when the
  proxy reports HTTPS) with no `Path`, so the browser scopes it to the folder the app
  is served from and other apps on the same host never see it.
- They're signed with a random key (`session.key` in the state folder, made on first
  start), mixed with the username and password hash. Changing either, or deleting the
  key, signs every device out.
- Failed sign-ins (and wrong setup codes) take an extra second, one password check runs
  at a time, and an address gets 5 failures per 15 minutes (50 for all addresses together pauses sign-in
  for a minute). The address is the last `X-Forwarded-For` entry, so the proxy must set
  that header itself (Caddy does).
- `POST`s etc. from other sites are refused (`Origin` / `Sec-Fetch-Site`).
- Responses get `X-Content-Type-Options`, `X-Frame-Options: DENY` and `Referrer-Policy`.

## Settings

None are needed. Each app picks an environment prefix:

| Variable | |
|---|---|
| `<PREFIX>_USERNAME` | Fixes the login name; otherwise it's chosen along with the password |
| `<PREFIX>_PASSWORD_HASH` | Fixes the password instead of `login.json` (and `passwd` then refuses to change it). `python -m formlogin hash` makes one (scrypt); older bcrypt hashes (`$2b$...`) work where the `bcrypt` package is installed |
| `<PREFIX>_AUTH` | `off` turns sign-in off, only for apps nothing untrusted can reach. Default `on` |

The app fails to start, with a message saying what's wrong, if these or `login.json`
aren't usable. A `login.json` changed while it runs that it can't use is ignored (the
log says why) and the last good password keeps working.

## Using it

The apps' Dockerfiles copy the `formlogin/` package in from a build context, pinned to
a tag of this repo (point `FORMLOGIN_SRC` at a local checkout to try changes):

```yaml
# docker-compose.yml
build:
  context: .
  additional_contexts:
    formlogin: ${FORMLOGIN_SRC:-https://github.com/jdogskizzle/formlogin.git#v2.0.0}
```
```dockerfile
COPY --from=formlogin formlogin /app/formlogin
```

FastAPI / Starlette:

```python
import formlogin, formlogin.asgi
login = formlogin.Login.from_env("LEDGER", "ledger", "/data",
                                 title="Server Fund", accent=("#3f7d36", "#6fbf62"))
formlogin.asgi.install(app, login)
```

`http.server` (use a `ThreadingHTTPServer`; a sign-in attempt blocks its thread briefly):

```python
import formlogin, formlogin.httpserver
LOGIN = formlogin.Login.from_env("CONTROL", "miner", "/state", title="Miner")

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split("?")[0]
        if formlogin.httpserver.handle(self, LOGIN, path):
            return
        ...  # the app; add formlogin.SECURITY_HEADERS to its responses
```

The third argument is the state folder: a volume the app keeps, where `login.json` and
`session.key` go. `passwd` finds it through a note the running app leaves in the
container's temp folder; outside one, name it: `python -m formlogin passwd <folder>`.

Options for `Login`: `title`, `accent` (light, dark button colour), `icon` (favicon
URL), and `is_public(method, path, headers, peer)` for requests that need no session,
e.g. Prometheus scraping the container directly:

```python
is_public=lambda m, path, h, peer: path == "/metrics" and formlogin.direct_private(h, peer)
```

The page itself should send the user to `login` on a `401`, and sign out with
`<form method="post" action="logout"><button>Sign out</button></form>`.

## Tests

    python -m unittest discover tests

The FastAPI tests are skipped unless `fastapi` and `httpx` are installed.

## License

[MIT](LICENSE)
