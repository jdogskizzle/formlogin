"""Form login for small single-user web apps: a sign-in page, a signed session cookie,
a limit on failed logins, and a cross-site check on changes.

The core here knows nothing about web frameworks. Adapters wire it in:
    formlogin.asgi        FastAPI / Starlette apps
    formlogin.httpserver  apps built on http.server

Settings come from the environment, under a prefix the app picks (e.g. LEDGER):
    <PREFIX>_USERNAME       login name
    <PREFIX>_PASSWORD_HASH  made with: python -m formlogin hash
    <PREFIX>_AUTH           "off" turns sign-in off (only if nothing untrusted can reach
                            the app); anything else, or unset, leaves it on

Make a password hash:
    python -m formlogin hash
"""
import base64
import collections
import getpass
import hashlib
import hmac
import html
import ipaddress
import json
import os
import secrets
import sys
import threading
import time
from dataclasses import dataclass, field
from importlib import resources
from urllib.parse import parse_qs, urlparse

SESSION_DAYS = 30
FAIL_DELAY = 1.0                      # seconds added to each failed login
FAIL_WINDOW, FAIL_LIMIT = 15 * 60, 5  # failed logins allowed per address in the window
GLOBAL_LIMIT = 50                     # all addresses together, same window
MIN_PASSWORD = 12
MAX_FORM = 4096                       # bytes accepted in a login POST
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
SECURITY_HEADERS = [("X-Content-Type-Options", "nosniff"), ("X-Frame-Options", "DENY"),
                    ("Referrer-Policy", "same-origin")]
TEMPLATE = resources.files(__package__).joinpath("login.html").read_text()


# ---------------------------------------------------------------- password hashes

def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p,
                          maxmem=128 * n * r * 2, dklen=32)


def hash_password(password: str) -> str:
    """scrypt:N:r:p:salt:digest. Only ':' and base64url, so it sits in .env unquoted."""
    salt = secrets.token_bytes(16)
    digest = _scrypt(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    return f"scrypt:{SCRYPT_N}:{SCRYPT_R}:{SCRYPT_P}:{_b64(salt)}:{_b64(digest)}"


def _verifier(stored: str):
    """Returns a function password -> bool for a stored hash, or raises ValueError."""
    if stored.startswith("scrypt:"):
        _, n, r, p, salt, digest = stored.split(":")
        n, r, p, salt, digest = int(n), int(r), int(p), _unb64(salt), _unb64(digest)
        return lambda pw: hmac.compare_digest(_scrypt(pw, salt, n, r, p), digest)
    if stored.startswith("$2"):
        # bcrypt hashes from before formlogin still work where the bcrypt package is installed.
        try:
            import bcrypt
        except ImportError:
            raise ValueError("it's a bcrypt hash and the bcrypt package isn't installed") from None
        return lambda pw: bcrypt.checkpw(pw.encode(), stored.encode())
    raise ValueError("it isn't a hash made by: python -m formlogin hash")


# ---------------------------------------------------------------- request helpers

def client_ip(headers, peer: str) -> str:
    """The last X-Forwarded-For entry is the one the nearest proxy added (Caddy replaces
    any the visitor sent). Without a proxy it's the connection's own address."""
    xff = (headers.get("x-forwarded-for") or "").split(",")[-1].strip()
    return xff or peer


def direct_private(headers, peer: str) -> bool:
    """A request straight from a private address that didn't come through a reverse proxy
    (e.g. Prometheus scraping the container)."""
    try:
        a = ipaddress.ip_address(peer)
    except ValueError:
        return False
    return (a.is_private or a.is_loopback) and not headers.get("x-forwarded-for")


def same_origin(headers) -> bool:
    """False for requests a browser says came from another site (on top of SameSite)."""
    if (headers.get("sec-fetch-site") or "") == "cross-site":
        return False
    origin = headers.get("origin")
    if not origin:
        return True
    host = headers.get("x-forwarded-host") or headers.get("host") or ""
    return urlparse(origin).netloc == host


def read_cookie(headers, name: str) -> str | None:
    for part in (headers.get("cookie") or "").split(";"):
        k, _, v = part.strip().partition("=")
        if k == name:
            return v
    return None


def _to_root(path: str) -> str:
    """Relative URL from this path back to the app's root, so redirects work whatever
    prefix the reverse proxy serves the app under."""
    return "../" * max(path.count("/") - 1, 0) or "./"


@dataclass
class Response:
    status: int
    body: bytes = b""
    content_type: str = "text/plain; charset=utf-8"
    headers: list = field(default_factory=list)


def _json(status: int, obj) -> Response:
    return Response(status, json.dumps(obj).encode(), "application/json")


def _redirect(where: str, cookie: str | None = None) -> Response:
    headers = [("Location", where)] + ([("Set-Cookie", cookie)] if cookie else [])
    return Response(303, headers=headers)


# ---------------------------------------------------------------- login

class Login:
    """One user, one password. Every request needs a session except the sign-in page and
    whatever is_public allows. API calls (under /api/) without one get 401, so the page can
    go to the sign-in form; other requests are redirected to it.

    Routes it answers itself: GET/POST /login, POST /logout.
    """

    def __init__(self, app: str, username: str, password_hash: str, key_file: str, *,
                 title: str | None = None, accent: tuple[str, str] = ("#2563eb", "#60a5fa"),
                 icon: str = "", is_public=None, enabled: bool = True):
        """app: short name, used in the cookie name and messages.
        key_file: where the random session-signing key is kept (made on first start).
        title: shown on the sign-in page. accent: (light, dark) button colour.
        icon: favicon href, e.g. a data: URI.
        is_public(method, path, headers, peer) -> bool: requests that need no session.
        enabled=False: everything is let through (no sign-in)."""
        self.app = app
        self.enabled = enabled
        self.cookie_name = f"{app}_session"
        self.is_public = is_public or (lambda *a: False)
        self.page = (TEMPLATE.replace("{{title}}", html.escape(title or app))
                     .replace("{{icon}}", f'<link rel="icon" href="{html.escape(icon)}">' if icon else "")
                     .replace("{{accent}}", accent[0]).replace("{{accent_dark}}", accent[1]))
        if not enabled:
            return
        if not username:
            raise SystemExit(f"{app}: the login username is not set")
        try:
            self._check = _verifier(password_hash or "")
        except ValueError as e:
            raise SystemExit(f"{app}: the password hash is not usable: {e}. "
                             "Make one with: python -m formlogin hash")
        self.username = username
        # Sessions are signed with a random key from key_file, mixed with the username and
        # password hash, so changing either signs everyone out (so does deleting key_file).
        try:
            fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(secrets.token_bytes(32))
        except FileExistsError:
            pass
        except OSError as e:
            raise SystemExit(f"{app}: can't create the session key {key_file}: {e}")
        with open(key_file, "rb") as f:
            secret = f.read()
        self._key = hmac.new(secret, f"{app}\0{username}\0{password_hash}".encode(),
                             hashlib.sha256).digest()
        self._check_lock = threading.Lock()  # one password check at a time
        self._fails = collections.defaultdict(collections.deque)
        self._fail_lock = threading.Lock()

    @classmethod
    def from_env(cls, prefix: str, app: str, key_file: str, **kw) -> "Login":
        """Reads <prefix>_USERNAME, <prefix>_PASSWORD_HASH and <prefix>_AUTH."""
        mode = (os.environ.get(f"{prefix}_AUTH") or "on").strip().lower()
        if mode not in ("on", "off"):
            raise SystemExit(f"{app}: {prefix}_AUTH must be on or off")
        if mode == "off":
            return cls(app, "", "", key_file, enabled=False, **kw)
        user = (os.environ.get(f"{prefix}_USERNAME") or "").strip()
        pw_hash = (os.environ.get(f"{prefix}_PASSWORD_HASH") or "").strip()
        if not user or not pw_hash:
            raise SystemExit(f"{app}: set {prefix}_USERNAME and {prefix}_PASSWORD_HASH "
                             f"(or {prefix}_AUTH=off if only trusted machines can reach it). "
                             "Make the hash with: python -m formlogin hash")
        return cls(app, user, pw_hash, key_file, **kw)

    # -------------------------------------------------- sessions

    def _sign(self, msg: str) -> str:
        return _b64(hmac.new(self._key, msg.encode(), hashlib.sha256).digest())

    def new_session(self) -> str:
        msg = f"{int(time.time()) + SESSION_DAYS * 86400}.{_b64(secrets.token_bytes(9))}"
        return f"{msg}.{self._sign(msg)}"

    def valid(self, token: str | None) -> bool:
        try:
            expires, nonce, sig = (token or "").split(".")
            return (hmac.compare_digest(sig, self._sign(f"{expires}.{nonce}"))
                    and int(expires) > time.time())
        except ValueError:
            return False

    def signed_in(self, headers) -> bool:
        return not self.enabled or self.valid(read_cookie(headers, self.cookie_name))

    def _cookie(self, headers, value: str, max_age: int) -> str:
        # No Path: the browser scopes the cookie to the folder the app is served from
        # (e.g. /ledger), so other apps on the same host never see it.
        secure = "; Secure" if (headers.get("x-forwarded-proto") or "").lower() == "https" else ""
        return f"{self.cookie_name}={value}; Max-Age={max_age}; HttpOnly; SameSite=Lax{secure}"

    # -------------------------------------------------- failed logins

    def _recent(self, q, now):
        while q and now - q[0] > FAIL_WINDOW:
            q.popleft()
        return len(q)

    def blocked(self, ip: str) -> int:
        """Seconds until this address may try again, or 0."""
        now = time.time()
        with self._fail_lock:
            for k in [k for k, q in self._fails.items() if not self._recent(q, now)]:
                del self._fails[k]
            mine = self._fails.get(ip)
            if mine and len(mine) >= FAIL_LIMIT:
                return int(FAIL_WINDOW - (now - mine[0])) + 1
            return 60 if sum(map(len, self._fails.values())) >= GLOBAL_LIMIT else 0

    def check(self, ip: str, username: str, password: str) -> bool:
        """Blocks for the hash check (and FAIL_DELAY on failure); run it off the event loop."""
        with self._check_lock:
            ok_pw = self._check(password)  # always run, so a wrong name takes as long
            ok = hmac.compare_digest(username.encode(), self.username.encode()) and ok_pw
            if not ok:
                with self._fail_lock:
                    self._fails[ip].append(time.time())
                time.sleep(FAIL_DELAY)
        return ok

    # -------------------------------------------------- requests

    def login_page(self, error: str = "", username: str = "", status: int = 200) -> Response:
        body = (self.page.replace("{{error}}", html.escape(error))
                .replace("{{user}}", html.escape(username))).encode()
        return Response(status, body, "text/html; charset=utf-8", [("Cache-Control", "no-store")])

    def needs_body(self, method: str, path: str) -> bool:
        """Whether handle() needs the request body (only for a sign-in attempt)."""
        return self.enabled and method == "POST" and path == "/login"

    def handle(self, method: str, path: str, headers, peer: str, body: bytes = b"") -> Response | None:
        """Decides a request. Returns the response to send, or None to pass it to the app.
        headers: case-insensitive mapping (lowercase names are looked up). path: the app's
        own path, without any prefix the proxy strips. May block (see check)."""
        if method not in SAFE_METHODS and not same_origin(headers):
            return _json(403, {"detail": "cross-site request refused"})
        if not self.enabled:
            return None
        if path == "/login":
            if method == "POST":
                return self._submit(headers, peer, body)
            if self.signed_in(headers):
                return _redirect("./")
            return self.login_page()
        if path == "/logout" and method == "POST":
            return _redirect("login", self._cookie(headers, "", 0))
        if self.signed_in(headers) or self.is_public(method, path, headers, peer):
            return None
        if path.startswith("/api/"):
            return _json(401, {"detail": "not signed in"})
        return _redirect(_to_root(path) + "login")

    def _submit(self, headers, peer: str, body: bytes) -> Response:
        if len(body) > MAX_FORM:
            return self.login_page("Too long.", status=413)
        form = parse_qs(body.decode(errors="replace"))
        name = (form.get("username") or [""])[0].strip()
        password = (form.get("password") or [""])[0]
        ip = client_ip(headers, peer)
        wait = self.blocked(ip)
        if wait:
            return self.login_page(f"Too many failed attempts. Try again in {wait // 60 + 1} min.",
                                   name, 429)
        if not self.check(ip, name, password):
            print(f"{self.app}: failed login from {ip}", file=sys.stderr, flush=True)
            return self.login_page("Wrong username or password.", name, 401)
        print(f"{self.app}: signed in from {ip}", file=sys.stderr, flush=True)
        return _redirect("./", self._cookie(headers, self.new_session(), SESSION_DAYS * 86400))


# ---------------------------------------------------------------- command line

def main(argv=None) -> None:
    argv = sys.argv[1:] if argv is None else argv
    if argv != ["hash"]:
        raise SystemExit("usage: python -m formlogin hash")
    pw = getpass.getpass("New password: ")
    if len(pw) < MIN_PASSWORD:
        raise SystemExit(f"Use at least {MIN_PASSWORD} characters.")
    if getpass.getpass("Again: ") != pw:
        raise SystemExit("The passwords don't match.")
    print(hash_password(pw))
