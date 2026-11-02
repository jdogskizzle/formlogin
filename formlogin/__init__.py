"""Form login for small single-user web apps: a sign-in page, a signed session cookie,
a limit on failed logins, and a cross-site check on changes.

The core here knows nothing about web frameworks. Adapters wire it in:
    formlogin.asgi        FastAPI / Starlette apps
    formlogin.httpserver  apps built on http.server

The password is kept in <state_dir>/login.json. Set or change it inside the running
container with:
    python -m formlogin passwd
With no password yet, the app shows a set-password page that needs the one-time setup
code it prints to its log. The running app picks up a new password without a restart.

Settings from the environment, under a prefix the app picks (e.g. LEDGER), all optional:
    <PREFIX>_USERNAME       fixes the login name (otherwise it's chosen with the password)
    <PREFIX>_PASSWORD_HASH  fixes the password instead of login.json (python -m formlogin hash)
    <PREFIX>_AUTH           "off" turns sign-in off (only if nothing untrusted can reach
                            the app); anything else, or unset, leaves it on
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
import tempfile
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
LOGIN_FILE, KEY_FILE = "login.json", "session.key"
# Where a running app notes its state folder, so `python -m formlogin passwd` run in the
# same container finds it.
POINTER = os.path.join(tempfile.gettempdir(), "formlogin.json")
CODE_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O or 1/I
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
        try:
            _, n, r, p, salt, digest = stored.split(":")
            n, r, p, salt, digest = int(n), int(r), int(p), _unb64(salt), _unb64(digest)
        except ValueError:
            raise ValueError("it's not a complete scrypt hash") from None
        return lambda pw: hmac.compare_digest(_scrypt(pw, salt, n, r, p), digest)
    if stored.startswith("$2"):
        # bcrypt hashes from before formlogin still work where the bcrypt package is installed.
        try:
            import bcrypt
        except ImportError:
            raise ValueError("it's a bcrypt hash and the bcrypt package isn't installed") from None
        return lambda pw: bcrypt.checkpw(pw.encode(), stored.encode())
    raise ValueError("it isn't a hash made by: python -m formlogin hash")


def password_problem(password: str, again: str) -> str:
    """Why a new password can't be used, or ''."""
    if len(password) < MIN_PASSWORD:
        return f"Use at least {MIN_PASSWORD} characters."
    if password != again:
        return "The passwords don't match."
    return ""


# ---------------------------------------------------------------- login.json

def read_login_file(state_dir: str) -> dict | None:
    """{"username", "password_hash"} from state_dir/login.json, or None if there's none."""
    try:
        with open(os.path.join(state_dir, LOGIN_FILE)) as f:
            data = json.load(f)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        raise ValueError(f"can't read {LOGIN_FILE}: {e}") from None
    if not isinstance(data, dict):
        raise ValueError(f"{LOGIN_FILE} isn't a JSON object")
    return data


def write_login_file(state_dir: str, username: str, password_hash: str) -> None:
    """Writes login.json in one step (readers see the old or the new file, never half)."""
    path = os.path.join(state_dir, LOGIN_FILE)
    fd, tmp = tempfile.mkstemp(dir=state_dir, prefix=".login-")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump({"username": username, "password_hash": password_hash}, f)
            f.write("\n")
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


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


def _field(label: str, name: str, kind: str = "text", value: str = "", autocomplete: str = "",
           autofocus: bool = False) -> str:
    extra = ' autocapitalize="none" spellcheck="false"' if kind == "text" else ""
    return (f'<label>{label}<input name="{name}" type="{kind}" value="{html.escape(value)}"'
            f' autocomplete="{autocomplete}"{extra} required{" autofocus" if autofocus else ""}></label>')


@dataclass
class _Creds:
    username: str
    check: object  # password -> bool
    key: bytes     # session-signing key


# ---------------------------------------------------------------- login

class Login:
    """One user, one password. Every request needs a session except the sign-in page and
    whatever is_public allows. API calls (under /api/) without one get 401, so the page can
    go to the sign-in form; other requests are redirected to it.

    Routes it answers itself: GET/POST /login, POST /logout.
    """

    def __init__(self, app: str, state_dir: str, *, username: str | None = None,
                 password_hash: str | None = None, prefix: str | None = None,
                 title: str | None = None, accent: tuple[str, str] = ("#2563eb", "#60a5fa"),
                 icon: str = "", is_public=None, enabled: bool = True):
        """app: short name, used in the cookie name and messages.
        state_dir: a folder the app keeps (volume): login.json and session.key go there.
        username / password_hash: fixed values that override login.json (e.g. from .env).
        prefix: the environment prefix, so `formlogin passwd` can respect fixed values.
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
        self.state_dir = state_dir
        self._fixed_user = username or None
        self._fixed_hash = password_hash or None
        if self._fixed_hash and not self._fixed_user:
            raise SystemExit(f"{app}: a fixed password hash needs a fixed username too")
        if not os.path.isdir(state_dir):
            raise SystemExit(f"{app}: the state folder {state_dir} doesn't exist (mount a volume there)")
        # Sessions are signed with a random key from session.key, mixed with the username and
        # password hash, so changing either signs everyone out (so does deleting the key).
        key_file = os.path.join(state_dir, KEY_FILE)
        try:
            fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(secrets.token_bytes(32))
        except FileExistsError:
            pass
        except OSError as e:
            raise SystemExit(f"{app}: can't create the session key {key_file}: {e}")
        with open(key_file, "rb") as f:
            self._secret = f.read()
        self._load_lock = threading.Lock()
        self._check_lock = threading.Lock()  # one password check at a time
        self._fails = collections.defaultdict(collections.deque)
        self._fail_lock = threading.Lock()
        self._mtime = self._setup_code = self._creds = None
        try:
            self._creds = self._load()
        except ValueError as e:
            raise SystemExit(f"{app}: {e}")
        self._mtime = self._file_mtime()
        if self._creds is None:
            self._start_setup()
        try:  # so `python -m formlogin passwd` in this container finds the state folder
            with open(POINTER, "w") as f:
                json.dump({"app": app, "prefix": prefix, "state_dir": os.path.abspath(state_dir)}, f)
        except OSError:
            pass

    @classmethod
    def from_env(cls, prefix: str, app: str, state_dir: str, **kw) -> "Login":
        """Reads <prefix>_USERNAME, <prefix>_PASSWORD_HASH and <prefix>_AUTH (all optional)."""
        mode = (os.environ.get(f"{prefix}_AUTH") or "on").strip().lower()
        if mode not in ("on", "off"):
            raise SystemExit(f"{app}: {prefix}_AUTH must be on or off")
        if mode == "off":
            return cls(app, state_dir, enabled=False, **kw)
        user = (os.environ.get(f"{prefix}_USERNAME") or "").strip()
        pw_hash = (os.environ.get(f"{prefix}_PASSWORD_HASH") or "").strip()
        if pw_hash and not user:
            raise SystemExit(f"{app}: {prefix}_PASSWORD_HASH is set, so set {prefix}_USERNAME too")
        return cls(app, state_dir, username=user, password_hash=pw_hash, prefix=prefix, **kw)

    # -------------------------------------------------- credentials

    def _file_mtime(self):
        try:
            return os.stat(os.path.join(self.state_dir, LOGIN_FILE)).st_mtime_ns
        except OSError:
            return None

    def _load(self) -> _Creds | None:
        """The current username and password, or None while none is set. Raises ValueError."""
        if self._fixed_hash:
            user, pw_hash = self._fixed_user, self._fixed_hash
        else:
            data = read_login_file(self.state_dir)
            if data is None:
                return None
            user = self._fixed_user or str(data.get("username") or "")
            pw_hash = str(data.get("password_hash") or "")
            if not user:
                raise ValueError(f"{LOGIN_FILE} has no username")
        try:
            check = _verifier(pw_hash)
        except ValueError as e:
            raise ValueError(f"the password hash is not usable: {e}") from None
        key = hmac.new(self._secret, f"{self.app}\0{user}\0{pw_hash}".encode(), hashlib.sha256).digest()
        return _Creds(user, check, key)

    def current(self) -> _Creds | None:
        """Credentials, re-read when login.json changes (so a new password applies at once)."""
        if self._fixed_hash:
            return self._creds
        mtime = self._file_mtime()
        if mtime != self._mtime:
            with self._load_lock:
                if mtime != self._mtime:
                    self._mtime = mtime
                    try:
                        self._creds = self._load()
                    except ValueError as e:  # keep what worked; say why
                        print(f"{self.app}: ignoring the changed {LOGIN_FILE}: {e}",
                              file=sys.stderr, flush=True)
                    else:
                        if self._creds is None:
                            self._start_setup()
                        else:
                            self._setup_code = None
                            print(f"{self.app}: new password in use; earlier sessions are signed out",
                                  file=sys.stderr, flush=True)
        return self._creds

    def _start_setup(self) -> None:
        code = "".join(secrets.choice(CODE_CHARS) for _ in range(10))
        self._setup_code = code
        print(f"{self.app}: no password is set yet. Open the app and use setup code "
              f"{code[:5]}-{code[5:]}, or set one with: python -m formlogin passwd "
              "(in this container)", file=sys.stderr, flush=True)

    # -------------------------------------------------- sessions

    def _sign(self, key: bytes, msg: str) -> str:
        return _b64(hmac.new(key, msg.encode(), hashlib.sha256).digest())

    def new_session(self, creds: _Creds | None = None) -> str:
        creds = creds or self.current()
        msg = f"{int(time.time()) + SESSION_DAYS * 86400}.{_b64(secrets.token_bytes(9))}"
        return f"{msg}.{self._sign(creds.key, msg)}"

    def valid(self, token: str | None) -> bool:
        creds = self.current()
        if creds is None:
            return False
        try:
            expires, nonce, sig = (token or "").split(".")
            return (hmac.compare_digest(sig, self._sign(creds.key, f"{expires}.{nonce}"))
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

    def _failed(self, ip: str) -> None:
        with self._fail_lock:
            self._fails[ip].append(time.time())
        time.sleep(FAIL_DELAY)

    def check(self, ip: str, username: str, password: str) -> bool:
        """Blocks for the hash check (and FAIL_DELAY on failure); run it off the event loop."""
        creds = self.current()
        if creds is None:
            return False
        with self._check_lock:
            ok_pw = creds.check(password)  # always run, so a wrong name takes as long
            ok = hmac.compare_digest(username.encode(), creds.username.encode()) and ok_pw
            if not ok:
                self._failed(ip)
        return ok

    # -------------------------------------------------- pages

    def _page(self, intro: str, fields: list[str], button: str, error: str, status: int) -> Response:
        body = (self.page.replace("{{intro}}", f'<p class="intro">{intro}</p>' if intro else "")
                .replace("{{fields}}", "\n  ".join(fields)).replace("{{button}}", button)
                .replace("{{error}}", html.escape(error))).encode()
        return Response(status, body, "text/html; charset=utf-8", [("Cache-Control", "no-store")])

    def login_page(self, error: str = "", username: str = "", status: int = 200) -> Response:
        return self._page("", [
            _field("Username", "username", value=username, autocomplete="username", autofocus=True),
            _field("Password", "password", "password", autocomplete="current-password"),
        ], "Sign in", error, status)

    def setup_page(self, error: str = "", username: str = "", status: int = 200) -> Response:
        fields = [_field("Setup code", "code", autocomplete="off", autofocus=True)]
        if not self._fixed_user:
            fields.append(_field("Username", "username", value=username, autocomplete="username"))
        fields += [_field("New password", "password", "password", autocomplete="new-password"),
                   _field("New password again", "again", "password", autocomplete="new-password")]
        return self._page("No password is set yet. The setup code is in the app's log "
                          "(<code>docker logs &lt;container&gt;</code>).",
                          fields, "Set password and sign in", error, status)

    # -------------------------------------------------- requests

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
            return self.setup_page() if self.current() is None else self.login_page()
        if path == "/logout" and method == "POST":
            return _redirect("login", self._cookie(headers, "", 0))
        if self.signed_in(headers) or self.is_public(method, path, headers, peer):
            return None
        if path.startswith("/api/"):
            return _json(401, {"detail": "not signed in"})
        return _redirect(_to_root(path) + "login")

    def _submit(self, headers, peer: str, body: bytes) -> Response:
        setup = self.current() is None
        page = self.setup_page if setup else self.login_page
        if len(body) > MAX_FORM:
            return page("Too long.", status=413)
        form = {k: v[0] for k, v in parse_qs(body.decode(errors="replace")).items()}
        name = form.get("username", "").strip()
        ip = client_ip(headers, peer)
        wait = self.blocked(ip)
        if wait:
            return page(f"Too many failed attempts. Try again in {wait // 60 + 1} min.", name, 429)
        if setup:
            return self._setup(headers, ip, form, name)
        if not self.check(ip, name, form.get("password", "")):
            print(f"{self.app}: failed login from {ip}", file=sys.stderr, flush=True)
            return self.login_page("Wrong username or password.", name, 401)
        print(f"{self.app}: signed in from {ip}", file=sys.stderr, flush=True)
        return _redirect("./", self._cookie(headers, self.new_session(), SESSION_DAYS * 86400))

    def _setup(self, headers, ip: str, form: dict, name: str) -> Response:
        given = form.get("code", "").upper().replace("-", "").replace(" ", "")
        with self._check_lock:
            code = self._setup_code
            if code is None:  # a password was set meanwhile
                return _redirect("login")
            if not hmac.compare_digest(given.encode(), code.encode()):
                print(f"{self.app}: wrong setup code from {ip}", file=sys.stderr, flush=True)
                self._failed(ip)
                return self.setup_page("Wrong setup code.", name, 401)
            user = self._fixed_user or name
            if not user:
                return self.setup_page("Choose a username.", name, 400)
            problem = password_problem(form.get("password", ""), form.get("again", ""))
            if problem:
                return self.setup_page(problem, name, 400)
            write_login_file(self.state_dir, user, hash_password(form["password"]))
        creds = self.current()
        print(f"{self.app}: password set from {ip}", file=sys.stderr, flush=True)
        return _redirect("./", self._cookie(headers, self.new_session(creds), SESSION_DAYS * 86400))


# ---------------------------------------------------------------- command line

def _ask_password() -> str:
    pw = getpass.getpass("New password: ")
    problem = password_problem(pw, pw) or password_problem(pw, getpass.getpass("Again: "))
    if problem:
        raise SystemExit(problem)
    return pw


def passwd(state_dir: str | None = None) -> None:
    """Sets the password (and the username, unless the environment fixes it) in login.json."""
    prefix = None
    if state_dir is None:
        try:
            with open(POINTER) as f:
                where = json.load(f)
            state_dir, prefix = where["state_dir"], where.get("prefix")
        except (OSError, ValueError, KeyError):
            raise SystemExit("Can't tell where this app keeps its login. Run this in the app's "
                             "running container (docker compose exec <service> python -m "
                             "formlogin passwd), or name the folder: python -m formlogin "
                             "passwd <state folder>")
    if prefix and os.environ.get(f"{prefix}_PASSWORD_HASH"):
        raise SystemExit(f"{prefix}_PASSWORD_HASH is set in the app's environment (.env), and it "
                         "takes priority. Remove it there and restart the app, then run this again.")
    fixed_user = (os.environ.get(f"{prefix}_USERNAME") or "").strip() if prefix else ""
    try:
        old = read_login_file(state_dir) or {}
    except ValueError:
        old = {}
    if fixed_user:
        print(f"Username: {fixed_user} (set by {prefix}_USERNAME)")
        user = fixed_user
    else:
        current = old.get("username") or ""
        user = input(f"Username [{current}]: " if current else "Username: ").strip() or current
        if not user:
            raise SystemExit("A username is needed.")
    write_login_file(state_dir, user, hash_password(_ask_password()))
    print("Password saved. The app uses it right away; every device is signed out.")


def main(argv=None) -> None:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["passwd"] and len(argv) <= 2:
        return passwd(argv[1] if len(argv) == 2 else None)
    if argv == ["hash"]:
        return print(hash_password(_ask_password()))
    raise SystemExit("usage: python -m formlogin passwd [state folder]   set the password\n"
                     "       python -m formlogin hash                    print a hash for .env")
