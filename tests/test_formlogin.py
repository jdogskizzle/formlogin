"""python -m unittest discover tests   (the ASGI tests need starlette + httpx, else skipped)"""
import http.client
import os
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

import formlogin
import formlogin.httpserver

formlogin.FAIL_DELAY = 0
formlogin.SCRYPT_N = 2 ** 10  # fast hashes for tests
HASH = formlogin.hash_password("correct horse battery")


def make(**kw):
    kw.setdefault("username", "me")
    kw.setdefault("password_hash", HASH)
    return formlogin.Login("app", tempfile.mkdtemp(), **kw)


class Hdr(dict):
    def get(self, k, default=None):
        return super().get(k.lower(), default)


def form(user="me", pw="correct horse battery"):
    return f"username={user}&password={pw.replace(' ', '+')}".encode()


class Core(unittest.TestCase):
    def test_hash_roundtrip(self):
        check = formlogin._verifier(HASH)
        self.assertTrue(check("correct horse battery"))
        self.assertFalse(check("wrong"))
        with self.assertRaises(ValueError):
            formlogin._verifier("plaintext")

    def test_bad_settings_fail_clearly(self):
        with self.assertRaises(SystemExit):
            make(password_hash="nope")
        with self.assertRaises(SystemExit):
            formlogin.Login("app", "/does/not/exist")
        with mock.patch.dict(os.environ, {"X_PASSWORD_HASH": HASH}, clear=True), self.assertRaises(SystemExit):
            formlogin.Login.from_env("X", "app", tempfile.mkdtemp())
        with mock.patch.dict(os.environ, {"X_AUTH": "maybe"}, clear=True), self.assertRaises(SystemExit):
            formlogin.Login.from_env("X", "app", "/tmp/x")
        with mock.patch.dict(os.environ, {"X_AUTH": "off"}, clear=True):
            self.assertIsNone(formlogin.Login.from_env("X", "app", "/tmp/x").handle("GET", "/", Hdr(), "1.2.3.4"))

    def test_flow(self):
        L = make()
        r = L.handle("GET", "/", Hdr(), "1.2.3.4")
        self.assertEqual((r.status, dict(r.headers)["Location"]), (303, "./login"))
        self.assertEqual(L.handle("GET", "/a/b", Hdr(), "1.2.3.4").headers[0][1], "../login")
        self.assertEqual(L.handle("GET", "/api/x", Hdr(), "1.2.3.4").status, 401)
        self.assertEqual(L.handle("GET", "/login", Hdr(), "1.2.3.4").status, 200)
        r = L.handle("POST", "/login", Hdr(), "1.2.3.4", form(pw="nope"))
        self.assertEqual(r.status, 401)
        self.assertIn(b"Wrong username", r.body)
        r = L.handle("POST", "/login", Hdr({"x-forwarded-proto": "https"}), "1.2.3.4", form())
        self.assertEqual(r.status, 303)
        cookie = dict(r.headers)["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("Secure", cookie)
        self.assertNotIn("Path", cookie)
        h = Hdr({"cookie": "other=1; " + cookie.split(";")[0]})
        self.assertIsNone(L.handle("GET", "/api/x", h, "1.2.3.4"))
        self.assertEqual(L.handle("GET", "/login", h, "1.2.3.4").status, 303)
        # a different password (or key) invalidates the session
        other = make(password_hash=formlogin.hash_password("another one!!"))
        self.assertEqual(other.handle("GET", "/api/x", h, "1.2.3.4").status, 401)

    def test_html_escaped(self):
        r = make().handle("POST", "/login", Hdr(), "1.2.3.4", form(user="<script>"))
        self.assertIn(b"&lt;script&gt;", r.body)
        self.assertNotIn(b"<script>", r.body)

    def test_cross_site_refused(self):
        L = make()
        h = Hdr({"origin": "https://evil.example", "host": "home.example"})
        self.assertEqual(L.handle("POST", "/login", h, "1.2.3.4", form()).status, 403)
        self.assertEqual(L.handle("POST", "/login", Hdr({"sec-fetch-site": "cross-site"}), "1.2.3.4", form()).status, 403)
        ok = Hdr({"origin": "https://home.example", "x-forwarded-host": "home.example", "host": "app:8000"})
        self.assertEqual(L.handle("POST", "/login", ok, "1.2.3.4", form()).status, 303)

    def test_lockout(self):
        L = make()
        for _ in range(formlogin.FAIL_LIMIT):
            L.handle("POST", "/login", Hdr(), "1.2.3.4", form(pw="nope"))
        self.assertEqual(L.handle("POST", "/login", Hdr(), "1.2.3.4", form()).status, 429)
        self.assertEqual(L.handle("POST", "/login", Hdr({"x-forwarded-for": "5.6.7.8"}), "10.0.0.1", form()).status, 303)

    def test_expired_and_tampered(self):
        L = make()
        tok = L.new_session()
        self.assertTrue(L.valid(tok))
        self.assertFalse(L.valid(tok[:-2] + "xx"))
        self.assertFalse(L.valid("junk"))
        self.assertFalse(L.valid(None))
        with mock.patch("time.time", return_value=time.time() + 31 * 86400):
            self.assertFalse(L.valid(tok))

    def test_public(self):
        L = make(is_public=lambda m, p, h, peer: p == "/metrics" and formlogin.direct_private(h, peer))
        self.assertIsNone(L.handle("GET", "/metrics", Hdr(), "172.18.0.5"))
        self.assertEqual(L.handle("GET", "/metrics", Hdr({"x-forwarded-for": "1.2.3.4"}), "172.18.0.5").status, 303)
        self.assertEqual(L.handle("GET", "/metrics", Hdr(), "8.8.8.8").status, 303)


def setup_form(code, user="me", pw="a brand new password", again=None):
    again = pw if again is None else again
    return (f"code={code}&username={user}&password={pw.replace(' ', '+')}"
            f"&again={again.replace(' ', '+')}").encode()


class FileAndSetup(unittest.TestCase):
    def test_setup_page(self):
        d = tempfile.mkdtemp()
        L = formlogin.Login("app", d)
        code = L._setup_code
        self.assertEqual(len(code), 10)
        r = L.handle("GET", "/login", Hdr(), "1.2.3.4")
        self.assertIn(b"Setup code", r.body)
        self.assertIn(b'name="username"', r.body)
        self.assertEqual(L.handle("GET", "/api/x", Hdr(), "1.2.3.4").status, 401)
        self.assertEqual(L.handle("POST", "/login", Hdr(), "1.2.3.4", setup_form("WRONGWRONG")).status, 401)
        self.assertEqual(L.handle("POST", "/login", Hdr(), "1.2.3.4", setup_form(code, pw="short")).status, 400)
        self.assertEqual(L.handle("POST", "/login", Hdr(), "1.2.3.4",
                                  setup_form(code, again="a different password")).status, 400)
        # dashes, spaces and lower case are fine
        r = L.handle("POST", "/login", Hdr(), "1.2.3.4", setup_form(f"{code[:5].lower()}-{code[5:]}"))
        self.assertEqual(r.status, 303)
        self.assertIsNone(L._setup_code)
        h = Hdr({"cookie": dict(r.headers)["Set-Cookie"].split(";")[0]})
        self.assertIsNone(L.handle("GET", "/api/x", h, "1.2.3.4"))
        self.assertEqual(formlogin.read_login_file(d)["username"], "me")
        # now it's a normal sign-in page
        self.assertIn(b"Sign in", L.handle("GET", "/login", Hdr(), "1.2.3.4").body)
        self.assertEqual(L.handle("POST", "/login", Hdr(), "1.2.3.4", form(pw="a brand new password")).status, 303)

    def test_setup_code_limited(self):
        L = formlogin.Login("app", tempfile.mkdtemp())
        for _ in range(formlogin.FAIL_LIMIT):
            L.handle("POST", "/login", Hdr(), "1.2.3.4", setup_form("WRONGWRONG"))
        self.assertEqual(L.handle("POST", "/login", Hdr(), "1.2.3.4", setup_form(L._setup_code)).status, 429)

    def test_fixed_username_not_asked(self):
        L = formlogin.Login("app", tempfile.mkdtemp(), username="boss")
        self.assertNotIn(b'name="username"', L.handle("GET", "/login", Hdr(), "1.2.3.4").body)
        r = L.handle("POST", "/login", Hdr(), "1.2.3.4", setup_form(L._setup_code, user=""))
        self.assertEqual(r.status, 303)
        self.assertEqual(L.current().username, "boss")

    def test_changed_file_applies_without_restart(self):
        d = tempfile.mkdtemp()
        formlogin.write_login_file(d, "me", HASH)
        L = formlogin.Login("app", d)
        self.assertIsNone(L._setup_code)
        r = L.handle("POST", "/login", Hdr(), "1.2.3.4", form())
        h = Hdr({"cookie": dict(r.headers)["Set-Cookie"].split(";")[0]})
        self.assertIsNone(L.handle("GET", "/api/x", h, "1.2.3.4"))
        time.sleep(0.01)
        formlogin.write_login_file(d, "me", formlogin.hash_password("the second password"))
        self.assertEqual(L.handle("GET", "/api/x", h, "1.2.3.4").status, 401)  # signed out
        self.assertEqual(L.handle("POST", "/login", Hdr(), "1.2.3.4", form()).status, 401)
        self.assertEqual(L.handle("POST", "/login", Hdr(), "1.2.3.4", form(pw="the second password")).status, 303)
        # a broken file is ignored, the last good password keeps working
        time.sleep(0.01)
        with open(os.path.join(d, "login.json"), "w") as f:
            f.write("{nope")
        self.assertEqual(L.handle("POST", "/login", Hdr(), "1.2.3.4", form(pw="the second password")).status, 303)
        # deleting it goes back to setup
        os.unlink(os.path.join(d, "login.json"))
        self.assertIn(b"Setup code", L.handle("GET", "/login", Hdr(), "1.2.3.4").body)

    def test_env_hash_wins(self):
        d = tempfile.mkdtemp()
        formlogin.write_login_file(d, "me", formlogin.hash_password("file password!!"))
        with mock.patch.dict(os.environ, {"X_USERNAME": "me", "X_PASSWORD_HASH": HASH}, clear=True):
            L = formlogin.Login.from_env("X", "app", d)
        self.assertEqual(L.handle("POST", "/login", Hdr(), "1.2.3.4", form()).status, 303)
        self.assertEqual(L.handle("POST", "/login", Hdr(), "1.2.3.4", form(pw="file password!!")).status, 401)

    def test_passwd_command(self):
        d = tempfile.mkdtemp()
        pointer = os.path.join(d, "pointer.json")
        with mock.patch.object(formlogin, "POINTER", pointer), \
                mock.patch.dict(os.environ, {"X_USERNAME": "boss"}, clear=True):
            L = formlogin.Login.from_env("X", "app", d)
            with mock.patch("getpass.getpass", return_value="from the command line"):
                formlogin.main(["passwd"])
            self.assertEqual(L.handle("POST", "/login", Hdr(), "1.2.3.4",
                                      form(user="boss", pw="from the command line")).status, 303)
            with mock.patch.dict(os.environ, {"X_PASSWORD_HASH": HASH}), self.assertRaises(SystemExit):
                formlogin.main(["passwd"])
        # without a fixed username it asks, offering the current one
        with mock.patch("getpass.getpass", return_value="yet another password"), \
                mock.patch("builtins.input", return_value="") as ask:
            formlogin.main(["passwd", d])
        self.assertIn("[boss]", ask.call_args[0][0])
        self.assertEqual(formlogin.read_login_file(d)["username"], "boss")
        with mock.patch("getpass.getpass", side_effect=["long enough password", "not the same one"]), \
                mock.patch("builtins.input", return_value=""), self.assertRaises(SystemExit):
            formlogin.main(["passwd", d])


class HTTPServerAdapter(unittest.TestCase):
    def setUp(self):
        L = make()

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                if not formlogin.httpserver.handle(self, L, self.path):
                    self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers()
                    self.wfile.write(b"ok")
            do_POST = do_GET

            def log_message(self, *a):
                pass

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown()

    def req(self, method, path, body=None, headers={}):
        c = http.client.HTTPConnection(*self.srv.server_address)
        c.request(method, path, body, headers)
        r = c.getresponse()
        return r, r.read()

    def test_flow(self):
        r, _ = self.req("GET", "/")
        self.assertEqual(r.status, 303)
        self.assertEqual(r.getheader("X-Frame-Options"), "DENY")
        r, _ = self.req("POST", "/login", form(), {"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(r.status, 303)
        cookie = r.getheader("Set-Cookie").split(";")[0]
        r, body = self.req("GET", "/", headers={"Cookie": cookie})
        self.assertEqual((r.status, body), (200, b"ok"))
        r, _ = self.req("POST", "/login", b"x" * 10000)
        self.assertEqual(r.status, 413)


try:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    import formlogin.asgi
except (ImportError, RuntimeError):  # RuntimeError: starlette without httpx
    FastAPI = None


@unittest.skipIf(FastAPI is None, "fastapi/httpx not installed")
class ASGIAdapter(unittest.TestCase):
    def test_flow(self):
        app = FastAPI()
        formlogin.asgi.install(app, make())

        @app.get("/api/x")
        def x():
            return {"ok": 1}

        c = TestClient(app, follow_redirects=False)
        self.assertEqual(c.get("/api/x").status_code, 401)
        r = c.get("/")
        self.assertEqual((r.status_code, r.headers["location"]), (303, "./login"))
        self.assertEqual(r.headers["x-frame-options"], "DENY")
        r = c.post("/login", content=form(), headers={"content-type": "application/x-www-form-urlencoded"})
        self.assertEqual(r.status_code, 303)
        r = c.get("/api/x")
        self.assertEqual((r.status_code, r.json()), (200, {"ok": 1}))
        self.assertEqual(r.headers["x-content-type-options"], "nosniff")
        r = c.post("/logout")
        self.assertIn("Max-Age=0", r.headers["set-cookie"])


if __name__ == "__main__":
    unittest.main()
