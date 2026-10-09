"""Тесты gecheck site на локальном HTTP-сервере."""

import http.server
import shutil
import sys
import tempfile
import threading
import unittest
from functools import partial
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from gecheck import site  # noqa: E402

site.PAUSE = 0


class _Quiet(http.server.SimpleHTTPRequestHandler):
    extra_headers = {}
    cookie = None

    def log_message(self, *args):
        pass

    def end_headers(self):
        for k, v in self.extra_headers.items():
            self.send_header(k, v)
        if self.cookie:
            self.send_header("Set-Cookie", self.cookie)
        super().end_headers()


class _Spa(_Quiet):
    """Отдаёт index.html на любой путь, как SPA."""

    def send_head(self):
        self.path = "/index.html"
        return super().send_head()


def serve(directory, handler):
    h = partial(handler, directory=str(directory))
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), h)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}"


class SiteTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        (self.dir / "index.html").write_text("<!doctype html><title>Shop</title>", encoding="utf-8")
        self.servers = []

    def tearDown(self):
        for s in self.servers:
            s.shutdown()
        shutil.rmtree(self.dir, ignore_errors=True)

    def start(self, handler=_Quiet, **attrs):
        cls = type("H", (handler,), attrs)
        httpd, base = serve(self.dir, cls)
        self.servers.append(httpd)
        return base

    def rules(self, findings):
        return sorted(f.rule + ":" + (f.anchor or "") for f in findings)

    def test_exposed_env_and_git_found(self):
        (self.dir / ".env").write_text("STRIPE_SECRET_KEY=sk_live_x\nDB_PASSWORD=x\n", encoding="utf-8")
        (self.dir / ".git").mkdir()
        (self.dir / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
        base = self.start()
        found = self.rules(site.check_exposed(base))
        self.assertIn("ge.site.exposed-file:.env", found)
        self.assertIn("ge.site.exposed-file:.git/HEAD", found)
        self.assertEqual(len(found), 2)

    def test_spa_fallback_is_not_a_leak(self):
        base = self.start(_Spa)
        self.assertEqual(site.check_exposed(base), [])

    def test_html_instead_of_env_is_not_a_leak(self):
        (self.dir / ".env").write_text("<html>nothing here</html>", encoding="utf-8")
        self.assertEqual(site.check_exposed(self.start()), [])

    def test_directory_listing(self):
        (self.dir / "uploads").mkdir()
        (self.dir / "uploads" / "passport.jpg").write_bytes(b"x")
        found = self.rules(site.check_exposed(self.start()))
        self.assertEqual(found, ["ge.site.dir-listing:uploads/"])

    def test_missing_headers_and_weak_cookie(self):
        base = self.start(cookie="sessionid=abc; Path=/")
        found = self.rules(site.check_headers(site.fetch(base + "/")))
        self.assertIn("ge.site.csp-missing:csp_missing", found)
        self.assertIn("ge.site.nosniff-missing:nosniff_missing", found)
        self.assertIn("ge.site.cookie-flags:sessionid", found)
        cookie = [f for f in site.check_headers(site.fetch(base + "/")) if f.anchor == "sessionid"][0]
        self.assertEqual(cookie.severity, "medium")

    def test_good_headers_pass(self):
        base = self.start(extra_headers={
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        }, cookie="sessionid=abc; Path=/; Secure; HttpOnly; SameSite=Lax")
        found = self.rules(site.check_headers(site.fetch(base + "/")))
        # по http HSTS не проверяется; http.server отдаёт версию Python в заголовке Server
        self.assertEqual(found, ["ge.site.server-version:server"])

    def test_normalize(self):
        self.assertEqual(site.normalize("goldeneye.kz")[:2], ("https://goldeneye.kz", "goldeneye.kz"))
        self.assertEqual(site.normalize("http://a.kz/ru/?x=1")[0], "http://a.kz")
        with self.assertRaises(ValueError):
            site.normalize("ftp://a.kz")


if __name__ == "__main__":
    unittest.main()
