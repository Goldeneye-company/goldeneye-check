"""Pro client tests against a fake goldeneye.kz server.

The real Pro rules are not in this repository; the fake server hands out one test rule.
"""

import http.server
import io
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from gecheck import cli, pro  # noqa: E402
from gecheck.install import engine_path  # noqa: E402

TEST_RULE = """rules:
  - id: ge.pro.test.marker
    languages: [javascript]
    severity: WARNING
    message: test rule
    metadata:
      ge:
        severity: high
        category: auth
        title: {ru: "Test rule (ru)", kk: "Test rule (kk)", en: "Test rule"}
        fix: {ru: "Fix it (ru)", kk: "Fix it (kk)", en: "Fix it"}
    pattern: pro_test_marker()
"""


class FakeServer:
    def __init__(self):
        srv = self
        self.balance = 2
        self.free = set()
        self.requests = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
                srv.requests.append((self.path, body))
                code, out = srv.handle(self.path.rsplit("/", 1)[-1], body, self.headers.get("Authorization"))
                raw = json.dumps(out).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/api/pro"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def handle(self, endpoint, body, auth):
        if endpoint == "login.php":
            return 200, {"ok": True}
        if endpoint == "verify.php":
            return (200, {"token": "t" * 40, "balance": self.balance}) if body.get("code") == "123456" else (422, {"error": "bad_code"})
        if auth != "Bearer " + "t" * 40:
            return 401, {"error": "unauthorized"}
        if endpoint == "balance.php":
            return 200, {"balance": self.balance, "packages": []}
        if endpoint == "rules.php":
            pid = body["project_id"]
            free = "2026-12-31T00:00:00Z" if pid in self.free else None
            if not body.get("confirm"):
                return 200, {"free_until": free, "balance": self.balance}
            if not free:
                if not self.balance:
                    return 402, {"error": "no_credits"}
                self.balance -= 1
                self.free.add(pid)
            return 200, {"version": "test.1", "charged": 0 if free else 1, "balance": self.balance,
                         "free_until": "2026-12-31T00:00:00Z",
                         "rules": [{"name": "pro-test.yaml", "content": TEST_RULE},
                                   {"name": "../evil.yaml", "content": "x"}]}
        return 404, {"error": "not_found"}

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class ProClientTest(unittest.TestCase):
    def setUp(self):
        self.server = FakeServer()
        self.home = Path(tempfile.mkdtemp())
        self.project = Path(tempfile.mkdtemp())
        (self.project / "app.js").write_text("pro_test_marker();\n", encoding="utf-8")
        self.env = mock.patch.dict(os.environ, {"GECHECK_PRO_SERVER": self.server.url})
        self.env.start()
        os.environ.pop("GECHECK_TOKEN", None)
        # the login is kept in a temp folder, not in the real ~/.goldeneye-check
        self.state = mock.patch("gecheck.pro._state_file", return_value=self.home / "account.json")
        self.state.start()

    def tearDown(self):
        self.state.stop()
        self.env.stop()
        self.server.stop()
        shutil.rmtree(self.home, ignore_errors=True)
        shutil.rmtree(self.project, ignore_errors=True)

    def run_cli(self, *args, tty=False, answer="yes"):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("gecheck.cli._interactive", return_value=tty), \
             mock.patch("builtins.input", return_value=answer), redirect_stdout(out), redirect_stderr(err):
            code = cli.main(list(args))
        return code, out.getvalue() + err.getvalue()

    def login(self):
        code, out = self.run_cli("login", "dev@example.kz", "--code", "123456")
        self.assertEqual(code, 0, out)

    def test_login_balance_logout(self):
        self.assertEqual(self.run_cli("balance")[0], cli.EXIT_ERROR)
        self.login()
        self.assertIn("2 Pro checks left", self.run_cli("balance")[1])
        self.run_cli("logout")
        self.assertIsNone(pro.token())

    def test_rules_are_saved_safely(self):
        self.login()
        folder, res = pro.fetch_rules(pro.token(), "a" * 16)
        try:
            self.assertEqual([p.name for p in folder.iterdir()], ["pro-test.yaml"])
            self.assertEqual(res["charged"], 1)
        finally:
            shutil.rmtree(folder)

    def test_pro_flag_without_login_fails(self):
        code, out = self.run_cli("scan", str(self.project), "--pro", "--no-deps", "--fail-on", "none")
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("gecheck login", out)

    def test_script_run_does_not_charge_without_flag(self):
        self.login()
        code, out = self.run_cli("scan", str(self.project), "--no-deps", "--fail-on", "none",
                                 "--out", str(self.home / "out"))
        self.assertIn("Add --pro", out)
        self.assertEqual(self.server.balance, 2)

    @unittest.skipUnless(engine_path("opengrep").exists(), "engines are not installed: gecheck install")
    def test_scan_with_pro_rules(self):
        self.login()
        out_dir = self.home / "out"
        code, out = self.run_cli("scan", str(self.project), "--no-deps", "--no-history", "--fail-on", "none",
                                 "--out", str(out_dir), tty=True, answer="yes")
        data = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
        self.assertIn("ge.pro.test.marker", [f["rule"] for f in data["findings"]], out)
        self.assertIn("1 check used", out)
        self.assertEqual(data["tool"]["engines"]["pro-rules"]["version"], "test.1")
        self.assertIn("1 check used", data["notice"]["en"])
        self.assertNotIn("goldeneye.kz/en/check/", (out_dir / "report.html").read_text(encoding="utf-8"))
        self.assertFalse(list(Path(tempfile.gettempdir()).glob("gecheck-pro-*/pro-test.yaml")))

        # the same project again: free re-check, nothing charged
        code, out = self.run_cli("scan", str(self.project), "--pro", "--no-deps", "--no-history", "--fail-on", "none",
                                 "--out", str(out_dir))
        self.assertIn("free until", out)
        self.assertEqual(self.server.balance, 1)

        # answering "no" skips Pro
        self.server.free.clear()
        code, out = self.run_cli("scan", str(self.project), "--no-deps", "--no-history", "--fail-on", "none",
                                 "--out", str(out_dir), tty=True, answer="no")
        data = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
        self.assertNotIn("pro-rules", data["tool"]["engines"])
        self.assertEqual(self.server.balance, 1)


if __name__ == "__main__":
    unittest.main()
