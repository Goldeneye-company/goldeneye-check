"""Тесты GoldenEye Check.

Встроенные проверки и отчёты тестируются без движков. Полный прогон по учебному проекту
запускается, только если движки установлены (gecheck install), иначе пропускается.

Запуск: python -m unittest discover -s tests
"""

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "bench"))

from gecheck.engines import builtin  # noqa: E402
from gecheck.install import NAMES, engine_path  # noqa: E402
from gecheck.model import Finding, mask_quoted, mask_secret  # noqa: E402
from gecheck.report import to_html, to_json, to_markdown  # noqa: E402
from gecheck.scanner import Options, ScanResult, run  # noqa: E402


class TempProject(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def write(self, rel, text):
        p = self.dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


class DownloadRetryTest(unittest.TestCase):
    """Временный сбой GitHub при скачивании движков не должен ронять установку."""

    def setUp(self):
        from gecheck import install
        self.install = install
        self.saved = (install.urllib.request.urlopen, install.RETRY_PAUSE)
        install.RETRY_PAUSE = 0

    def tearDown(self):
        self.install.urllib.request.urlopen, self.install.RETRY_PAUSE = self.saved

    def fake(self, codes):
        import io
        import urllib.error
        calls = []

        def urlopen(req, timeout=None):
            code = codes[len(calls)]
            calls.append(code)
            if code != 200:
                raise urllib.error.HTTPError(req.full_url, code, "err", {}, io.BytesIO(b""))
            return io.BytesIO(b"engine")
        self.install.urllib.request.urlopen = urlopen
        return calls

    def test_retries_server_errors(self):
        calls = self.fake([500, 502, 200])
        self.assertEqual(self.install._download("https://x/engine", log=lambda *_: None), b"engine")
        self.assertEqual(calls, [500, 502, 200])

    def test_gives_up_with_message(self):
        self.fake([500, 500, 500])
        with self.assertRaises(SystemExit) as ctx:
            self.install._download("https://x/engine", log=lambda *_: None)
        self.assertIn("после 3 попыток", str(ctx.exception))

    def test_client_error_is_not_retried(self):
        calls = self.fake([404, 200])
        with self.assertRaises(SystemExit):
            self.install._download("https://x/engine", log=lambda *_: None)
        self.assertEqual(calls, [404])


class MaskTest(unittest.TestCase):
    def test_secret_never_printed_whole(self):
        secret = "sk_live_" + "A" * 24
        masked = mask_secret(secret)
        self.assertNotIn(secret, masked)
        self.assertTrue(masked.startswith("sk_liv"))

    def test_short_values_fully_hidden(self):
        self.assertEqual(mask_secret("hunter2"), "••••••")

    def test_quoted_values_masked_in_snippet(self):
        line = 'const ADMIN_PASSWORD = "Qwerty2026!";'
        self.assertNotIn("Qwerty2026!", mask_quoted(line))


class BuiltinTest(TempProject):
    def test_supabase_table_without_rls(self):
        self.write("supabase/migrations/001.sql",
                   "create table profiles (id uuid);\n"
                   "create table public.orders (id int);\n"
                   "alter table public.orders enable row level security;\n")
        tables = [f.anchor for f in builtin.check_supabase_rls(self.dir)]
        self.assertEqual(tables, ["public.profiles"])

    def test_firebase_open_write_is_critical(self):
        self.write("firestore.rules", "match /{d=**} {\n  allow read, write: if true;\n}\n")
        found = builtin.check_firebase(self.dir)
        self.assertEqual([(f.severity, f.line) for f in found], [("critical", 2)])

    def test_firebase_closed_rules_ok(self):
        self.write("firestore.rules", "allow read: if request.auth != null;\n")
        self.assertEqual(builtin.check_firebase(self.dir), [])

    def test_compose_default_password_and_port(self):
        self.write("docker-compose.yml",
                   "services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: postgres\n"
                   "    ports:\n      - \"5432:5432\"\n")
        rules = sorted(f.rule for f in builtin.check_compose(self.dir))
        self.assertEqual(rules, ["ge.config.compose-db-port", "ge.config.compose-default-password"])

    def test_compose_localhost_port_ok(self):
        self.write("docker-compose.yml", "    ports:\n      - \"127.0.0.1:5432:5432\"\n")
        self.assertEqual(builtin.check_compose(self.dir), [])

    def test_public_env_secret(self):
        # значения нарочно ненастоящие: правило срабатывает по имени переменной, а не по виду ключа
        self.write(".env.local", "NEXT_PUBLIC_STRIPE_SECRET_KEY=fake-value-for-tests-only\n"
                                 "NEXT_PUBLIC_SUPABASE_URL=https://demo.supabase.co\n")
        found = builtin.check_public_env(self.dir)
        self.assertEqual([f.anchor for f in found], ["NEXT_PUBLIC_STRIPE_SECRET_KEY"])
        self.assertNotIn("fake-value-for-tests-only", found[0].snippet)

    def test_htaccess_indexes(self):
        self.write("public/.htaccess", "Options +Indexes\n")
        self.assertEqual(len(builtin.check_htaccess(self.dir)), 1)
        self.write("public/.htaccess", "Options -Indexes\n")
        self.assertEqual(builtin.check_htaccess(self.dir), [])


def _result(findings):
    return ScanResult(root=Path("demo"), findings=findings, warnings=[], engines={},
                      started_at="2026-10-04T00:00:00+00:00", duration=1.0)


def _finding(severity="critical", snippet="db.query(`SELECT ${id}`)"):
    return Finding(rule="ge.js.sql-injection", engine="opengrep", severity=severity, category="injection",
                   file="src/a.js", line=3, title={"ru": "SQL", "kk": "SQL", "en": "SQL"},
                   fix={"ru": "параметры", "kk": "параметрлер", "en": "params"}, snippet=snippet)


class ReportTest(unittest.TestCase):
    def test_json_has_no_code_by_default(self):
        data = to_json(_result([_finding()]))
        self.assertNotIn("snippet", data["findings"][0])
        self.assertEqual(data["schema"], "goldeneye-check/report@1")

    def test_json_snippets_opt_in(self):
        data = to_json(_result([_finding()]), include_snippets=True)
        self.assertIn("snippet", data["findings"][0])

    def test_score_and_grade(self):
        r = _result([_finding("critical"), _finding("high", "x")])
        self.assertEqual((r.score, r.grade), (65, "D"))
        self.assertEqual((_result([]).score, _result([]).grade), (100, "A"))

    def test_dependencies_penalty_capped(self):
        deps = []
        for _ in range(12):
            f = _finding("high", "x")
            f.category = "dependencies"
            deps.append(f)
        r = _result(deps)
        self.assertEqual((r.score, r.grade), (70, "C"))

    def test_html_escapes_code(self):
        page = to_html(_result([_finding(snippet="<script>alert(1)</script>")]), "kk")
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn('lang="kk"', page)

    def test_fingerprint_ignores_line_shift(self):
        a, b = _finding(), _finding()
        b.line = 40
        self.assertEqual(a.fingerprint(), b.fingerprint())

    def test_markdown_all_languages(self):
        for lang in ("ru", "kk", "en"):
            self.assertIn("GoldenEye Check", to_markdown(_result([_finding()]), lang))


@unittest.skipUnless(all(engine_path(n).exists() for n in NAMES), "движки не установлены: gecheck install")
class FixtureTest(unittest.TestCase):
    """Полный прогон: каждая заложенная дыра найдена, безопасные фрагменты чистые."""

    @classmethod
    def setUpClass(cls):
        from make_fixture import CASES, build, marker_lines
        cls.tmp = Path(tempfile.mkdtemp())
        root = cls.tmp / "fixture"
        build(root)
        cls.cases, cls.markers = CASES, marker_lines(root)
        cls.result = run(root, Options(), log=lambda *_: None)
        cls.hits = {(f.file, f.line) for f in cls.result.findings} | {(f.file, None) for f in cls.result.findings}

    @classmethod
    def tearDownClass(cls):
        from make_fixture import remove_tree
        remove_tree(cls.tmp)

    def test_all_vulnerabilities_found(self):
        missed = [cid for cid, (rel, line) in self.markers.items()
                  if cid.startswith("V") and (rel, line) not in self.hits]
        self.assertEqual(missed, [])

    def test_no_false_positives(self):
        false = [cid for cid, (rel, line) in self.markers.items()
                 if cid.startswith("S") and (rel, line) in self.hits]
        self.assertEqual(false, [])

    def test_report_json_has_no_raw_secrets(self):
        text = json.dumps(to_json(self.result, include_snippets=True), ensure_ascii=False)
        self.assertNotRegex(text, r"sk_live_[A-Za-z0-9]{24}")
        self.assertNotRegex(text, r"T3BlbkFJ[A-Za-z0-9_-]{20}")


if __name__ == "__main__":
    unittest.main()
