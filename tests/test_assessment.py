"""Step 4 of the methodology plan: stages 1, 6, 8, 9 and 10, coverage and the report sections."""

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gecheck.assessment import assess, to_json  # noqa: E402
from gecheck.engines import config  # noqa: E402
from gecheck.methodology import classify  # noqa: E402
from gecheck.model import Finding  # noqa: E402
from gecheck.report import to_html, to_markdown  # noqa: E402
from gecheck.scanner import ScanResult  # noqa: E402
from gecheck.stages import context, iso, readme, roadmap  # noqa: E402


def finding(rule, severity="high", category="injection", cwe=None, engine="opengrep", file="a.php", line=1):
    return Finding(rule=rule, engine=engine, severity=severity, category=category, file=file, line=line,
                   title={"en": rule, "ru": rule, "kk": rule}, fix={"en": "fix", "ru": "fix", "kk": "fix"}, cwe=cwe)


class Project(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def write(self, rel, text):
        p = self.dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")

    def result(self):
        extras = {}
        findings = config.scan(self.dir, [], extras)
        r = ScanResult(root=self.dir, findings=findings, warnings=[], engines={}, started_at="2026-11-26T00:00:00",
                       duration=0.1, measures=extras["measures"], inventory=extras["inventory"], model=extras["model"])
        assess(r, extras)
        return r


class ClassifyTest(unittest.TestCase):
    def test_older_engines(self):
        cases = [(finding("ge.js.path", cwe="CWE-22"), "F", "localhost"),
                 (finding("ge.js.sqli", cwe="CWE-89"), "E", "localhost"),
                 (finding("gitleaks.key", category="secrets", engine="gitleaks", cwe="CWE-798"), "A", "localhost"),
                 (finding("osv.lodash", category="dependencies", engine="osv-scanner", severity="medium"), "M",
                  "production"),
                 (finding("ge.config.supabase-no-rls", category="data-access", engine="builtin", cwe="CWE-284"), "D",
                  "pilot")]
        for f, code, stage in cases:
            classify(f)
            self.assertEqual((f.category_code, f.stage), (code, stage), f.rule)
            self.assertTrue(f.iso and f.detector and f.effort)
        dep = cases[3][0]
        self.assertIn("8.8", dep.iso)


class ReadmeTest(Project):
    def test_claims_limitations_purpose_in_russian(self):
        self.write("README.md", "# Портал документов\n\nПередача документов клиентам.\n\n## Возможности\n\n"
                                "- блокировка после 5 неверных паролей;\n- ежедневный бэкап базы;\n- журнал действий;\n\n"
                                "## Ограничения\n\nДля интернета потребуется HTTPS и reverse proxy.\n")
        docs = readme.build(context.build(self.dir))
        self.assertEqual({c.key for c in docs.claims}, {"attempt_limit", "backup", "audit_log"})
        self.assertIn("documents", docs.purpose)
        self.assertTrue(docs.plans_proxy)
        self.assertIn("no_tls", docs.known_rules)
        self.assertEqual(docs.limitations[0][1], 13)

    def test_code_blocks_are_not_claims(self):
        self.write("README.md", "# App\n\n```\ndocker compose exec db pg_dump > backup.sql\n```\n")
        self.assertEqual(readme.build(context.build(self.dir)).claims, [])


class DeclarationTest(Project):
    def test_stated_backup_that_does_not_exist(self):
        self.write("README.md", "# App\n\n- nightly backup of the database\n- audit log of every action\n")
        self.write("docker-compose.yml", "services:\n  db:\n    image: postgres:17@sha256:1\n")
        self.write("app.php", "<?php\nfunction audit($a) { error_log($a); }\n")
        r = self.result()
        rows = {row["claim"].key: row["status"] for row in r.assessment["declared"]}
        self.assertEqual(rows, {"backup": "missing", "audit_log": "implemented"})
        declared = [f for f in r.findings if f.rule == "ge.docs.declared-not-implemented"]
        self.assertEqual([(f.file, f.line, f.category_code) for f in declared], [("README.md", 3, "K")])


class SeverityTest(Project):
    def test_chain_known_and_proxy_plan(self):
        self.write("README.md", "# App\n\n## Limitations\n\nThe demo password and HTTPS will be replaced; "
                                "a reverse proxy is planned.\n")
        self.write("index.php", "<?php\n$page = $_GET['page'];\nif ($page === 'login') {\n"
                                "    if (password_verify($_POST['p'], getenv('ADMIN_PASSWORD') ?: 'Admin123!')) {}\n}\n"
                                "echo '<p>Demo: Admin123!</p>';\n"
                                "$n = $db->prepare(\"SELECT COUNT(*) FROM tries WHERE ip = ? AND failed\");\n"
                                "$ip = $_SERVER['REMOTE_ADDR']; $b = $n->fetchColumn() >= 5;\n")
        r = self.result()
        by = {f.rule: f for f in r.findings}
        login = by["ge.code.login-no-limit"]
        self.assertIn("ge.config.credentials-in-page", login.chain)
        self.assertTrue(by["ge.config.credentials-in-page"].known)
        self.assertIn("proxy", by["ge.code.limit-race"].detail["en"])


class CoverageTest(Project):
    def test_ruby_only_is_preliminary_and_grade_a_needs_coverage(self):
        self.write("app.rb", "puts 'hi'\n")
        r = self.result()
        self.assertLess(r.coverage, 60)
        self.assertTrue(r.preliminary)
        self.assertEqual(r.grade, "B")  # no findings, but most categories were not checked
        self.assertIn("ruby", to_json(r)["coverage"]["languages"])

    def test_php_is_fully_covered(self):
        self.assertEqual(iso.coverage(["php"])["percent"], 100)


class RoadmapTest(unittest.TestCase):
    def test_verdict_and_top(self):
        a = finding("x", "high")
        a.stage = "pilot"
        b = finding("y", "critical")
        b.stage = "localhost"
        c = finding("z", "medium")
        c.stage = "production"
        self.assertEqual(roadmap.verdict([a, c]), "block_pilot")
        self.assertEqual(roadmap.verdict([a, b]), "block_localhost")
        self.assertEqual(roadmap.verdict([c]), "block_production")
        self.assertEqual(roadmap.verdict([]), "ready")
        self.assertEqual([f.rule for f in roadmap.top([c, a, b])], ["y", "x", "z"])


class ReportSectionsTest(Project):
    def test_sections_in_three_languages(self):
        self.write("README.md", "# Portal\n\n- audit log of actions\n")
        self.write("index.php", "<?php\n$stmt = $db->prepare('SELECT 1');\nsession_start();\n")
        r = self.result()
        for lang, words in (("ru", ("Готовность", "Подтверждённые меры", "Дорожная карта", "Покрытие и ограничения",
                                    "ISO/IEC 27001:2022")),
                            ("kk", ("Дайындық", "Расталған шаралар", "Жол картасы")),
                            ("en", ("Readiness", "Confirmed measures", "Roadmap", "Stated in the documentation"))):
            page = to_html(r, lang)
            md = to_markdown(r, lang)
            for w in words:
                self.assertIn(w, page, f"{lang}: {w}")
                self.assertIn(w, md, f"{lang} md: {w}")
        self.assertIn("8.15", to_markdown(r, "en"))  # ISO controls of a finding

    def test_site_report_has_no_code_sections(self):
        r = ScanResult(root=self.dir, findings=[], warnings=[], engines={}, started_at="2026-11-26T00:00:00",
                       duration=0.1, kind="site")
        self.assertNotIn("Readiness", to_html(r, "en"))


if __name__ == "__main__":
    unittest.main()
