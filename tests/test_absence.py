"""Step 2 of the methodology plan: missing measures (stage 4), inventory (stage 2), confirmed measures
and verification of candidates (stage 7)."""

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gecheck.engines import config  # noqa: E402
from gecheck.report import write_reports  # noqa: E402
from gecheck.stages import context, inventory, measures  # noqa: E402
from gecheck.stages.code import Structure, mask  # noqa: E402


class Project(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def write(self, rel, text):
        p = self.dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")

    def found(self):
        return {(f.rule.split(".")[-1], f.file, f.line): f for f in config.scan(self.dir, [])}

    def rules(self):
        return {r for r, _f, _l in self.found()}

    def severity(self, rule):
        return next(f.severity for (r, _f, _l), f in self.found().items() if r == rule)


class CodeStructureTest(unittest.TestCase):
    def test_braces_in_strings_and_heredoc_do_not_count(self):
        code = "<?php\n$a = '{';\n$db->exec(<<<'SQL'\nCREATE TABLE t (x INT) -- }\nSQL);\nfunction f() {\n  return 1;\n}\n"
        s = Structure(code)
        self.assertEqual([(b.start, b.end, b.name) for b in s.blocks], [(6, 8, "f")])
        self.assertIn("CREATE TABLE", mask(code, "php", keep_strings=True))
        self.assertNotIn("CREATE TABLE", mask(code, "php"))

    def test_route_blocks_and_top_level(self):
        code = ("<?php\n$x = 1;\nif ($page === 'login') {\n  login();\n}\nfor ($i = 0; $i < 3; $i++) {\n  try {\n"
                "    connect();\n  } catch (E $e) {\n    retry();\n  }\n}\n")
        s = Structure(code)
        self.assertEqual(s.unit(4).start, 3)
        self.assertFalse(s.unit(4).is_function)
        self.assertTrue(s.always_runs(2))
        self.assertFalse(s.always_runs(4))
        self.assertTrue(s.always_runs(8))
        self.assertFalse(s.always_runs(10))

    def test_functions_and_methods(self):
        s = Structure("<?php\nclass A {\n  public function run(): void\n  {\n    x();\n  }\n}\n"
                      "$f = static function (int $a): bool {\n  return true;\n};\n")
        self.assertEqual(s.unit(5).name, "run")
        self.assertTrue(s.unit(9).is_function)
        js = Structure("app.post('/login', async (req, res) => {\n  check();\n});\n", "js")
        self.assertTrue(js.unit(2).is_function)


class GitIgnoreTest(Project):
    def test_rules(self):
        self.write(".gitignore", ".env\nsecrets/\n/build\n*.log\n!keep.log\ndocs/**/*.pdf\n")
        self.write(".goldeneye-check/.gitignore", "*\n")
        gi = inventory.GitIgnore(self.dir)
        self.assertTrue(gi.ignored(".env"))
        self.assertTrue(gi.ignored("app/.env"))
        self.assertTrue(gi.ignored("secrets/db_password"))
        self.assertTrue(gi.ignored("build/app.js"))
        self.assertFalse(gi.ignored("src/build/app.js"))
        self.assertTrue(gi.ignored("var/app.log"))
        self.assertFalse(gi.ignored("keep.log"))
        self.assertTrue(gi.ignored("docs/a/b/manual.pdf"))
        self.assertTrue(gi.ignored(".goldeneye-check/report.md"))
        self.assertFalse(gi.ignored("README.md"))


LOGIN = """<?php
if ($page === 'login') {
    $stmt = $db->prepare('SELECT * FROM users WHERE email = ?');
    $stmt->execute([$_POST['email']]);
    $user = $stmt->fetch();
    if ($user && password_verify($_POST['password'], $user['password_hash'])) {
        session_regenerate_id(true);
    }
}
"""


class LoginTest(Project):
    def test_no_limit_no_mfa_is_critical(self):
        self.write("index.php", LOGIN)
        self.assertEqual(self.severity("login-no-limit"), "critical")
        self.assertIn(("login-timing", "index.php", 6), self.found())

    def test_second_factor_lowers_to_high(self):
        self.write("index.php", LOGIN)
        self.write("totp.php", "<?php\nfunction totp_verify($s, $c) { return true; }\n")
        self.assertEqual(self.severity("login-no-limit"), "high")

    def test_attempt_limit_and_dummy_hash_are_quiet(self):
        code = LOGIN.replace("    $user = $stmt->fetch();\n",
                             "    if (too_many_attempts($ip)) exit;\n    $user = $stmt->fetch();\n"
                             "    if (!$user) password_hash('x', PASSWORD_DEFAULT);\n")
        self.write("index.php", code)
        self.assertFalse(self.rules() & {"login-no-limit", "login-timing"})

    def test_password_change_of_a_signed_in_user(self):
        self.write("account.php", "<?php\nfunction change_password() {\n    $me = require_user();\n"
                                  "    if (!password_verify($_POST['current'], $me['hash'])) return;\n}\n")
        self.assertNotIn("login-no-limit", self.rules())

    def test_javascript_and_python(self):
        self.write("server.js", "app.post('/login', async (req, res) => {\n  const u = await find(req.body.email);\n"
                                "  if (u && await bcrypt.compare(req.body.password, u.hash)) res.send('ok');\n});\n")
        self.write("app.py", "@app.post('/login')\ndef login():\n    user = find(request.form['email'])\n"
                             "    if user and check_password_hash(user.hash, request.form['password']):\n"
                             "        return 'ok'\n")
        found = self.found()
        self.assertIn(("login-no-limit", "server.js", 3), found)
        self.assertIn(("login-no-limit", "app.py", 4), found)

    def test_rate_limit_package_counts_for_the_whole_project(self):
        self.write("server.js", "app.post('/login', async (req, res) => {\n"
                                "  if (await bcrypt.compare(req.body.password, hash)) res.send('ok');\n});\n")
        self.write("package.json", '{"dependencies": {"express-rate-limit": "7.4.0"}}\n')
        self.assertNotIn("login-no-limit", self.rules())

    def test_command_line_tools_are_not_reachable(self):
        self.write("bin/check-password.php", LOGIN)
        self.assertNotIn("login-no-limit", self.rules())


UPLOAD = """<?php
if ($page === 'upload') {
    $name = bin2hex(random_bytes(16));
    move_uploaded_file($_FILES['f']['tmp_name'], '/data/' . $name);
    $db->prepare('INSERT INTO files (name) VALUES (?)')->execute([$name]);
}
if ($page === 'get') {
    readfile('/data/' . $_GET['name']);
}
"""


class UploadTest(Project):
    def test_unprotected_upload(self):
        self.write("index.php", UPLOAD)
        found = self.found()
        upload = found[("upload-unprotected", "index.php", 4)]
        self.assertEqual(upload.severity, "high")
        self.assertIn("antivirus", upload.title["en"])
        self.assertEqual(found[("no-deletion", "index.php", 5)].severity, "high")
        self.assertIn(("no-quota", "index.php", 4), found)

    def test_protected_upload_is_quiet(self):
        self.write("index.php", UPLOAD)
        self.write("lib.php", "<?php\nfunction scan($p) { return clamd_instream($p); }\n"
                              "function digest($p) { return hash_file('sha256', $p); }\n"
                              "function seal($d, $k) { return sodium_crypto_secretbox($d, $n, $k); }\n"
                              "function remove($p) { unlink($p); }\n"
                              "function room() { return disk_free_space('/data'); }\n")
        self.assertFalse(self.rules() & {"upload-unprotected", "no-deletion", "no-quota"})

    def test_a_comment_is_not_a_measure(self):
        self.write("index.php", UPLOAD + "// TODO: clamav, hash_file, unlink\n")
        self.assertIn("upload-unprotected", self.rules())
        self.assertIn("no-deletion", self.rules())


class EntropyTest(Project):
    def test_short_password_without_and_with_a_limit(self):
        self.write("a.php", "<?php\n$password = strtoupper(substr(bin2hex(random_bytes(8)), 0, 12));\n"
                            "$token = bin2hex(random_bytes(24));\n")
        found = self.found()
        f = found[("weak-generated-secret", "a.php", 2)]
        self.assertEqual(f.severity, "medium")
        self.assertIn("48", f.title["en"])
        self.assertNotIn(("weak-generated-secret", "a.php", 3), found)
        self.write("b.php", "<?php\n$n = $db->query(\"SELECT COUNT(*) FROM attempts WHERE failed\");\n")
        self.assertEqual(self.severity("weak-generated-secret"), "low")

    def test_python_token(self):
        self.write("app.py", "import secrets\nreset_token = secrets.token_hex(4)\nsession_key = secrets.token_hex(32)\n")
        found = self.found()
        self.assertIn(("weak-generated-secret", "app.py", 2), found)
        self.assertNotIn(("weak-generated-secret", "app.py", 3), found)


RACE = """<?php
if ($page === 'file') {
    $n = $db->prepare("SELECT COUNT(*) FROM logs WHERE link = ? AND ip = ? AND result = 'wrong_password'");
    $n->execute([$id, $_SERVER['REMOTE_ADDR']]);
    $blocked = (int) $n->fetchColumn() >= 5;
}
"""


class RaceTest(Project):
    def test_count_then_decide_without_a_lock(self):
        self.write("index.php", RACE)
        f = self.found()[("limit-race", "index.php", 3)]
        self.assertEqual(f.severity, "high")
        self.assertIn("IP", f.title["en"])

    def test_send_limit_is_medium_and_reported_once(self):
        self.write("send.php", "<?php\n$st = $db->prepare('SELECT\n"
                               "    (SELECT COUNT(*) FROM login_codes WHERE email = ?) AS by_email,\n"
                               "    (SELECT COUNT(*) FROM login_codes WHERE ip = ?) AS by_ip');\n"
                               "$c = $st->fetch();\nif ($c['by_email'] >= 5) exit;\n")
        races = [f for (r, _f, _l), f in self.found().items() if r == "limit-race"]
        self.assertEqual([(f.line, f.severity) for f in races], [(3, "medium")])

    def test_transaction_before_the_count(self):
        self.write("index.php", RACE.replace("    $n = ", "    $db->beginTransaction();\n    $n = "))
        self.assertNotIn("limit-race", self.rules())

    def test_function_called_only_under_a_lock(self):
        self.write("limits.php", "<?php\nfunction is_locked($db, $ip) {\n"
                                 "    $s = $db->prepare('SELECT COUNT(*) FROM attempts WHERE ip = ? AND failed');\n"
                                 "    $s->execute([$ip]);\n    return $s->fetchColumn() >= 5;\n}\n")
        self.write("login.php", "<?php\nfunction login($db) {\n    $db->beginTransaction();\n"
                                "    if (is_locked($db, $ip)) return;\n}\n")
        self.assertNotIn("limit-race", self.rules())
        self.write("other.php", "<?php\nfunction other($db) {\n    if (is_locked($db, $ip)) return;\n}\n")
        self.assertIn("limit-race", self.rules())


class ErrorHandlerTest(Project):
    def test_plain_php(self):
        self.write("public/index.php", "<?php\nrequire 'app.php';\n")
        self.write("app.php", "<?php\nif (!$db) throw new RuntimeException('no db');\n")
        self.assertIn(("no-error-handler", "app.php", 2), self.found())

    def test_handler_or_framework(self):
        self.write("public/index.php", "<?php\nset_exception_handler('fail');\n")
        self.assertNotIn("no-error-handler", self.rules())
        self.write("public/index.php", "<?php\necho 1;\n")
        self.write("composer.json", '{"require": {"laravel/framework": "^11.0"}}\n')
        self.assertNotIn("no-error-handler", self.rules())


class BackupTest(Project):
    def test_database_without_backup(self):
        self.write("docker-compose.yml", "services:\n  db:\n    image: postgres:17@sha256:1\n")
        self.assertIn(("no-backup", "docker-compose.yml", 3), self.found())
        self.write("scripts/backup.sh", "#!/bin/sh\npg_dump -Fc app > /backups/app.dump\n")
        self.assertNotIn("no-backup", self.rules())

    def test_a_comment_in_a_script_is_not_a_backup(self):
        self.write("docker-compose.yml", "services:\n  db:\n    image: mysql:8@sha256:1\n")
        self.write("run.sh", "#!/bin/sh\n# add mysqldump later\nexec app\n")
        self.assertIn("no-backup", self.rules())


class PerRequestTest(Project):
    def test_endpoint_hashing_its_own_input(self):
        """An endpoint script that hashes a code it sends is not shared work of every request."""
        self.write("api/send-code.php", "<?php\n$code = random_int(0, 999999);\n"
                                        "$st->execute([password_hash((string) $code, PASSWORD_DEFAULT)]);\n")
        self.assertNotIn("per-request-heavy", self.rules())

    def test_top_level_hash_and_ddl(self):
        self.write("index.php", "<?php\nrequire __DIR__ . '/bootstrap.php';\n")
        self.write("bootstrap.php", "<?php\n$db->exec(<<<'SQL'\nCREATE TABLE IF NOT EXISTS t (id INT);\nSQL);\n"
                                    "$seed->execute([password_hash($p, PASSWORD_DEFAULT)]);\n"
                                    "if ($page === 'add') {\n    $h = password_hash($p, PASSWORD_DEFAULT);\n}\n"
                                    "function add($p) { return password_hash($p, PASSWORD_DEFAULT); }\n")
        found = self.found()
        self.assertIn(("per-request-heavy", "bootstrap.php", 2), found)
        self.assertIn(("per-request-heavy", "bootstrap.php", 5), found)
        self.assertNotIn(("per-request-heavy", "bootstrap.php", 7), found)
        self.assertNotIn(("per-request-heavy", "bootstrap.php", 9), found)

    def test_command_line_scripts(self):
        self.write("bin/run.php", "<?php\nrequire 'seed.php';\n")
        self.write("bin/seed.php", "<?php\n$seed->execute([password_hash($p, PASSWORD_DEFAULT)]);\n")
        self.assertNotIn("per-request-heavy", self.rules())


class InventoryTest(Project):
    def test_scanner_reports_and_dumps(self):
        self.write(".gitignore", ".env\n")
        self.write(".goldeneye-check/report.md", "# GoldenEye Check: 192.168.10.25\n")
        self.write("backup/app.sql", "INSERT INTO users VALUES (1, 'a@b.kz');\n" * 1000)
        self.write("docs/network.md", "Server 10.0.0.5\n")
        found = self.found()
        self.assertIn(("repo-artifact", ".goldeneye-check/report.md", None), found)
        self.assertIn(("repo-artifact", "backup/app.sql", None), found)
        self.assertNotIn(("repo-artifact", "docs/network.md", None), found)

    def test_ignored_reports_are_quiet(self):
        self.write(".goldeneye-check/report.md", "# GoldenEye Check: 192.168.10.25\n")
        self.write(".goldeneye-check/.gitignore", "*\n")
        self.assertNotIn("repo-artifact", self.rules())

    def test_absent_files(self):
        self.write("index.php", "<?php\necho 1;\n")
        inv = inventory.build(context.build(self.dir))
        for item in ("tests", "ci", "git"):
            self.assertIn(item, inv.absent)
        self.assertNotIn("php_ini", inv.absent)  # without an image php.ini belongs to the host
        self.assertIn("index.php", inv.roles["entry"])
        self.write("Dockerfile", "FROM php:8.3-apache\n")
        self.assertIn("php_ini", inventory.build(context.build(self.dir)).absent)

    def test_reports_folder_excludes_itself(self):
        class Result:  # the minimum write_reports needs for JSON
            pass
        out = self.dir / ".goldeneye-check"
        write_reports(Result(), out, set())
        self.assertEqual((out / ".gitignore").read_text(encoding="utf-8"), "*\n")


class MeasuresTest(Project):
    def test_measures_with_lines(self):
        self.write("index.php", "<?php\nsession_regenerate_id(true);\n$stmt = $db->prepare('SELECT 1');\n"
                                "// session_regenerate_id in a comment\n")
        ms = {m.key: m for m in measures.collect(context.build(self.dir))}
        self.assertEqual(ms["session_regenerate"].lines, [2])
        self.assertEqual(ms["prepared_statements"].lines, [3])

    def test_project_escape_helper(self):
        self.write("view.php", "<?php\nfunction e(string $v): string { return htmlspecialchars($v, ENT_QUOTES); }\n"
                               "echo '<p>' . e($name) . '</p>';\n")
        ms = {m.key: m for m in measures.collect(context.build(self.dir))}
        self.assertEqual(ms["output_escaping"].lines, [2, 3])


if __name__ == "__main__":
    unittest.main()
