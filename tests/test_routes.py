"""Step 3 of the methodology plan: routes (stage 3), the route x measure matrix and the route checks (stage 4)."""

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gecheck.engines import config  # noqa: E402
from gecheck.stages import context, matrix, measures, routes, system  # noqa: E402


class Project(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def write(self, rel, text):
        p = self.dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")

    def routes(self):
        src = measures.Sources(context.build(self.dir))
        return [(r.adapter, r.method, r.name, r.file, r.line) for r in routes.collect(src)]

    def cells(self):
        ctx = context.build(self.dir)
        src = measures.Sources(ctx)
        return {c.route.name: c for c in matrix.build(src, routes.collect(src), ctx)}

    def found(self):
        return {(f.rule.split(".")[-1], f.file, f.line): f for f in config.scan(self.dir, [])}

    def rules(self):
        return {r for r, _f, _l in self.found()}


FRONT = """<?php
require 'bootstrap.php';
$page = $_GET['page'] ?? 'login';
if ($page === 'logout') {
    $_SESSION = []; session_destroy();
}
if ($page === 'login') {
    if (password_verify($_POST['password'], $hash)) { $_SESSION['user'] = 1; }
}
$me = requireUser();
if ($page === 'revoke') {
    requireCsrf();
    $id = filter_input(INPUT_POST, 'link_id', FILTER_VALIDATE_INT);
    $db->prepare('UPDATE links SET revoked = 1 WHERE id = ?')->execute([$id]);
}
echo '<h1>Dashboard</h1>';
"""


class AdaptersTest(Project):
    def test_php_front_controller_and_guard(self):
        self.write("public/index.php", FRONT)
        self.write("public/bootstrap.php", "<?php\nsession_start();\n")
        got = self.routes()
        self.assertIn(("php-front", "ANY", "logout", "public/index.php", 4), got)
        self.assertIn(("php-front", "GET", "(default)", "public/index.php", 16), got)
        cells = self.cells()
        self.assertFalse(cells["login"].signed_in)
        self.assertTrue(cells["revoke"].signed_in)
        self.assertTrue(cells["revoke"].mutates and cells["revoke"].csrf)

    def test_php_route_table(self):
        self.write("public/index.php", "<?php\n$routes = [\n    'home' => 'route_home',\n    'save' => 'route_save',\n];\n"
                                       "$routes[$_GET['p'] ?? 'home']();\n")
        self.write("src/routes.php", "<?php\nfunction route_home() { echo 1; }\nfunction route_save() {\n"
                                     "    require_user();\n    audit('saved');\n}\n")
        cells = self.cells()
        self.assertEqual(set(cells), {"home", "save"})
        self.assertTrue(cells["save"].signed_in and cells["save"].audit)

    def test_express_flask_spring_go(self):
        self.write("server.js", "app.post('/items/:id', requireAuth, async (req, res) => {\n"
                                "  await db.query('DELETE FROM items WHERE id = $1', [req.params.id]);\n});\n"
                                "app.get('/health', health);\nfunction health(req, res) { res.send('ok'); }\n")
        self.write("app.py", "@app.route('/notes', methods=['POST'])\n@login_required\ndef add_note():\n"
                             "    db.session.add(Note())\n    db.session.commit()\n")
        self.write("Api.java", "@RestController\nclass Api {\n  @PostMapping(\"/orders\")\n"
                               "  public void create(@RequestBody Order o) {\n    repo.save(o);\n  }\n}\n")
        self.write("main.go", "func main() {\n  r.POST(\"/upload\", upload)\n  http.HandleFunc(\"/ping\", func(w http.ResponseWriter, "
                              "r *http.Request) {\n    w.Write([]byte(\"ok\"))\n  })\n}\nfunc upload(c *gin.Context) {\n}\n")
        got = {(a, m, n) for a, m, n, _f, _l in self.routes()}
        for item in (("express", "POST", "/items/:id"), ("express", "GET", "/health"), ("python", "POST", "/notes"),
                     ("spring", "POST", "/orders"), ("go", "POST", "/upload"), ("go", "ANY", "/ping")):
            self.assertIn(item, got)
        cells = self.cells()
        self.assertTrue(cells["/items/:id"].signed_in)
        self.assertTrue(cells["/notes"].signed_in and cells["/notes"].mutates)

    def test_sub_actions_inside_a_function_are_not_routes(self):
        self.write("public/index.php", "<?php\nfunction users() {\n    $page = $_GET['page'];\n"
                                       "    if ($page === 'create') {\n        add();\n    }\n}\n")
        self.assertEqual([r for r in self.routes() if r[0] == "php-front"], [])


class MatrixChecksTest(Project):
    def setUp(self):
        super().setUp()
        self.write("public/index.php", FRONT)
        self.write("public/bootstrap.php", "<?php\nsession_start();\n")

    def test_vulnerable_front_controller(self):
        found = self.found()
        audit = found[("route-no-audit", "public/index.php", 4)]
        self.assertEqual(audit.severity, "high")
        self.assertIn("revoke", audit.title["en"])
        self.assertIn(("logout-get", "public/index.php", 4), found)
        self.assertIn(("object-no-owner", "public/index.php", 14), found)
        self.assertIn(("session-no-timeout", "public/bootstrap.php", 2), found)

    def test_audit_owner_and_post_only_logout_are_quiet(self):
        code = FRONT.replace("$_SESSION = []; session_destroy();", "require_post(); audit('logout'); session_destroy();")
        code = code.replace("{ $_SESSION['user'] = 1; }", "{ audit('login'); }")
        code = code.replace("WHERE id = ?')->execute([$id]);", "WHERE id = ? AND user_id = ?')->execute([$id, $me]);\n"
                                                                 "    audit('revoked');")
        self.write("public/index.php", code)
        self.assertFalse(self.rules() & {"route-no-audit", "logout-get", "object-no-owner"})


class RouteSignalsTest(Project):
    def test_token_in_query_with_default_apache_logs(self):
        self.write("Dockerfile", "FROM php:8.3-apache\n")
        self.write("public/index.php", "<?php\n$page = $_GET['page'];\nif ($page === 'file') {\n"
                                       "    $t = $_GET['token'];\n}\n")
        self.assertIn(("token-in-query", "public/index.php", 4), self.found())
        self.write("docker/apache.conf", 'LogFormat "%a %t \\"%m %U %H\\" %>s" short\nCustomLog /dev/stdout short\n')
        self.assertNotIn("token-in-query", self.rules())

    def test_no_store_file_and_secret_responses(self):
        self.write("public/index.php", "<?php\n$page = $_GET['page'];\nif ($page === 'get') {\n"
                                       "    header('Content-Disposition: attachment');\n    readfile($path);\n}\n")
        self.assertIn(("route-no-store", "public/index.php", 5), self.found())
        self.write("src/headers.php", "<?php\nfunction headers() { header('Cache-Control: no-store'); }\n")
        self.assertNotIn("route-no-store", self.rules())

    def test_host_header_session_secret_and_csp(self):
        self.write("public/index.php", "<?php\n$page = $_GET['page'];\nif ($page === 'new') {\n"
                                       "    $url = 'https://' . $_SERVER['HTTP_HOST'] . '/f?t=' . $t;\n"
                                       "    $_SESSION['link'] = ['url' => $url, 'password' => $p];\n}\n"
                                       "echo '<input value=\"x\" onclick=\"this.select()\">';\n")
        found = self.found()
        self.assertIn(("host-header-url", "public/index.php", 4), found)
        self.assertIn(("secret-in-session", "public/index.php", 5), found)
        self.assertIn(("csp-missing", "public/index.php", 7), found)
        self.write("public/h.php", "<?php\nheader(\"Content-Security-Policy: default-src 'self'\");\n")
        self.assertNotIn("csp-missing", self.rules())

    def test_error_path(self):
        self.write("public/index.php", "<?php\n$page = $_GET['page'];\nif ($page === 'link') {\n"
                                       "    $doc = filter_input(INPUT_POST, 'document_id', FILTER_VALIDATE_INT);\n"
                                       "    $s = $db->prepare('INSERT INTO links (document_id) VALUES (?)');\n"
                                       "    $s->execute([$doc]);\n}\n")
        self.assertIn(("error-path-unhandled", "public/index.php", 6), self.found())
        self.write("public/boot.php", "<?php\nset_exception_handler('fail');\n")
        self.assertNotIn("error-path-unhandled", self.rules())


class ModelTest(Project):
    def test_assets_subjects_boundaries(self):
        self.write("public/index.php", FRONT)
        self.write("db/schema.sql", "CREATE TABLE users (\n id INT,\n email TEXT,\n password_hash TEXT\n);\n"
                                    "CREATE TABLE documents (\n id INT,\n name TEXT\n);\n")
        self.write("docker-compose.yml", "services:\n  db:\n    image: postgres:17\n")
        ctx = context.build(self.dir)
        src = measures.Sources(ctx)
        cells = matrix.build(src, routes.collect(src), ctx)
        model = system.build(ctx, src, cells, [])
        tables = {a["table"]: a for a in model["assets"]}
        self.assertEqual(tables["users"]["kind"], "credentials")
        self.assertIn("password_hash", tables["users"]["sensitive_columns"])
        self.assertEqual(tables["documents"]["kind"], "documents")
        self.assertIn("anonymous", model["subjects"])
        self.assertIn("user", model["subjects"])
        self.assertTrue(any(b["between"] == ["application", "database"] for b in model["trust_boundaries"]))


if __name__ == "__main__":
    unittest.main()
