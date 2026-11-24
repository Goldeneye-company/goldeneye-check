"""Configuration readers, the KB of image defaults and the stage 4-5 configuration checks."""

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from gecheck import kb  # noqa: E402
from gecheck.config import dockerfile, ini, yamlish  # noqa: E402
from gecheck.engines import config  # noqa: E402
from gecheck.i18n import LANGS, TEXTS  # noqa: E402
from gecheck.methodology import CATEGORIES  # noqa: E402
from gecheck.stages.findings import RULES  # noqa: E402


class Project(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def write(self, rel, text):
        p = self.dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")

    def rules(self):
        return sorted((f.rule.split(".")[-1], f.file, f.line) for f in config.scan(self.dir, []))

    def keys(self):
        return {r for r, _f, _l in self.rules()}


class YamlishTest(unittest.TestCase):
    def test_compose_structure_and_lines(self):
        node = yamlish.parse(
            "services:\n"
            "  web:   # comment\n"
            "    image: \"nginx:1.27\"\n"
            "    ports:\n"
            "      - \"127.0.0.1:8080:80\"\n"
            "    environment:\n"
            "      - KEY=value # trailing\n"
            "    command: |\n"
            "      run\n"
            "      --flag\n"
            "    healthcheck:\n"
            "      test: [\"CMD\", \"true\"]\n"
            "  db:\n"
            "    volumes:\n"
            "      - type: volume\n"
            "        source: data\n")
        web = node["services"]["web"]
        self.assertEqual(node["services"].lines, {"web": 2, "db": 13})
        self.assertEqual(web["image"].value, "nginx:1.27")
        self.assertEqual(web["ports"][0].value, "127.0.0.1:8080:80")
        self.assertEqual(web["ports"][0].line, 5)
        self.assertEqual(web["environment"][0].value, "KEY=value")
        self.assertEqual(web["command"].value, "run\n--flag")
        self.assertEqual(web["healthcheck"]["test"].value, '["CMD", "true"]')
        self.assertEqual(node["services"]["db"]["volumes"][0]["source"].value, "data")

    def test_hash_inside_quotes_is_not_a_comment(self):
        node = yamlish.parse("a: \"x # y\"\nb: 'it''s'\n")
        self.assertEqual(node["a"].value, "x # y")
        self.assertEqual(node["b"].value, "it's")


class DockerfileTest(unittest.TestCase):
    def test_stages_continuations_and_copies(self):
        stages = dockerfile.parse(
            "FROM node:22 AS build\n"
            "COPY . /src\n"
            "FROM php:8.3-apache\n"
            "RUN apt-get update \\\n"
            "    && apt-get install -y git\n"
            "COPY --from=build /src/dist /var/www/html\n"
            "COPY --chown=www-data:www-data conf/app.ini /usr/local/etc/php/conf.d/app.ini\n"
            "USER www-data\n")
        final = dockerfile.runtime(stages)
        self.assertEqual((stages[0].alias, final.image, final.line), ("build", "php:8.3-apache", 3))
        self.assertEqual([i.name for i in final.instructions], ["RUN", "COPY", "COPY", "USER"])
        self.assertEqual(final.instructions[0].line, 4)
        self.assertEqual(dockerfile.copies(final), [("conf/app.ini", "/usr/local/etc/php/conf.d/app.ini", 7)])

    def test_ini(self):
        values = ini.parse("; comment\n[PHP]\ndisplay_errors = Off ; inline\nexpose_php=\"0\"\n")
        self.assertEqual(values["display_errors"], ("Off", 3))
        self.assertFalse(ini.truthy(values["expose_php"][0]))


class KbTest(unittest.TestCase):
    def test_entries_match_variants(self):
        self.assertEqual([e["id"] for e in kb.entries_for("php:8.3-apache")], ["php", "php-apache"])
        self.assertEqual([e["id"] for e in kb.entries_for("php:8.3-fpm-alpine")], ["php"])
        self.assertEqual([e["id"] for e in kb.entries_for("docker.io/library/postgres:17")], ["postgres"])
        self.assertEqual(kb.entries_for("mycompany/app:1.0"), [])
        self.assertEqual([e["id"] for e in kb.entries_for("eclipse-temurin:21-jre")], ["java"])
        self.assertEqual([e["id"] for e in kb.entries_for("golang:1.23-alpine")], ["golang"])
        self.assertEqual([e["id"] for e in kb.entries_for("gcr.io/distroless/static:nonroot")], ["distroless"])

    def test_every_entry_documents_its_source(self):
        for e in kb.load()["images"]:
            self.assertTrue(e["source"], e["id"])
            self.assertIn("checked", e)


class RuleMetadataTest(unittest.TestCase):
    def test_rules_have_texts_and_valid_categories(self):
        for key, (category, detector, cwe, *_rest) in RULES.items():
            self.assertIn(category, CATEGORIES, key)
            self.assertTrue(cwe.startswith("CWE-"), key)
            for part in ("title", "fix"):
                for lang in LANGS:
                    self.assertTrue(TEXTS[key][part][lang], f"{key} {part} {lang}")


VULNERABLE_COMPOSE = """services:
  app:
    build: .
    ports:
      - "8080:80"
    environment:
      ADMIN_PASSWORD: ${ADMIN_PASSWORD:-Admin123!}
      DB_USER: ${DB_USER:-app}
  db:
    image: postgres:17-alpine
    environment:
      POSTGRES_USER: ${DB_USER:-app}
      POSTGRES_PASSWORD: ${DB_PASSWORD:-change_me}
"""

SAFE_COMPOSE = """services:
  proxy:
    image: caddy:2@sha256:aaaa
    ports:
      - "443:443"
    read_only: true
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true
    deploy:
      resources:
        limits:
          memory: 128m
  app:
    build: .
    ports:
      - "127.0.0.1:8080:8080"
    read_only: true
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    mem_limit: 256m
    environment:
      ADMIN_PASSWORD: ${ADMIN_PASSWORD:?ADMIN_PASSWORD is not set}
      DB_USER: app_rw
  db:
    image: postgres:17-alpine@sha256:bbbb
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    mem_limit: 512m
    environment:
      POSTGRES_USER: owner
      POSTGRES_PASSWORD_FILE: /run/secrets/pg
"""

SAFE_DOCKERFILE = """FROM php:8.3-apache@sha256:cccc
RUN mv "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"
COPY docker/php/app.ini /usr/local/etc/php/conf.d/app.ini
COPY docker/apache/security.conf /etc/apache2/conf-enabled/security.conf
USER www-data
"""


class ConfigChecksTest(Project):
    def test_vulnerable_compose(self):
        self.write("docker-compose.yml", VULNERABLE_COMPOSE)
        self.write("Dockerfile", "FROM php:8.3-apache\n")
        self.write("index.php", "<?php\nsession_start();\n$t = date('Y-m-d H:i:s');\n")
        found = self.rules()
        self.assertIn(("compose-default-secret", "docker-compose.yml", 7), found)
        self.assertIn(("compose-default-secret", "docker-compose.yml", 13), found)
        self.assertIn(("no-tls", "docker-compose.yml", 5), found)
        self.assertIn(("db-superuser", "docker-compose.yml", 12), found)
        self.assertIn(("php-display-errors", "Dockerfile", 1), found)
        self.assertIn(("php-session-strict", "index.php", 2), found)
        self.assertIn(("php-timezone", "index.php", 3), found)
        self.assertIn(("container-hardening", "docker-compose.yml", 2), found)
        self.assertIn(("image-unpinned", "Dockerfile", 1), found)

    def test_safe_configuration_is_quiet(self):
        self.write("docker-compose.yml", SAFE_COMPOSE)
        self.write("Dockerfile", SAFE_DOCKERFILE)
        self.write("docker/php/app.ini", "expose_php = Off\nsession.use_strict_mode = 1\ndate.timezone = UTC\n")
        self.write("docker/apache/security.conf", "ServerTokens Prod\nServerSignature Off\n")
        self.write("index.php", "<?php\nsession_start();\n$t = date('Y-m-d H:i:s');\n")
        self.assertEqual(self.rules(), [])

    def test_tls_terminator_or_localhost_port(self):
        self.write("docker-compose.yml", "services:\n  web:\n    image: node:22@sha256:1\n    ports:\n"
                                         "      - \"127.0.0.1:3000:3000\"\n")
        self.assertNotIn("no-tls", self.keys())

    def test_nginx_server_tokens_from_mounted_config(self):
        compose = ("services:\n  web:\n    image: nginx:1.27@sha256:1\n    ports:\n      - \"443:443\"\n"
                   "    volumes:\n      - ./nginx/site.conf:/etc/nginx/conf.d/default.conf:ro\n")
        self.write("docker-compose.yml", compose)
        self.write("nginx/site.conf", "server { listen 443 ssl; }\n")
        self.assertIn(("server-tokens", "docker-compose.yml", 3), self.rules())
        self.write("nginx/site.conf", "server_tokens off;\nserver { listen 443 ssl; }\n")
        self.assertNotIn("server-tokens", self.keys())

    def test_mysql_root_user(self):
        self.write("docker-compose.yml", "services:\n  app:\n    image: app@sha256:1\n    environment:\n"
                                         "      DB_USER: root\n  db:\n    image: mysql:8@sha256:2\n"
                                         "    environment:\n      MYSQL_ROOT_PASSWORD_FILE: /run/secrets/x\n")
        self.assertIn("db-superuser", self.keys())


class JavaGoTest(Project):
    def test_build_image_at_runtime(self):
        self.write("Dockerfile", "FROM golang:1.23\nCOPY . .\nRUN go build -o /app\nCMD [\"/app\"]\n")
        self.assertIn(("build-image-runtime", "Dockerfile", 1), self.rules())
        self.write("Dockerfile", "FROM golang:1.23 AS build\nRUN go build -o /app\n"
                                 "FROM gcr.io/distroless/static:nonroot\nCOPY --from=build /app /app\n")
        self.assertNotIn("build-image-runtime", self.keys())

    def test_jvm_debug_and_jmx(self):
        self.write("docker-compose.yml",
                   "services:\n  api:\n    image: eclipse-temurin:21-jre@sha256:1\n    environment:\n"
                   "      JAVA_TOOL_OPTIONS: -agentlib:jdwp=transport=dt_socket,server=y,address=*:5005\n"
                   "    command: java -Dcom.sun.management.jmxremote.authenticate=false -jar app.jar\n")
        found = self.rules()
        self.assertIn(("java-debug-port", "docker-compose.yml", 5), found)
        self.assertIn(("jmx-no-auth", "docker-compose.yml", 6), found)

    def test_spring_boot_properties(self):
        self.write("pom.xml", "<project><parent><artifactId>spring-boot-starter-parent</artifactId></parent></project>")
        self.write("src/main/resources/application.yml",
                   "management:\n  endpoints:\n    web:\n      exposure:\n        include: \"*\"\n"
                   "server:\n  error:\n    include-stacktrace: always\n")
        self.write("src/main/resources/application-dev.properties", "spring.h2.console.enabled=true\n")
        self.write("src/test/resources/application.properties", "spring.h2.console.enabled=true\n")
        sev = {(f.rule.split(".")[-1], f.file): f.severity for f in config.scan(self.dir, [])}
        self.assertEqual(sev[("spring-actuator-exposed", "src/main/resources/application.yml")], "high")
        self.assertEqual(sev[("spring-stacktrace", "src/main/resources/application.yml")], "medium")
        self.assertEqual(sev[("spring-h2-console", "src/main/resources/application-dev.properties")], "low")
        self.assertNotIn(("spring-h2-console", "src/test/resources/application.properties"), sev)

    def test_spring_safe_and_not_spring(self):
        self.write("pom.xml", "<project><artifactId>spring-boot-starter-web</artifactId></project>")
        self.write("src/main/resources/application.properties",
                   "management.endpoints.web.exposure.include=health,info\n")
        self.assertEqual([r for r in self.keys() if r.startswith("spring")], [])
        self.write("pom.xml", "<project><artifactId>plain</artifactId></project>")
        self.write("src/main/resources/application.properties", "management.endpoints.web.exposure.include=*\n")
        self.assertEqual([r for r in self.keys() if r.startswith("spring")], [])

    def test_tomcat(self):
        self.write("Dockerfile", "FROM tomcat:10.1-jre21\nRUN cp -r webapps.dist/* webapps/\n")
        found = self.rules()
        self.assertIn(("tomcat-manager", "Dockerfile", 2), found)
        self.assertIn(("server-tokens", "Dockerfile", 1), found)
        self.write("Dockerfile", "FROM tomcat:10.1-jre21\nCOPY conf/server.xml /usr/local/tomcat/conf/server.xml\n")
        self.write("conf/server.xml", '<Valve className="org.apache.catalina.valves.ErrorReportValve" '
                                      'showReport="false" showServerInfo="false"/>\n')
        self.assertNotIn("server-tokens", self.keys())

    def test_gin_debug_mode(self):
        self.write("go.mod", "module x\nrequire github.com/gin-gonic/gin v1.10.0\n")
        self.write("main.go", "package main\nfunc main() {\n\tr := gin.Default()\n\tr.Run()\n}\n")
        self.assertIn(("gin-debug", "main.go", 3), self.rules())
        self.write("Dockerfile", "FROM golang:1.23 AS b\nFROM scratch\nENV GIN_MODE=release\n")
        self.assertNotIn("gin-debug", self.keys())

    def test_go_pprof_and_timeouts(self):
        self.write("main.go", 'package main\nimport _ "net/http/pprof"\n'
                              'func main() {\n\thttp.ListenAndServe(":8080", nil)\n}\n')
        sev = {(f.rule.split(".")[-1], f.line): f.severity for f in config.scan(self.dir, [])}
        self.assertEqual(sev[("go-pprof", 2)], "high")
        self.assertIn(("go-http-timeouts", 4), sev)
        self.write("main.go", "package main\nfunc main() {\n\tsrv := &http.Server{\n\t\tAddr: \":8080\",\n"
                              "\t\tReadHeaderTimeout: 5 * time.Second,\n\t}\n\tsrv.ListenAndServe()\n}\n")
        self.write("main_test.go", 'package main\nimport _ "net/http/pprof"\n')
        self.assertEqual(self.keys() & {"go-pprof", "go-http-timeouts"}, set())


class CodeDefaultsTest(Project):
    def test_fallback_secrets_in_three_languages(self):
        self.write("a.php", "<?php $p = getenv('DB_PASSWORD') ?: 'S3cret-pass';\n")
        self.write("b.js", "const key = process.env.API_KEY || 'abc123xyz';\n")
        self.write("c.py", "TOKEN = os.getenv('TOKEN', 'tok_123456')\n")
        self.write("d.py", "HOST = os.getenv('DB_HOST', 'localhost')\n")
        found = self.rules()
        self.assertEqual([f for r, f, _l in found if r == "code-default-secret"], ["a.php", "b.js", "c.py"])

    def test_default_password_printed_on_page(self):
        self.write("boot.php", "<?php $p = getenv('ADMIN_PASSWORD') ?: 'Admin123!';\n")
        self.write("login.php", "<?php echo '<p>Demo: admin@example.com / Admin123!</p>';\n")
        self.assertIn(("credentials-in-page", "login.php", 1), self.rules())

    def test_insecure_cookie(self):
        self.write("a.php", "<?php session_set_cookie_params(['httponly' => true, 'secure' => false]);\n")
        self.write("settings.py", "SESSION_COOKIE_SECURE = False\n")
        self.write("app.js", "app.use(session({ cookie: { secure: false } }));\n")
        self.write("other.js", "const opts = { secure: false };\n")
        files = [f for r, f, _l in self.rules() if r == "cookie-not-secure"]
        self.assertEqual(files, ["a.php", "app.js", "settings.py"])


if __name__ == "__main__":
    unittest.main()
