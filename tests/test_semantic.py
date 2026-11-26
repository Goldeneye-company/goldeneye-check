"""The semantic layer (Pro): what is sent, how the answers are checked. A fake client stands in for the model."""

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gecheck import semantic  # noqa: E402
from gecheck.scanner import Options, run  # noqa: E402

CORPUS = Path(__file__).resolve().parent / "corpus" / "ghalam"
PROMPTS = {"version": "test", "model": "claude-opus-5-5", "effort": "high", "system": "You review code.",
           "routes_task": "Review the routes.", "docs_task": "Read the documentation."}
T = {"ru": "т", "kk": "т", "en": "t"}


def finding(kind, category, line, evidence, severity="medium", file="public/index.php"):
    return {"kind": kind, "category": category, "severity": severity, "confidence": "high", "file": file,
            "line": line, "evidence": evidence, "cwe": "CWE-200", "title": T, "fix": T}


class FakeStream:
    def __init__(self, message):
        self.message = message

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get_final_message(self):
        return self.message


class FakeClient:
    """Answers routes requests with `findings` and documentation requests with `claims`."""

    def __init__(self, findings=(), claims=(), stop_reason="end_turn"):
        self.calls = []
        self.findings, self.claims, self.stop_reason = list(findings), list(claims), stop_reason
        self.beta = SimpleNamespace(messages=SimpleNamespace(stream=self.stream))

    def stream(self, **kw):
        self.calls.append(kw)
        docs = kw["messages"][0]["content"].startswith(PROMPTS["docs_task"])
        body = {"claims": self.claims} if docs else {"findings": self.findings}
        usage = SimpleNamespace(input_tokens=1000, output_tokens=200, cache_read_input_tokens=500,
                                cache_creation_input_tokens=0)
        return FakeStream(SimpleNamespace(stop_reason=self.stop_reason, usage=usage,
                                          content=[SimpleNamespace(type="text", text=json.dumps(body))]))


def line_of(rel, n):
    return (CORPUS / rel).read_text(encoding="utf-8").splitlines()[n - 1].strip()


class SemanticTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.root = cls.tmp / "ghalam"
        shutil.copytree(CORPUS, cls.root, ignore=shutil.ignore_patterns("expected.json"))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def scan(self, client, **kw):
        options = Options(history=False, deps=False, ai=True, pro_semantic=PROMPTS, ai_client=client, **kw)
        return run(self.root, options, log=lambda *_: None)

    def test_answers_are_checked_against_the_code(self):
        s4 = finding("info_before_auth", "D", 77, line_of("public/index.php", 77)[:60])
        s3 = finding("secret_channel", "F", 134, "onclick=\"this.select()\"></label><label>Password")
        invented = finding("access_control", "D", 50, "if ($user->isAdmin()) {")
        duplicate = finding("access_control", "D", 124, line_of("public/index.php", 124)[:50])  # static owner check
        client = FakeClient(findings=[s4, s3, invented, duplicate])
        r = self.scan(client)
        ai = {(f.file, f.line, f.category_code) for f in r.findings if f.engine == "semantic"}
        self.assertEqual(ai, {("public/index.php", 77, "D"), ("public/index.php", 134, "F")})
        self.assertEqual(r.semantic["dropped"], 2)
        self.assertEqual(r.semantic["status"], "done")
        f = next(f for f in r.findings if f.engine == "semantic")
        self.assertEqual((f.detector, f.confidence), ("semantic", "medium"))  # a model alone is never "high"

    def test_request_shape(self):
        client = FakeClient()
        self.scan(client)
        kw = client.calls[0]
        self.assertEqual(kw["model"], "claude-opus-5-5")
        self.assertEqual(kw["fallbacks"], "default")
        self.assertIn("server-side-fallback-2026-07-01", kw["betas"])
        self.assertEqual(kw["output_config"]["effort"], "high")
        self.assertEqual(kw["output_config"]["format"]["type"], "json_schema")
        self.assertEqual(kw["system"][1]["cache_control"], {"type": "ephemeral"})
        self.assertNotIn("thinking", kw)
        self.assertEqual(len(client.calls), 2)  # one part with the routes, one with the documentation

    def test_secrets_are_masked(self):
        payload = semantic.dry_run(semantic.build_payload(*self.parts()), PROMPTS)
        self.assertNotIn("Admin123!", payload)
        self.assertNotIn("change_me", payload)
        self.assertIn("password_verify", payload)  # the code itself stays readable

    def parts(self):
        from gecheck.stages import context, matrix, measures, readme, routes
        ctx = context.build(self.root)
        src = measures.Sources(ctx)
        cells = matrix.build(src, routes.collect(src), ctx)
        return ctx, src, cells, [], measures.collect(ctx, src), readme.build(ctx)

    def test_readme_statements_from_free_text(self):
        quote = line_of("README.md", 12)  # "- a maximum number of downloads;"
        client = FakeClient(claims=[{"file": "README.md", "line": 12, "quote": quote, "category": "H",
                                     "status": "implemented", "reason": T},
                                    {"file": "README.md", "line": 3, "quote": "military-grade encryption",
                                     "category": "G", "status": "missing", "reason": T}])
        r = self.scan(client)
        rows = [x for x in r.assessment["declared"] if x.get("source") == "semantic"]
        self.assertEqual([(x["claim"].line, x["status"]) for x in rows], [(12, "implemented")])

    def test_refusal_and_consent(self):
        r = self.scan(FakeClient(findings=[finding("business_rule", "E", 8, "if ($page === 'logout') {")],
                                 stop_reason="refusal"))
        self.assertFalse([f for f in r.findings if f.engine == "semantic"])
        self.assertTrue(any("declined" in w for w in r.warnings))
        client = FakeClient()
        r = self.scan(client, ai_confirm=lambda _description: False)
        self.assertEqual((r.semantic["status"], client.calls), ("declined", []))

    def test_dry_run_sends_nothing(self):
        client = FakeClient()
        out = self.tmp / "payload.md"
        r = self.scan(client, ai_dry_run=out)
        self.assertEqual((r.semantic["status"], client.calls), ("dry_run", []))
        self.assertIn("## public/index.php lines", out.read_text(encoding="utf-8"))

    def test_needs_pro(self):
        r = run(self.root, Options(history=False, deps=False, ai=True), log=lambda *_: None)
        self.assertIsNone(r.semantic)
        self.assertTrue(any("Pro" in w for w in r.warnings))

    def test_cost(self):
        u = semantic.Usage(input_tokens=1_000_000, output_tokens=100_000, cache_read=1_000_000)
        self.assertEqual(u.cost("claude-opus-5-5"), 4.0 + 2.0 + 0.4)
        self.assertIsNone(u.cost("some-other-model"))


if __name__ == "__main__":
    unittest.main()
