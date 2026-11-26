"""Pro sections of the report: rendering of the tables the server sends (the real tables are not in this repository)."""

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gecheck import pro_report  # noqa: E402
from gecheck.report import to_html, to_json, to_markdown, write_reports  # noqa: E402
from gecheck.scanner import Options, run  # noqa: E402

T = {"ru": "т", "kk": "т", "en": "t"}

# A small stand-in for the server tables
COMPLIANCE = {
    "iso27002": {"version": "test", "national": {"designation": "СТ РК ISO/IEC 27001-2023", "verified": False,
                                                 "note": {"ru": "Нужно подтвердить нумерацию", "kk": "Растау керек",
                                                          "en": "Numbering to be confirmed"}},
                 "controls": {"8.5": {"title": {"ru": "Безопасная аутентификация", "kk": "Қауіпсіз аутентификация",
                                                "en": "Secure authentication"}, "categories": ["B", "C", "H"], "shows": T},
                              "8.13": {"title": {"ru": "Резервное копирование", "kk": "Резервтік көшіру",
                                                 "en": "Information backup"}, "categories": ["K"], "shows": T}}},
    "kz": {"version": "test", "sources": [{"id": "ET", "title": {"ru": "Единые требования", "kk": "Бірыңғай талаптар",
                                                                  "en": "Unified requirements"}, "applies": T}],
           "requirements": [{"id": "ET-47", "source": "ET", "ref": "п. 47", "controls": ["8.5"], "categories": ["B"],
                             "measures": ["mfa"], "partial": False, "text": {"ru": "MFA", "kk": "MFA", "en": "MFA"}},
                            {"id": "ET-75", "source": "ET", "ref": "п. 75", "controls": ["8.13"], "categories": ["K"],
                             "partial": True, "text": T}]},
    "checklist": {"version": "test", "items": [{"control": "5.24", "et": None,
                                                "question": {"ru": "Есть ли порядок реагирования?", "kk": "?", "en": "?"},
                                                "evidence": T}]},
    "issued_to": 7, "issued_on": "2026-11-26",
}


class ProReportTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = Path(tempfile.mkdtemp())
        (cls.dir / "index.php").write_text("<?php\nsession_start();\nif (password_verify($_POST['p'], $h)) {}\n",
                                           encoding="utf-8")
        cls.result = run(cls.dir, Options(history=False, deps=False, pro_compliance=COMPLIANCE), log=lambda *_: None)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir, ignore_errors=True)

    def test_statuses(self):
        pro = self.result.pro
        self.assertEqual([c["id"] for c in pro["controls"]], ["8.5", "8.13"])
        req = {r["id"]: r["status"] for r in pro["requirements"]}
        self.assertEqual(req["ET-47"], "not_done")      # the requirement names MFA, the code has none
        self.assertIn(req["ET-75"], ("partial", "not_done", "not_assessed"))  # never "done" for a partial requirement

    def test_sections_replace_the_lite_summary(self):
        page = to_html(self.result, "ru")
        self.assertIn("Меры ISO/IEC 27002:2022", page)
        self.assertIn("Требования Республики Казахстан", page)
        self.assertIn("Есть ли порядок реагирования?", page)
        self.assertIn("Нужно подтвердить нумерацию", page)
        self.assertNotIn("GoldenEye Check Pro.</p>", page.split("Меры ISO/IEC 27002:2022")[1][:2000])
        md = to_markdown(self.result, "en")
        self.assertIn("| 8.5 Secure authentication |", md)
        data = to_json(self.result)["pro"]
        self.assertEqual({r["id"] for r in data["requirements"]}, {"ET-47", "ET-75"})
        self.assertNotIn("text", json.dumps(data["requirements"]))  # statuses only, the texts stay with the server

    def test_audit_report_and_pdf(self):
        out = self.dir / ".goldeneye-check"
        with mock.patch.object(pro_report, "print_pdf", return_value=False):
            written = write_reports(self.result, out, {"html", "pdf"}, "kk")
        names = {p.name for p in written}
        self.assertIn("report-audit.html", names)
        audit = (out / "report-audit.html").read_text(encoding="utf-8")
        for words in ("Бастапқы код қауіпсіздігін тексеру есебі", "9. Шектеулер", "п. 47"):
            self.assertIn(words, audit)
        self.assertTrue(any("PDF" in w for w in self.result.warnings))

    def test_without_pro_there_is_no_audit_report(self):
        lite = run(self.dir, Options(history=False, deps=False), log=lambda *_: None)
        self.assertIsNone(lite.pro)
        out = Path(tempfile.mkdtemp())
        try:
            written = write_reports(lite, out, {"html", "pdf"}, "en")
            self.assertEqual([p.name for p in written], ["report.html"])
            self.assertTrue(any("Pro" in w for w in lite.warnings))
        finally:
            shutil.rmtree(out, ignore_errors=True)

    def test_broken_tables_are_ignored(self):
        self.assertFalse(pro_report.valid({"iso27002": {}}))
        self.assertFalse(pro_report.valid(None))


class BrowserTest(unittest.TestCase):
    def test_print_pdf_without_a_browser(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            (tmp / "a.html").write_text("<p>x</p>", encoding="utf-8")
            with mock.patch.object(pro_report, "find_browser", return_value=None):
                self.assertFalse(pro_report.print_pdf(tmp / "a.html", tmp / "a.pdf"))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
