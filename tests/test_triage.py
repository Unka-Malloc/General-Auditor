"""Deterministic triage contracts: no model, no verdict, stable classes."""
import io
import json
import os
from contextlib import redirect_stdout
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from general_auditor.cli import main
from general_auditor.local_store import LocalStore
from general_auditor.triage import REASONS, render_triage, triage


def finding(rule, path, value="", line_text=None, category="Backend information", line=1):
    """Build the subset of a saved scan finding that triage reads."""
    text = value if line_text is None else line_text
    spans = [] if value == "" else [{"start": 0, "end": len(value), "text": value}]
    return {
        "file": path,
        "line": line,
        "column": 1,
        "commit": "a" * 40,
        "rule": rule,
        "category": category,
        "severity": "warning",
        "evidence": "synthetic",
        "judgment": "unreviewed",
        "basis": "",
        "impact": "",
        "action": "",
        "source_evidence": {
            "kind": "literal_match",
            "matched_text": value,
            "span": {"start": 0, "end": len(value), "unit": "unicode_codepoint"},
            "value_spans": spans,
            "context": {"start_line": line, "end_line": line, "text": text},
            "provenance": {"commit": "a" * 40, "object": "b" * 40, "scope": "history", "source_kind": "blob"},
        },
    }


def synthetic_scan(repository="SymPolicy/Styio"):
    return {
        "id": "synthetic-triage-scan",
        "repository": repository,
        "scope": "history",
        "status": "completed_with_warnings",
        "head": "c" * 40,
        "coverage": {"commits": 3, "text_versions": 4, "excluded": []},
        "findings": [
            finding("privacy.credential.binding", "LICENSE", "https://www.gnu.org/licenses/"),
            finding("privacy.credential.binding", "src/config.py", "sk-EXAMPLE-your-key-here"),
            finding("privacy.endpoint.private-host", "docs/setup.md", "https://example.com/hook"),
            finding("privacy.endpoint.private-host", "docs/guide.md", "https://developer.mozilla.org/en-US/docs"),
            finding("privacy.endpoint.private-host", "docs/site.md", "https://styio.io/docs"),
            finding("privacy.local.machine-path", "src/parser.cpp", "\\/Users\\/name\\/project"),
            finding("privacy.personal.identifier", "src/version.py", "0123456789",
                    line_text="pin abcdef0123456789abcdef0123456789abcdef01 and 0123456789"),
            finding("privacy.local.machine-path", "packaging/templates/app.service", "/usr/share/app/templates"),
            finding("privacy.local.machine-path", "Dockerfile", "/home/app/.cache"),
            finding("privacy.local.deployment-path", "tests/fixtures/run.json", "/tmp/build/out"),
            finding("privacy.personal.identifier", "src/id.py", "00000000"),
            finding("privacy.local.machine-path", "README.md", "/Users/unka/DevSpace/project",
                    line_text="run cd /Users/unka/DevSpace/project"),
            finding("privacy.local.deployment-path", "docs/ops.md", "/var/folders/zd/abc/T/x"),
            finding("privacy.credential.binding", "src/app.py", "ghp_9f3aQ7mZpL2xV8nR4tYb6Kc1Wd5Ee0Sg7Uj2"),
            finding("privacy.endpoint.private-host", "docs/api.md", "https://api.meshrix-internal.io/v1"),
            finding("privacy.business.assignment", "src/analytics.dart", "tenant_acme_prod_2026"),
            finding("privacy.other.custom", "src/queue.py", "prod-cluster-7"),
            finding("repository.general-auditor-workflow", ".github/workflows/", category="Repository contract"),
            finding("privacy.endpoint.private-host", "src/client.js", "config.endpoint"),
            finding("privacy.backend.metadata", "src/schema.py", "tenant_id"),
            finding("privacy.personal.record-field", "src/session.dart", 'data["session_key"]'),
        ],
    }


class TriageClassificationTests(unittest.TestCase):
    def triaged(self):
        scan = synthetic_scan()
        return scan, triage(scan)

    def reason(self, result, index):
        for group in result["groups"]:
            for value in group["values"]:
                for location in value["locations"]:
                    if location["index"] == index:
                        return group["disposition"], group["reason"]
        raise AssertionError(f"finding {index} was not classified")

    def test_every_finding_gets_one_conservative_class(self):
        scan, result = self.triaged()
        expected = {
            0: ("cleared", "cleared-license-text"),
            1: ("cleared", "cleared-placeholder"),
            2: ("cleared", "cleared-reserved-reference"),
            3: ("cleared", "cleared-public-reference"),
            4: ("cleared", "cleared-repository-identity"),
            5: ("cleared", "cleared-escape-artifact"),
            6: ("cleared", "cleared-checksum-fragment"),
            7: ("cleared", "cleared-system-path"),
            8: ("cleared", "cleared-container-account"),
            9: ("cleared", "cleared-scratch-path"),
            10: ("cleared", "cleared-synthetic-literal"),
            11: ("decision", "decision-home-path"),
            12: ("decision", "decision-machine-temp"),
            13: ("decision", "decision-credential"),
            14: ("decision", "decision-endpoint"),
            15: ("decision", "decision-personal-or-backend"),
            16: ("decision", "decision-unclassified"),
            17: ("contract", "contract-declared"),
            18: ("cleared", "cleared-dotted-code-name"),
            19: ("cleared", "cleared-field-identifier"),
            20: ("cleared", "cleared-code-expression"),
        }
        for index, want in expected.items():
            self.assertEqual(self.reason(result, index), want, f"finding {index}")
        totals = result["totals"]
        self.assertEqual(totals["findings"], len(scan["findings"]))
        self.assertEqual(totals["decisions"] + totals["contracts"] + totals["cleared"], totals["findings"])
        self.assertEqual(totals["decisions"], 6)
        self.assertEqual(totals["contracts"], 1)
        self.assertEqual(totals["cleared"], 14)
        self.assertEqual(result["groups"][0]["disposition"], "decision")
        self.assertTrue(all(group["reason"] in REASONS for group in result["groups"]))

    def test_credentials_and_identifiers_never_clear_as_code(self):
        scan = synthetic_scan()
        # A quoted short password and a quoted identity value are literals, not expressions.
        scan["findings"].extend([
            finding("privacy.credential.binding", "src/auth.py", '"hunter2"'),
            finding("privacy.personal.identifier", "src/user.py", '"123456789"'),
        ])
        result = triage(scan)
        self.assertEqual(self.reason(result, 21), ("decision", "decision-credential"))
        self.assertEqual(self.reason(result, 22), ("decision", "decision-personal-or-backend"))

    def test_decision_groups_keep_distinct_values_and_cleared_groups_are_capped(self):
        scan = synthetic_scan()
        same = "/Users/unka/DevSpace/other"
        scan["findings"].extend(
            [finding("privacy.local.machine-path", "README.md", same, line_text="cd " + same)] * 4)
        scan["findings"].append(
            finding("privacy.local.machine-path", "README.md", "/Users/unka/elsewhere",
                    line_text="cd /Users/unka/elsewhere"))
        result = triage(scan)
        home = [group for group in result["groups"] if group["reason"] == "decision-home-path"]
        self.assertEqual(len(home), 1)
        # The base scan already carries one home path, so three distinct values remain.
        self.assertEqual(home[0]["count"], 6)
        self.assertEqual(home[0]["distinct"], 3)
        self.assertEqual(home[0]["values_shown"], 3)
        self.assertEqual(home[0]["values"][0]["occurrences"], 4)
        cleared = [group for group in result["groups"] if group["disposition"] == "cleared"]
        self.assertTrue(all(group["values_shown"] <= 8 for group in cleared))
        self.assertTrue(all(group["values_shown"] <= group["distinct"] for group in result["groups"]))

    def test_triage_is_deterministic_and_needs_no_model(self):
        scan = synthetic_scan()
        first, second = triage(scan), triage(scan)
        first.pop("generated_at")
        second.pop("generated_at")
        self.assertEqual(first, second)
        source = Path(__file__).resolve().parents[1] / "general_auditor" / "triage.py"
        text = source.read_text()
        for forbidden in ("urllib", "requests", "socket", "openai", "anthropic"):
            self.assertNotIn(forbidden, text)

    def test_invalid_scan_is_rejected(self):
        with self.assertRaises(ValueError):
            triage(None)
        with self.assertRaises(ValueError):
            triage({"findings": "not-a-list"})


class TriageReportTests(unittest.TestCase):
    def test_report_escapes_source_and_needs_no_script(self):
        scan = synthetic_scan()
        scan["findings"][11] = finding("privacy.local.machine-path", "README.md",
                                       "</script><img src=x onerror=alert(1)>/Users/unka/DevSpace")
        html = render_triage(triage(scan))
        self.assertIn("&lt;/script&gt;", html)
        self.assertNotIn("<script", html)
        self.assertNotIn("<img", html)
        self.assertIn("default-src 'none'", html)
        self.assertIn("does not judge privacy", html)

    def test_cli_writes_private_triage_files_and_rejects_ci(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            (root / ".gitignore").write_text("/.general-auditor/local/\n")
            store = LocalStore(root)
            scan = synthetic_scan()
            with store.locked():
                store.write_json("scan.json", scan)
            output = io.StringIO()
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("CI", None)
                os.environ.pop("GITHUB_ACTIONS", None)
                with redirect_stdout(output):
                    self.assertEqual(main(["triage", "--directory", str(root)]), 0)
            printed = output.getvalue()
            self.assertIn('"decisions": 6', printed)
            for value in ("unka", "ghp_", "meshrix-internal", "tenant_acme"):
                self.assertNotIn(value, printed)
            folder = root / ".general-auditor/local"
            self.assertTrue((folder / "triage.html").exists())
            self.assertTrue((folder / "triage.json").exists())
            self.assertEqual((folder / "triage.json").stat().st_mode & 0o777, 0o600)
            saved = json.loads((folder / "triage.json").read_text())
            self.assertEqual(saved["schema"], "general-auditor-local-triage")
            with patch.dict(os.environ, {"CI": "true"}):
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(main(["triage", "--directory", str(root)]), 1)


if __name__ == "__main__":
    unittest.main()
