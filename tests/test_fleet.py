"""Fleet closing report contracts: one command, one file, outside version control."""
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
from general_auditor.fleet import build, discover, remedy_for, render, run, shape
from general_auditor.local_store import LocalStore
from general_auditor.triage import triage

from tests.test_triage import synthetic_scan


def make_repository(root: Path, organization: str, repository: str, scan: dict) -> Path:
    directory = root / organization / repository
    directory.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(directory)], check=True)
    (directory / ".gitignore").write_text("/.general-auditor/local/\n")
    store = LocalStore(directory)
    with store.locked():
        store.write_json("scan.json", scan)
    return directory


class FleetDiscoveryTests(unittest.TestCase):
    def test_only_repositories_with_a_saved_scan_are_discovered(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            make_repository(root, "SymPolicy", "Styio", synthetic_scan("SymPolicy/Styio"))
            make_repository(root, "LicoLand", "LicoArc", synthetic_scan("LicoLand/LicoArc"))
            (root / "SymPolicy" / "NoScan").mkdir()
            found = discover(str(root))
            self.assertEqual([entry["repository"] for entry in found], ["LicoLand/LicoArc", "SymPolicy/Styio"])


class FleetShapeTests(unittest.TestCase):
    def test_shapes_separate_code_from_data(self):
        self.assertEqual(shape("tenant_id"), "identifier")
        self.assertEqual(shape("config.endpoint"), "dotted-code-name")
        self.assertEqual(shape("https://example.com/x"), "url")
        self.assertEqual(shape("api.vendor.com"), "host")
        self.assertEqual(shape("/Users/unka/project"), "home-path")
        self.assertEqual(shape("/var/folders/zd/x/T/y"), "machine-temp")
        self.assertEqual(shape("/home/app/.cache"), "path")
        self.assertEqual(shape("/usr/share/app/templates"), "path")

    def test_remedy_follows_the_dominant_shape(self):
        self.assertEqual(remedy_for("privacy.backend.metadata", {"identifier": 9, "expression": 1})[0], "DETECTOR-FIX")
        self.assertEqual(remedy_for("privacy.endpoint.private-host", {"dotted-code-name": 8, "host": 2})[0], "DETECTOR-FIX")
        self.assertEqual(remedy_for("privacy.credential.binding", {"identifier": 6, "other": 4})[0], "DETECTOR-FIX")
        self.assertEqual(remedy_for("privacy.local.machine-path", {"home-path": 3})[0], "REAL-FIX")
        self.assertEqual(remedy_for("privacy.endpoint.private-host", {"host": 8, "identifier": 2})[0], "EXACT-EXCEPTION")
        self.assertEqual(remedy_for("privacy.personal.identifier", {"digits": 5, "other": 5})[0], "DECIDE")


class FleetReportTests(unittest.TestCase):
    def aggregate(self):
        reports = {}
        for repository in ("SymPolicy/Styio", "LicoLand/LicoArc"):
            reports[repository] = triage(synthetic_scan(repository))
        return build(reports)

    def test_aggregate_keeps_every_project_and_ranks_rules(self):
        result = self.aggregate()
        self.assertEqual(result["schema"], "general-auditor-fleet-report")
        self.assertEqual(result["totals"]["findings"], 42)
        self.assertEqual([project["repository"] for project in result["projects"]],
                         ["LicoLand/LicoArc", "SymPolicy/Styio"])  # ranked by decision volume
        home = [rule for rule in result["remedies"] if rule["rule"] == "privacy.local.machine-path"]
        self.assertEqual(len(home), 1)
        self.assertEqual(home[0]["remedy"], "REAL-FIX")
        self.assertEqual(home[0]["repositories"], 2)
        groups = {group["rule"]: group for group in result["projects"][0]["groups"]}
        self.assertIn("privacy.local.machine-path", groups)
        self.assertTrue(all(set(row) == {"n", "m", "f", "l", "s"} for row in groups["privacy.local.machine-path"]["rows"]))

    def test_report_is_one_unredacted_sidebar_page(self):
        page = render(self.aggregate())
        self.assertEqual(page.count("<!doctype html>"), 1)
        for anchor in ('id="nav"', 'id="panel"', 'id="fleet-data"', 'id="projectfilter"', 'id="rowfilter"'):
            self.assertIn(anchor, page)
        self.assertIn("SymPolicy/Styio", page)
        self.assertIn("/Users/unka/DevSpace/project", page)
        self.assertNotIn("withheld", page)
        self.assertNotIn("contenteditable", page)

    def test_run_writes_every_repository_and_one_closing_report(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            make_repository(root, "SymPolicy", "Styio", synthetic_scan("SymPolicy/Styio"))
            make_repository(root, "LicoLand", "LicoArc", synthetic_scan("LicoLand/LicoArc"))
            output = io.StringIO()
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("CI", None)
                os.environ.pop("GITHUB_ACTIONS", None)
                with redirect_stdout(output):
                    self.assertEqual(main(["fleet", "--root", str(root)]), 0)
            summary = json.loads(output.getvalue())
            self.assertEqual(summary["repositories"], 2)
            self.assertEqual(summary["findings"], 42)
            self.assertTrue(Path(summary["report"]).exists())
            self.assertEqual(summary["report"], str(root / "fleet-report.html"))
            for repository in ("SymPolicy/Styio", "LicoLand/LicoArc"):
                local = root / repository / ".general-auditor/local"
                self.assertTrue((local / "triage.json").exists())
                self.assertTrue((local / "triage.html").exists())

    def test_report_refuses_to_land_inside_a_worktree_or_in_ci(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            make_repository(root, "SymPolicy", "Styio", synthetic_scan("SymPolicy/Styio"))
            inside = root / "SymPolicy" / "Styio" / "fleet-report.html"
            with self.assertRaises(ValueError):
                run(str(root), str(inside))
            with patch.dict(os.environ, {"CI": "true"}):
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(main(["fleet", "--root", str(root)]), 1)

    def test_empty_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError):
                run(temp)


if __name__ == "__main__":
    unittest.main()
