"""Deterministic contracts for local, scan-bound contextual reviews."""

from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile
import subprocess
import unittest

from general_auditor.review import (
    REVIEW_TOPICS,
    complete_review,
    create_review_request,
    render_review_template,
    validate_review,
    write_local_receipt,
)


def synthetic_scan():
    return {
        "id": "scan-identity-a1",
        "repository": "SymPolicy/Synthetic",
        "visibility": "public",
        "head": "d" * 40,
        "base": "b" * 40,
        "scope": "commit-range",
        "profile_source": "central",
        "status": "completed_with_warnings",
        "agent_review": "not_performed",
        "rule_ids": ["privacy.credential-binding", "privacy.ip-address"],
        "local_review": [
            "Assess resource ownership, data lifecycle, and dependency usage.",
            "Review repository-specific publishing boundaries.",
        ],
        "semantic_review": [
            {
                "id": "detector-endpoint-context",
                "title": "Endpoint ownership context",
                "prompt": "Confirm whether endpoint candidates are public examples or deployments.",
            },
        ],
        "findings": [
            {
                "file": "src/config.txt",
                "line": 7,
                "column": 3,
                "commit": "a" * 40,
                "rule": "privacy.credential-binding",
                "category": "Credentials",
                "severity": "warning",
                "evidence": "[source value withheld] Literal credential assignment",
                "judgment": "unreviewed",
                "basis": "Pattern match only; source context requires local Agent or maintainer review.",
                "impact": "Potential exposure if confirmed.",
                "action": "Review locally.",
                # A producer-only field must not leak into the local request or receipt.
                "raw_value": "synthetic value that must stay out of the packet",
            },
            {
                "file": "notes/design.txt",
                "line": 2,
                "commit": "c" * 40,
                "rule": "privacy.ip-address",
                "category": "Network information",
                "severity": "warning",
                "evidence": "[source value withheld] Address literal",
                "judgment": "unreviewed",
                "basis": "Pattern match only; address ownership requires context.",
                "impact": "Potential private endpoint disclosure if confirmed.",
                "action": "Review locally.",
            },
        ],
        "coverage": {
            "commits": 3,
            "commit_ids": ["a" * 40, "c" * 40, "d" * 40],
            "text_versions": 4,
            "bytes": 220,
            "excluded": [],
        },
        "local_review_files": [
            {"path": "src/config.txt", "commits": ["a" * 40], "states": {"text": 1}},
            {"path": "notes/design.txt", "commits": ["c" * 40], "states": {"text": 1}},
        ],
        # Local checkout information must never be copied to a prompt or receipt.
        "diagnostics": {"private_runtime_value": "synthetic internal diagnostic"},
    }


def valid_receipt(scan):
    request = create_review_request(scan)
    return {
        "schema": "general-auditor-local-review-receipt",
        "binding": request["binding"],
        "summary": "Reviewed the selected source scope and recorded contextual outcomes.",
        "finding_reviews": [
            {
                "index": finding["index"],
                "identity": finding["identity"],
                "verdict": "false_positive",
                "basis": "The surrounding implementation identifies this as a synthetic fixture.",
                "impact": "No protected value is established by this signal.",
                "action": "Keep the fixture and retain this judgment for this scan only.",
            }
            for finding in request["findings"]
        ],
        "semantic_reviews": [
            {
                "id": task["id"],
                "conclusion": "No additional issue was established in this review area.",
                "evidence": "Reviewed the selected repository commits and relevant implementation context.",
            }
            for task in request["tasks"]
        ],
        "additional_findings": [],
        "limitations": [],
    }


class ReviewRequestTests(unittest.TestCase):
    def test_request_covers_lico_topics_detector_tasks_and_profile_obligations(self):
        scan = synthetic_scan()
        request = create_review_request(scan)
        task_ids = [item["id"] for item in request["tasks"]]
        self.assertEqual(len(REVIEW_TOPICS), 8)
        self.assertEqual(task_ids[:8], [item["id"] for item in REVIEW_TOPICS])
        self.assertIn("detector-endpoint-context", task_ids)
        self.assertIn("profile:SymPolicy-Synthetic:0", task_ids)
        self.assertIn("profile:SymPolicy-Synthetic:1", task_ids)
        self.assertEqual(len(request["findings"]), 2)
        self.assertEqual(len(request["files"]), 2)
        rendered = render_review_template(request)
        packet = json.loads(rendered)
        self.assertEqual(packet["schema"], "general-auditor-review-handoff")
        self.assertIn('"finding_reviews"', rendered)
        self.assertIn('"semantic_reviews"', rendered)
        self.assertNotIn("raw_value", rendered)
        self.assertNotIn("synthetic value that must stay out", rendered)
        self.assertNotIn("private_runtime_value", rendered)
        self.assertNotIn("/Users/", rendered)

    def test_structural_directory_location_binds_without_accepting_escapes(self):
        def structural_scan(path):
            scan = synthetic_scan()
            scan["findings"].append({
                "file": path,
                "line": None,
                "commit": "d" * 40,
                "rule": "repository.documentation-required-section",
                "category": "Documentation governance",
                "severity": "warning",
                "evidence": "A required formal documentation section has no tracked Markdown file.",
                "judgment": "unreviewed",
                "basis": "Pattern match only; source context requires local Agent or maintainer review.",
                "impact": "A declared documentation contract may be missing.",
                "action": "Review locally.",
            })
            return scan

        scan = structural_scan("docs/specs/")
        request = create_review_request(scan)
        identity = [item["identity"] for item in request["findings"]
                    if item["identity"]["file"] == "docs/specs/"]
        self.assertEqual(len(identity), 1)
        self.assertIsNone(identity[0]["line"])
        complete_review(scan, valid_receipt(scan))

        for rejected in ("/etc/passwd", "docs/../outside/", "docs/./specs/",
                         "docs\\specs", "docs//specs", "docs/specs//", ""):
            with self.assertRaises(ValueError):
                create_review_request(structural_scan(rejected))

    def test_duplicate_or_malformed_semantic_tasks_are_rejected(self):
        scan = synthetic_scan()
        scan["semantic_review"].append(dict(scan["semantic_review"][0]))
        with self.assertRaises(ValueError):
            create_review_request(scan)
        scan = synthetic_scan()
        scan["semantic_review"] = [{"id": "x", "title": "Incomplete"}]
        with self.assertRaises(ValueError):
            create_review_request(scan)


class ReviewReceiptTests(unittest.TestCase):
    def test_complete_review_is_local_only_and_does_not_change_ci_verdict(self):
        scan = synthetic_scan()
        review = valid_receipt(scan)
        review["finding_reviews"][0]["verdict"] = "uncertain"
        review["additional_findings"] = [
            {
                "path": "src/extra.txt",
                "line": 4,
                "commit": "a" * 40,
                "category": "Runtime data",
                "rule": "context.user-record",
                "verdict": "confirmed",
                "basis": "The selected context establishes an actual nonpublic record.",
                "impact": "The record would expose protected user data.",
                "action": "Remove the record and keep synthetic test data only.",
            }
        ]
        before = deepcopy(scan)

        completed = complete_review(scan, review)

        self.assertEqual(scan, before)
        self.assertEqual(completed["schema"], "general-auditor-local-review-report")
        self.assertEqual(completed["publication"], "local_only")
        self.assertEqual(completed["scan"]["agent_review"], "not_performed")
        self.assertEqual(completed["contextual_review"]["identity_attested"], False)
        self.assertEqual(completed["contextual_review"]["receipt_status"], "complete")
        self.assertEqual(completed["contextual_review"]["disposition"], "action_required")
        self.assertEqual(completed["contextual_review"]["counts"]["confirmed"], 1)
        self.assertEqual(completed["contextual_review"]["counts"]["uncertain"], 1)
        self.assertEqual(completed["contextual_review"]["counts"]["false_positive"], 1)
        self.assertEqual(scan["findings"][0]["judgment"], "unreviewed")
        # The synthetic producer-only field is never copied into the review data.
        self.assertNotIn("raw_value", json.dumps(completed["contextual_review"]))
        self.assertNotIn("private_runtime_value", json.dumps(completed))

    def test_receipt_must_match_exact_scan_scope_and_finding_identity(self):
        scan = synthetic_scan()
        review = valid_receipt(scan)
        validate_review(scan, review)

        for field, changed in (
            ("id", "scan-identity-b2"),
            ("head", "f" * 40),
            ("base", "e" * 40),
            ("scope", "snapshot"),
            ("profile_source", "different-profile"),
            ("status", "incomplete"),
            ("rule_ids", ["different-rule"]),
        ):
            with self.subTest(field=field):
                other_scan = deepcopy(scan)
                other_scan[field] = changed
                with self.assertRaises(ValueError):
                    validate_review(other_scan, review)

        changed = deepcopy(review)
        changed["finding_reviews"][0]["identity"]["file"] = "different.txt"
        with self.assertRaises(ValueError):
            validate_review(scan, changed)

    def test_all_findings_and_all_tasks_must_be_reviewed_exactly_once(self):
        scan = synthetic_scan()
        review = valid_receipt(scan)
        invalid = []
        missing_finding = deepcopy(review)
        missing_finding["finding_reviews"].pop()
        invalid.append(missing_finding)
        duplicate_finding = deepcopy(review)
        duplicate_finding["finding_reviews"].append(deepcopy(duplicate_finding["finding_reviews"][0]))
        invalid.append(duplicate_finding)
        missing_task = deepcopy(review)
        missing_task["semantic_reviews"].pop()
        invalid.append(missing_task)
        duplicate_task = deepcopy(review)
        duplicate_task["semantic_reviews"].append(deepcopy(duplicate_task["semantic_reviews"][0]))
        invalid.append(duplicate_task)
        pending = deepcopy(review)
        pending["finding_reviews"][0]["verdict"] = "pending"
        invalid.append(pending)
        for item in invalid:
            with self.subTest(receipt=item), self.assertRaises(ValueError):
                validate_review(scan, item)

    def test_profile_task_change_invalidates_existing_receipt(self):
        scan = synthetic_scan()
        receipt = valid_receipt(scan)
        changed_scan = deepcopy(scan)
        changed_scan["local_review"].append("Review a newly selected project-specific boundary.")
        with self.assertRaises(ValueError):
            validate_review(changed_scan, receipt)
        changed_scan = deepcopy(scan)
        changed_scan["local_review"][0] = "Assess changed ownership and recovery requirements."
        with self.assertRaises(ValueError):
            validate_review(changed_scan, receipt)

    def test_file_manifest_and_additions_must_remain_inside_selected_commits(self):
        scan = synthetic_scan()
        receipt = valid_receipt(scan)
        receipt["additional_findings"] = [
            {
                "path": "src/extra.txt",
                "line": 4,
                "commit": "f" * 40,
                "category": "Runtime data",
                "rule": "context.user-record",
                "verdict": "confirmed",
                "basis": "The selected context establishes an actual nonpublic record.",
                "impact": "The record would expose protected user data.",
                "action": "Remove the record and keep synthetic test data only.",
            }
        ]
        with self.assertRaises(ValueError):
            validate_review(scan, receipt)
        changed_scan = deepcopy(scan)
        changed_scan["local_review_files"][0]["commits"] = ["f" * 40]
        with self.assertRaises(ValueError):
            create_review_request(changed_scan)

    def test_uncommitted_additions_use_null_commit_only_for_local_worktree_scopes(self):
        for scope in ("staged", "worktree"):
            with self.subTest(scope=scope):
                scan = synthetic_scan()
                scan["scope"] = scope
                scan["coverage"]["commit_ids"] = []
                scan["local_review_files"] = [
                    {"path": "src/uncommitted.txt", "commits": [], "states": {scope: 1}},
                ]
                self.assertEqual(create_review_request(scan)["files"][0]["commits"], [])
                receipt = valid_receipt(scan)
                receipt["additional_findings"] = [
                    {
                        "path": "src/uncommitted.txt",
                        "line": 3,
                        "commit": None,
                        "category": "Runtime data",
                        "rule": "context.user-record",
                        "verdict": "confirmed",
                        "basis": "The selected uncommitted context establishes a nonpublic record.",
                        "impact": "The record may expose protected user information.",
                        "action": "Remove the record from the outgoing change.",
                    }
                ]
                validate_review(scan, receipt)
                completed = complete_review(scan, receipt)
                self.assertIsNone(completed["contextual_review"]["additional_findings"][0]["commit"])
                self.assertEqual(completed["contextual_review"]["binding"]["scope"], scope)

        scan = synthetic_scan()
        scan["local_review_files"][0]["commits"] = []
        with self.assertRaises(ValueError):
            create_review_request(scan)

        scan = synthetic_scan()
        receipt = valid_receipt(scan)
        receipt["additional_findings"] = [
            {
                "path": "src/uncommitted.txt",
                "line": 3,
                "commit": None,
                "category": "Runtime data",
                "rule": "context.user-record",
                "verdict": "confirmed",
                "basis": "The selected context establishes a nonpublic record.",
                "impact": "The record may expose protected user information.",
                "action": "Remove the record from the outgoing change.",
            }
        ]
        with self.assertRaises(ValueError):
            validate_review(scan, receipt)

    def test_additions_are_redacted_repository_relative_and_location_bound(self):
        scan = synthetic_scan()
        review = valid_receipt(scan)
        review["additional_findings"] = [
            {
                "path": "../private.txt",
                "line": 1,
                "category": "Data",
                "rule": "context.example",
                "verdict": "confirmed",
                "basis": "Context confirms a private record.",
                "impact": "The record is exposed.",
                "action": "Remove it.",
            }
        ]
        with self.assertRaises(ValueError):
            validate_review(scan, review)
        review["additional_findings"][0]["path"] = "src/private.txt"
        review["additional_findings"][0]["text"] = "synthetic raw source excerpt"
        with self.assertRaises(ValueError):
            validate_review(scan, review)

    def test_private_local_reasoning_preserves_original_literals(self):
        scan = synthetic_scan()
        for field, text in (
            ("summary", "Reviewed local file /Users/tester/private/config.") ,
            ("summary", "Observed a token: 'ghp_" + "A" * 32 + "'."),
        ):
            review = valid_receipt(scan)
            review[field] = text
            with self.subTest(field=field, text_kind="path" if "/Users/" in text else "token"):
                result = complete_review(scan, review)
                self.assertEqual(result["contextual_review"][field], text)

    def test_incomplete_scan_or_concrete_limitations_never_look_complete(self):
        scan = synthetic_scan()
        review = valid_receipt(scan)
        review["limitations"] = ["One selected binary could not be inspected."]
        result = complete_review(scan, review)
        self.assertEqual(result["contextual_review"]["receipt_status"], "incomplete")

        failed_scan = deepcopy(scan)
        failed_scan["status"] = "incomplete"
        review = valid_receipt(failed_scan)
        result = complete_review(failed_scan, review)
        self.assertEqual(result["contextual_review"]["receipt_status"], "incomplete")

    def test_original_evidence_identity_binds_span_context_and_version(self):
        scan = synthetic_scan()
        raw = "Synthetic 原文"
        evidence = {"kind": "literal_match", "matched_text": raw,
                    "context": {"text": "prefix " + raw, "start_line": 7, "end_line": 7},
                    "span": {"start": 7, "end": 7 + len(raw), "unit": "unicode_codepoint"},
                    "provenance": {"scope": "range", "commit": "a" * 40,
                                   "object": "e" * 40, "source_kind": "git_blob"}}
        scan["findings"][0]["source_evidence"] = evidence
        receipt = valid_receipt(scan)
        request = create_review_request(scan)
        self.assertEqual(request["findings"][0]["identity"]["source_evidence"], evidence)
        validate_review(scan, receipt)
        for field in ("span", "context", "provenance"):
            changed = deepcopy(scan)
            if field == "span":
                changed["findings"][0]["source_evidence"][field]["start"] += 1
                changed["findings"][0]["source_evidence"][field]["end"] += 1
            elif field == "context":
                changed["findings"][0]["source_evidence"][field]["text"] += " changed"
            else:
                changed["findings"][0]["source_evidence"][field]["object"] = "f" * 40
            with self.assertRaises(ValueError):
                validate_review(changed, receipt)
        receipt["finding_reviews"][0]["identity"]["source_evidence"]["context"]["text"] = "mutated"
        self.assertEqual(scan["findings"][0]["source_evidence"], evidence)

    def test_receipt_writer_uses_private_file_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run(["git", "init", "-q", directory], check=True)
            (Path(directory) / ".gitignore").write_text("/.general-auditor/local/\n")
            path = Path(directory) / ".general-auditor/local/review-receipt.json"
            scan = synthetic_scan()
            write_local_receipt(directory, scan, valid_receipt(scan))
            self.assertEqual(json.loads(path.read_text())["schema"], "general-auditor-local-review-receipt")
            if os.name == "posix":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
