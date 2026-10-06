"""Separate private local evidence from source-free CI checks."""

import argparse
import json
import os
from pathlib import Path
import sys

from .config import initialize, load_profile
from .github import APIError
from .gitdata import GitError
from .scanner import scan


def parser():
    root = argparse.ArgumentParser(description="Common and repository-specific audits")
    commands = root.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="Initialize repository configuration and local-report ignore rule")
    init.add_argument("--repository", required=True)
    init.add_argument("--directory", default=".")
    init.add_argument("--central-profile", action="store_true")
    init.add_argument("--with-workflow", action="store_true")
    for name, help_text in (("scan", "Save exact evidence in the protected local report directory"),
                            ("check", "Run CI checks without creating reports or emitting source evidence")):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("--repository", required=True)
        command.add_argument("--directory", default=".")
        command.add_argument("--policy-root", default=str(Path(__file__).resolve().parents[1]))
        command.add_argument("--profile", help="Explicit trusted profile; never trust a PR-supplied policy")
        command.add_argument("--head", default="HEAD")
        command.add_argument("--base")
        command.add_argument("--scope", choices=["snapshot", "range", "history", "staged", "worktree"])
        command.add_argument("--event", help="GitHub event JSON for contribution context")
        command.add_argument("--trigger", default="local")
    for name in ("review-request", "review-complete"):
        command = commands.add_parser(name, help="Use the repository's protected local contextual review files")
        command.add_argument("--directory", default=".")
    return root


def _read_json(path):
    with Path(path).open(encoding="utf-8") as source:
        return json.load(source)


def _local_only():
    if any(os.environ.get(key, "").lower() not in {"", "0", "false", "no"}
           for key in ("CI", "GITHUB_ACTIONS")):
        raise ValueError("Private report commands are unavailable in CI")


def _exit_status(result):
    return 1 if result["status"] == "incomplete" else 2 if result["status"] == "policy_failure" else 0


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command in {"scan", "review-request", "review-complete"}:
            _local_only()
        if args.command == "init":
            created = initialize(args.directory, args.repository, profile_only=args.central_profile,
                                 with_workflow=args.with_workflow)
            print(json.dumps({"initialized": len(created)}))
            return 0
        if args.command in {"scan", "check"}:
            # Validate the destination before reading source into a raw local result.
            if args.command == "scan":
                from .local_store import LocalStore, save_scan
                LocalStore(args.directory)
            profile = _read_json(args.profile) if args.profile else None
            event = _read_json(args.event) if args.event else {}
            if not isinstance(event, dict):
                raise ValueError("Invalid event input")
            pull = event.get("pull_request", {})
            metadata = {}
            if not isinstance(pull, dict) or any(not isinstance(pull.get(key, {}), dict) for key in ("base", "head")):
                raise ValueError("Invalid pull request metadata")
            if pull:
                metadata.update(base_ref=pull.get("base", {}).get("ref"), head_ref=pull.get("head", {}).get("ref"))
            result = scan(args.directory, args.repository, head=args.head, base=args.base,
                          policy_root=args.policy_root, profile=profile, scope=args.scope,
                          event=metadata, trigger=args.trigger, include_source=args.command == "scan")
            if args.command == "check":
                from .governance import check_repository
                governance = check_repository(args.repository, profile if profile is not None else load_profile(args.policy_root, args.repository)[0], result.get("head"))
                result["findings"].extend(governance)
                if any(item.get("judgment") == "unverified" for item in governance):
                    result["status"] = "incomplete"
                elif governance and result["status"] == "completed":
                    result["status"] = "completed_with_warnings"
            else:
                save_scan(args.directory, result)
            print(json.dumps({"status": result["status"], "findings": len(result["findings"]),
                              "agent_review": result["agent_review"]}))
            return _exit_status(result)
        from .local_store import LocalStore
        from .review import create_review_request, render_review_template, complete_review
        from .report import render_review
        store = LocalStore(args.directory)
        with store.locked():
            source = store.read_json("scan.json", None)
            if args.command == "review-request":
                request = create_review_request(source)
                store.write_json("review-request.json", request)
                handoff = render_review_template(request)
                receipt = store.read_json("review-receipt.json", None)
                if receipt is not None and not isinstance(receipt, dict):
                    raise ValueError("Invalid existing receipt")
                if receipt is None or receipt.get("binding") != request["binding"]:
                    if receipt is not None:
                        history = store.read_json("receipt-history.json", [])
                        if not isinstance(history, list):
                            raise ValueError("Invalid receipt history")
                        if receipt not in history:
                            history.append(receipt)
                            store.write_json("receipt-history.json", history)
                    store.write_json("review-receipt.json", json.loads(handoff)["receipt_template"])
                store.write_text("review-handoff.json", handoff)
            else:
                result = complete_review(source, store.read_json("review-receipt.json", None))
                store.write_json("review.json", result)
                store.write_text("review.html", render_review(result))
        print(json.dumps({"status": "prepared" if args.command == "review-request" else "review_complete"}))
        return 0
    except (APIError, GitError, ValueError, OSError, TypeError):
        print("Audit operation could not complete. Check trusted configuration, Git access and local storage permissions; source values are withheld.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
