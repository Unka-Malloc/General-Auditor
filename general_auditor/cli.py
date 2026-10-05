"""CLI entry points; advisory matches never cause a failing exit status."""

import argparse
import json
from pathlib import Path
import sys

from .config import initialize
from .github import APIError, GitHub
from .gitdata import GitError
from .report import read_json, render, render_review, write_json, write_text
from .runner import run
from .scanner import scan


def parser():
    root = argparse.ArgumentParser(description="Common and repository-specific advisory audits")
    commands = root.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="Initialize path-independent configuration without overwriting files")
    init.add_argument("--repository", required=True)
    init.add_argument("--directory", default=".")
    init.add_argument("--central-profile", action="store_true")
    init.add_argument("--with-workflow", action="store_true", help="Also install the optional repository-local CI template")
    scan_parser = commands.add_parser("scan", help="Read selected Git or local candidate content; privacy findings are advisory")
    scan_parser.add_argument("--repository", required=True)
    scan_parser.add_argument("--directory", default=".")
    scan_parser.add_argument("--policy-root", default=str(Path(__file__).resolve().parents[1]))
    scan_parser.add_argument("--profile", help="Explicit local profile; never auto-trust a PR-supplied policy")
    scan_parser.add_argument("--head", default="HEAD")
    scan_parser.add_argument("--base")
    scan_parser.add_argument("--scope", choices=["snapshot", "range", "history", "staged", "worktree"])
    scan_parser.add_argument("--event", help="GitHub event JSON for contribution context")
    scan_parser.add_argument("--trigger", default="local")
    scan_parser.add_argument("--output", required=True)
    scan_parser.add_argument("--html", help="Optional local HTML report; never published automatically")
    scan_parser.add_argument("--visibility", choices=["private", "public"], default="private")
    request = commands.add_parser("review-request", help="Prepare a local contextual review request")
    request.add_argument("--scan", required=True)
    request.add_argument("--output", required=True)
    request.add_argument("--template")
    complete = commands.add_parser("review-complete", help="Validate a local scan-bound review receipt")
    complete.add_argument("--scan", required=True)
    complete.add_argument("--receipt", required=True)
    complete.add_argument("--output", required=True)
    complete.add_argument("--html")
    batch = commands.add_parser("batch", help="Explicitly audit one public repository or all configured organizations")
    batch.add_argument("--repository", required=True, help="owner/repository or all")
    batch.add_argument("--root", default=".")
    watch = commands.add_parser("watch", help="Audit only changed public branch/PR heads and expire old reports")
    watch.add_argument("--root", default=".")
    discover = commands.add_parser("discover", help="Initialize missing central profiles for all public repositories")
    discover.add_argument("--root", default=".")
    for name, description in (("coordinate", "Dispatch changed repositories independently"), ("audit-repository", "Audit one repository and persist its durable result")):
        command = commands.add_parser(name, help=description)
        command.add_argument("--root", default=".")
        command.add_argument("--repository", required=True)
        command.add_argument("--force", action="store_true")
    assemble = commands.add_parser("assemble", help="Merge completed results and refresh the single report")
    assemble.add_argument("--root", default=".")
    assemble.add_argument("--event", help="GitHub workflow completion event")
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == "init":
            result = {"created": initialize(args.directory, args.repository, profile_only=args.central_profile, with_workflow=args.with_workflow)}
        elif args.command == "scan":
            profile = read_json(args.profile, None) if args.profile else None
            if args.profile and profile is None:
                raise ValueError("Explicit profile is missing")
            event = read_json(args.event, None) if args.event else {}
            if not isinstance(event, dict):
                raise ValueError("Invalid event input")
            pull = event.get("pull_request", {})
            metadata = {}
            if pull:
                metadata.update(base_ref=pull.get("base", {}).get("ref"), head_ref=pull.get("head", {}).get("ref"))
            result = scan(args.directory, args.repository, head=args.head, base=args.base, policy_root=args.policy_root,
                          profile=profile, visibility=args.visibility, scope=args.scope, event=metadata, trigger=args.trigger)
            write_json(args.output, result)
            if args.html:
                write_text(args.html, render({"runs": [result], "generated_at": result["finished_at"]}, local=True))
            print(json.dumps({"status": result["status"], "findings": len(result["findings"]), "agent_review": result["agent_review"]}))
            return 1 if result["status"] == "incomplete" else 2 if result["status"] == "policy_failure" else 0
        elif args.command in {"review-request", "review-complete"}:
            from .review import create_review_request, render_review_template, complete_review
            source = read_json(args.scan, None)
            if args.command == "review-request":
                result = create_review_request(source)
                write_json(args.output, result)
                if args.template:
                    write_text(args.template, render_review_template(result))
            else:
                receipt = read_json(args.receipt, None)
                result = complete_review(source, receipt)
                write_json(args.output, result)
                if args.html:
                    write_text(args.html, render_review(result))
            print(json.dumps({"status": "prepared" if args.command == "review-request" else "review_complete"}))
            return 0
        elif args.command in {"batch", "watch"}:
            result = run(args.root, repository=getattr(args, "repository", None), watch=args.command == "watch")
        elif args.command in {"coordinate", "audit-repository", "assemble"}:
            from .pipeline import coordinate, audit, assemble
            if args.command == "coordinate":
                result = coordinate(args.root, args.repository, force=args.force)
            elif args.command == "audit-repository":
                result = audit(args.root, args.repository, force=args.force)
            elif args.command == "assemble":
                result = assemble(args.root, event=read_json(args.event, {}) if args.event else {})
        else:
            inventory = GitHub().repositories()
            created = []
            for row in inventory:
                created.extend(initialize(args.root, row["repository"], profile_only=True))
            write_json(Path(args.root) / "reports/inventory.json", {"schema_version": 1, "repositories": inventory})
            result = {"repositories": len(inventory), "initialized": len(created)}
        print(json.dumps(result))
        return 1 if result.get("incomplete") else 2 if result.get("policy_failures") else 0
    except (APIError, GitError, ValueError, OSError):
        print("Audit operation could not complete. Check configuration, Git availability and GitHub access; source values are withheld.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
