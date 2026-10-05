"""CLI entry points; advisory matches never cause a failing exit status."""

import argparse
import json
from pathlib import Path
import sys

from .config import initialize
from .github import APIError, GitHub
from .gitdata import GitError
from .report import read_json, render, write_json, write_text
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
    scan_parser = commands.add_parser("scan", help="Read committed Git content; findings are advisory")
    scan_parser.add_argument("--repository", required=True)
    scan_parser.add_argument("--directory", default=".")
    scan_parser.add_argument("--policy-root", default=".")
    scan_parser.add_argument("--profile", help="Explicit local profile; never auto-trust a PR-supplied policy")
    scan_parser.add_argument("--head", default="HEAD")
    scan_parser.add_argument("--base")
    scan_parser.add_argument("--output", required=True)
    scan_parser.add_argument("--html", help="Optional local HTML report; never published automatically")
    scan_parser.add_argument("--visibility", choices=["private", "public"], default="private")
    batch = commands.add_parser("batch", help="Explicitly audit one public repository or all configured organizations")
    batch.add_argument("--repository", required=True, help="owner/repository or all")
    batch.add_argument("--root", default=".")
    watch = commands.add_parser("watch", help="Audit only changed public branch/PR heads and expire old reports")
    watch.add_argument("--root", default=".")
    discover = commands.add_parser("discover", help="Initialize missing central profiles for all public repositories")
    discover.add_argument("--root", default=".")
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
            result = scan(args.directory, args.repository, head=args.head, base=args.base, policy_root=args.policy_root,
                          profile=profile, visibility=args.visibility)
            write_json(args.output, result)
            if args.html:
                write_text(args.html, render({"runs": [result], "generated_at": result["finished_at"]}, local=True))
            print(json.dumps({"status": result["status"], "warnings": len(result["findings"]), "agent_review": result["agent_review"]}))
            return 0
        elif args.command in {"batch", "watch"}:
            result = run(args.root, repository=getattr(args, "repository", None), watch=args.command == "watch")
        else:
            inventory = GitHub().repositories()
            created = []
            for row in inventory:
                created.extend(initialize(args.root, row["repository"], profile_only=True))
            write_json(Path(args.root) / "reports/inventory.json", {"schema_version": 1, "repositories": inventory})
            result = {"repositories": len(inventory), "initialized": len(created)}
        print(json.dumps(result))
        return 1 if result.get("incomplete") else 0
    except (APIError, GitError, ValueError, OSError):
        print("Audit operation could not complete. Check configuration, Git availability and GitHub access; source values are withheld.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
