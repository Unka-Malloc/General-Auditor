"""Read Git objects without checking out or executing target content."""

from contextlib import contextmanager
import os
from pathlib import Path
import re
import subprocess
import tempfile

from .config import repository_name


SHA = re.compile(r"[0-9a-f]{40}\Z")
MAX_TEXT_BYTES = 2 * 1024 * 1024


class GitError(RuntimeError):
    pass


def git_environment():
    # Do not inherit injected Git config, credentials or workstation hooks.
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_") and k not in {"GH_TOKEN", "GITHUB_TOKEN"}}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0", GIT_LFS_SKIP_SMUDGE="1")
    return env


def git(root, *args, check=True):
    result = subprocess.run(["git", "-c", "core.hooksPath=" + os.devnull, "-C", str(root), *args],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=git_environment())
    if check and result.returncode:
        raise GitError("Git object operation failed; target output is withheld")
    return result


def commit(root, revision):
    # --end-of-options prevents a CLI revision from becoming a Git option.
    value = git(root, "rev-parse", "--verify", "--end-of-options", revision + "^{commit}").stdout.decode().strip()
    if not SHA.fullmatch(value):
        raise GitError("Commit identity is invalid")
    return value


@contextmanager
def public_repository(repository, jobs):
    repository_name(repository)
    revisions = sorted({revision for job in jobs for revision in (job["head"], job["base"]) if revision})
    if not revisions or any(not SHA.fullmatch(revision) for revision in revisions):
        raise GitError("Expected immutable commit identities")
    with tempfile.TemporaryDirectory(prefix="general-auditor-") as directory:
        git(directory, "init", "--bare", "--quiet")
        git(directory, "remote", "add", "origin", "https://github.com/" + repository + ".git")
        # One object store and one negotiation for all selected refs in this repository.
        # Ranges require complete ancestry; pure snapshots need only their trees.
        depth = [] if any(job["base"] for job in jobs) else ["--depth=1"]
        git(directory, "fetch", "--quiet", "--no-tags", *depth, "origin", *revisions)
        yield Path(directory)


def tree(root, revision):
    for record in git(root, "ls-tree", "-r", "-z", "-l", revision).stdout.split(b"\0"):
        if not record:
            continue
        metadata, path = record.split(b"\t", 1)
        mode, kind, oid, size = metadata.split()
        yield (path.decode("utf-8", "replace"), mode.decode(), kind.decode(), oid.decode(),
               int(size) if size != b"-" else 0)


class BlobReader:
    """One Git process per scan, with at most one file in memory."""

    def __init__(self, root):
        self.process = subprocess.Popen(["git", "-C", str(root), "cat-file", "--batch"],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, env=git_environment())

    def read(self, oid):
        self.process.stdin.write(oid.encode() + b"\n")
        self.process.stdin.flush()
        header = self.process.stdout.readline().split()
        if len(header) != 3 or header[1] != b"blob":
            raise GitError("Git blob is unavailable")
        size = int(header[2])
        data = self.process.stdout.read(size)
        ending = self.process.stdout.read(1)
        if len(data) != size or ending != b"\n":
            raise GitError("Git blob read was incomplete")
        return data

    def close(self):
        self.process.stdin.close()
        self.process.stdout.close()
        if self.process.wait():
            raise GitError("Git blob reader failed")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
