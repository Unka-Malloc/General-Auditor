"""Read Git objects without checking out or executing target content."""

from contextlib import contextmanager
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

from .config import repository_name


SHA = re.compile(r"[0-9a-f]{40}\Z")


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


def repository_root(directory):
    """Resolve one repository root so a nested invocation cannot narrow coverage."""
    bare = git(directory, "rev-parse", "--is-bare-repository").stdout.strip() == b"true"
    option = "--absolute-git-dir" if bare else "--show-toplevel"
    return Path(os.fsdecode(git(directory, "rev-parse", option).stdout.rstrip(b"\n")))


def unborn_head(root):
    """A symbolic HEAD whose branch does not yet exist has no baseline commit."""
    symbolic = git(root, "symbolic-ref", "--quiet", "HEAD", check=False)
    if symbolic.returncode:
        return False
    ref = symbolic.stdout.decode().strip()
    return git(root, "show-ref", "--verify", "--quiet", ref, check=False).returncode == 1


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


class ObjectSizer:
    """Read staged Git object sizes through one streaming process."""

    def __init__(self, root):
        self.process = subprocess.Popen(
            ["git", "-C", str(root), "cat-file", "--batch-check=%(objecttype) %(objectsize)"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=git_environment(),
        )

    def size(self, oid):
        self.process.stdin.write(oid.encode("ascii") + b"\n")
        self.process.stdin.flush()
        fields = self.process.stdout.readline().split()
        if len(fields) != 2 or fields[0] != b"blob":
            raise GitError("Staged Git object metadata is unavailable")
        return int(fields[1])

    def close(self):
        self.process.stdin.close()
        self.process.stdout.close()
        if self.process.wait():
            raise GitError("Git object metadata reader failed")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def index_tree(root):
    """Yield immutable stage-zero index entries without writing a tree object."""
    records = git(root, "ls-files", "--stage", "-z").stdout.split(b"\0")
    with ObjectSizer(root) as sizer:
        for record in records:
            if not record:
                continue
            metadata, raw_path = record.split(b"\t", 1)
            mode, oid, stage = metadata.split()
            if stage != b"0":
                raise GitError("The staged index contains unresolved merge entries")
            kind = "commit" if mode == b"160000" else "blob"
            size = sizer.size(oid.decode("ascii")) if kind == "blob" else 0
            yield (raw_path.decode("utf-8", "replace"), mode.decode("ascii"), kind,
                   oid.decode("ascii"), size)


def worktree_tree(root):
    """Yield tracked and non-ignored untracked regular files without following links."""
    records = git(root, "ls-files", "--cached", "--others", "--exclude-standard", "-z").stdout.split(b"\0")
    root_bytes = os.fsencode(root)
    gitlinks = {path: (mode, kind, oid, size) for path, mode, kind, oid, size in index_tree(root) if kind == "commit"}
    seen = set()
    for raw_path in records:
        if not raw_path or raw_path in seen:
            continue
        seen.add(raw_path)
        path = raw_path.decode("utf-8", "replace")
        if path in gitlinks:
            yield (path, *gitlinks[path], raw_path)
            continue
        try:
            info = os.lstat(os.path.join(root_bytes, raw_path))
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            mode, kind, size = "120000", "blob", info.st_size
        elif stat.S_ISREG(info.st_mode):
            mode = "100755" if info.st_mode & stat.S_IXUSR else "100644"
            kind, size = "blob", info.st_size
        else:
            # Gitlinks and directories are not traversed; binary/external content
            # remains an explicit scanner coverage exclusion.
            continue
        path = raw_path.decode("utf-8", "replace")
        yield (path, mode, kind, None, size, raw_path)


class BlobReader:
    """One Git process per scan, with at most one file in memory."""

    def __init__(self, root):
        self.process = subprocess.Popen(["git", "-C", str(root), "cat-file", "--batch"],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, env=git_environment())

    def read_object(self, oid):
        self.process.stdin.write(oid.encode() + b"\n")
        self.process.stdin.flush()
        header = self.process.stdout.readline().split()
        if len(header) != 3 or header[1] == b"missing":
            raise GitError("Git object is unavailable")
        size = int(header[2])
        data = self.process.stdout.read(size)
        ending = self.process.stdout.read(1)
        if len(data) != size or ending != b"\n":
            raise GitError("Git blob read was incomplete")
        return header[1].decode("ascii"), data

    def read(self, oid):
        kind, data = self.read_object(oid)
        if kind != "blob":
            raise GitError("Git blob is unavailable")
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
