"""Private, repository-rooted local audit files. No arbitrary output paths."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import stat
import subprocess
import uuid

NAMES = frozenset({'scan.json', 'history.json', 'index.html', 'review-request.json',
                   'review-handoff.json', 'review-receipt.json', 'receipt-history.json', 'review.json', 'review.html'})


class LocalStore:
    def __init__(self, directory):
        result = subprocess.run(['git', '-C', str(directory), 'rev-parse', '--show-toplevel'],
                                capture_output=True, text=True)
        if result.returncode:
            raise ValueError('Local reports require a Git working tree')
        self.root = Path(result.stdout.strip()).resolve()
        tracked = subprocess.run(['git', '-C', str(self.root), 'ls-files', '-z', '--', '.general-auditor/local'], capture_output=True)
        if tracked.returncode or tracked.stdout:
            raise ValueError('Local report files are tracked; remove them from the Git index without deleting local data')
        paths = ['.general-auditor/local/', '.general-auditor/local/.lock'] + [
            '.general-auditor/local/' + name for name in sorted(NAMES)]
        ignored = subprocess.run(['git', '-C', str(self.root), 'check-ignore', '--no-index', '-z', '--stdin'],
                                 input=('\0'.join(paths) + '\0').encode(), capture_output=True)
        if ignored.returncode or set(ignored.stdout.decode().split('\0')) - {''} != set(paths):
            raise ValueError('The fixed local report directory must be ignored by Git')
        with self._directory():
            pass


    @contextmanager
    def _directory(self):
        if not hasattr(os, 'O_NOFOLLOW') or os.open not in os.supports_dir_fd:
            raise ValueError('Safe local report storage requires descriptor-relative filesystem support')
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        descriptors = [os.open(self.root, flags)]
        try:
            for component in ('.general-auditor', 'local'):
                try:
                    os.mkdir(component, 0o700, dir_fd=descriptors[-1])
                except FileExistsError:
                    pass
                descriptor = os.open(component, flags, dir_fd=descriptors[-1])
                descriptors.append(descriptor)
                if os.fstat(descriptor).st_uid != os.getuid():
                    raise ValueError('Local report directory is not owned by the current user')
                os.fchmod(descriptor, 0o700)
            yield descriptors[-1]
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)

    @contextmanager
    def locked(self):
        """Serialize local history updates; no timeout can discard an audit."""
        import fcntl
        with self._directory() as directory:
            descriptor = os.open('.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            try:
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_uid != os.getuid():
                    raise ValueError('Unsafe local report lock')
                os.fchmod(descriptor, 0o600)
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                yield self
            finally:
                os.close(descriptor)

    def _name(self, name):
        if name not in NAMES:
            raise ValueError('Unsupported local report filename')
        return name

    def read_json(self, name, default=None):
        name = self._name(name)
        with self._directory() as directory:
            try:
                descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
            except FileNotFoundError:
                return default
            with os.fdopen(descriptor, 'r', encoding='utf-8') as stream:
                metadata = os.fstat(stream.fileno())
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_uid != os.getuid():
                    raise ValueError('Unsafe local report file')
                os.fchmod(stream.fileno(), 0o600)
                return json.load(stream)

    def write_text(self, name, content):
        name = self._name(name)
        with self._directory() as directory:
            try:
                metadata = os.stat(name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                metadata = None
            if metadata and (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_uid != os.getuid()):
                raise ValueError('Unsafe local report destination')
            temporary = '.write-' + uuid.uuid4().hex
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            try:
                with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
                    os.fchmod(stream.fileno(), 0o600)
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
                os.fsync(directory)
            finally:
                try:
                    os.unlink(temporary, dir_fd=directory)
                except FileNotFoundError:
                    pass

    def write_json(self, name, value):
        self.write_text(name, json.dumps(value, ensure_ascii=True, indent=2, allow_nan=False) + '\n')


def save_scan(root, scan):
    """Persist the exact local scan and all retained local history, never stdout."""
    from .report import render
    if scan.get('source_mode') != 'local_raw':
        raise ValueError('A local source-bearing scan is required')
    store = LocalStore(root)
    with store.locked():
        ledger = store.read_json('history.json', {'runs': []})
        by_id = {row['id']: row for row in ledger['runs']}
        if scan['id'] in by_id and by_id[scan['id']] != scan:
            raise ValueError('A saved scan identity cannot be replaced with different evidence')
        by_id[scan['id']] = scan
        history = {'generated_at': scan['finished_at'], 'runs': sorted(by_id.values(), key=lambda row: (row['finished_at'], row['id']), reverse=True)}
        store.write_json('history.json', history)
        store.write_json('scan.json', scan)
        store.write_text('index.html', render(history))
    return '.general-auditor/local/index.html'
