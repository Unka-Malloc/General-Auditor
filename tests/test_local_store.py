"""Synthetic-only private storage and retained-history contracts."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from general_auditor.local_store import LocalStore, save_scan


class LocalStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        (self.root / '.gitignore').write_text('/.general-auditor/local/\n')

    def test_exact_private_roundtrip_and_failed_replace_preserves_prior_file(self):
        store = LocalStore(self.root)
        original = {'source': 'Synthetic 原文 </script>\n', 'file': 'src/\udcff.txt'}
        store.write_json('scan.json', original)
        self.assertEqual(store.read_json('scan.json'), original)
        with patch('general_auditor.local_store.os.replace', side_effect=OSError('synthetic failure')):
            with self.assertRaises(OSError):
                store.write_json('scan.json', {'other': True})
        self.assertEqual(store.read_json('scan.json'), original)
        folder = self.root / '.general-auditor/local'
        self.assertEqual(folder.stat().st_mode & 0o777, 0o700)
        self.assertEqual((folder / 'scan.json').stat().st_mode & 0o777, 0o600)
        self.assertFalse(list(folder.glob('.write-*')))
        with self.assertRaises(ValueError):
            store.write_text('../escape', 'forbidden')

    def test_symlink_and_hardlink_destinations_cannot_escape(self):
        store = LocalStore(self.root)
        outside = self.root / 'preserved'; outside.write_text('unchanged')
        dest = self.root / '.general-auditor/local/scan.json'
        dest.symlink_to(outside)
        with self.assertRaises(ValueError): store.write_json('scan.json', {})
        with self.assertRaises(OSError): store.read_json('scan.json')
        dest.unlink(); os.link(outside, dest)
        with self.assertRaises(ValueError): store.write_json('scan.json', {})
        with self.assertRaises(ValueError): store.read_json('scan.json')
        self.assertEqual(outside.read_text(), 'unchanged')

    def test_unsafe_directory_rejected_during_construction(self):
        outside = self.root / 'outside'; outside.mkdir()
        (self.root / '.general-auditor').symlink_to(outside, target_is_directory=True)
        with self.assertRaises((OSError, ValueError)): LocalStore(self.root)
        self.assertFalse((outside / 'local').exists())

    def test_ignore_required_and_tracked_data_preserved(self):
        (self.root / '.gitignore').write_text('')
        with self.assertRaises(ValueError): LocalStore(self.root)
        (self.root / '.gitignore').write_text('/.general-auditor/local/\n')
        store = LocalStore(self.root); store.write_json('scan.json', {'preserved': True})
        subprocess.run(['git', '-C', str(self.root), 'add', '-f', '.general-auditor/local/scan.json'], check=True)
        with self.assertRaises(ValueError): LocalStore(self.root)
        self.assertTrue((self.root / '.general-auditor/local/scan.json').exists())

    def test_individually_ignored_files_do_not_protect_temporary_data(self):
        from general_auditor.local_store import NAMES
        (self.root / ".gitignore").write_text("".join("/.general-auditor/local/" + name + "\n" for name in NAMES))
        with self.assertRaises(ValueError): LocalStore(self.root)

    def test_history_retains_old_runs_and_rejects_identity_replacement(self):
        from tests.test_report_rendering import fixture
        scans = fixture(1)['runs']
        for scan in scans:
            scan['source_mode'] = 'local_raw'
            save_scan(self.root, scan)
        store = LocalStore(self.root)
        self.assertEqual(len(store.read_json('history.json')['runs']), 2)
        self.assertEqual(store.read_json('scan.json'), scans[-1])
        changed = {**scans[-1], 'status': 'incomplete'}
        with self.assertRaises(ValueError): save_scan(self.root, changed)
        self.assertEqual(store.read_json('scan.json'), scans[-1])
        with self.assertRaises(ValueError): save_scan(self.root, {**changed, 'source_mode': 'source_free'})
