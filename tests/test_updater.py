import contextlib
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import updater as u


class Package:
    def __init__(self, name='lsphp82', version='1', arch='x86_64'):
        self.name, self.version, self.arch = name, version, arch
        self.epoch, self.release = 0, '1'

    def __str__(self):
        return '{}-{}.{}'.format(self.name, self.version, self.arch)


class PolicyTests(unittest.TestCase):
    def validate(self, old, new, removed):
        return u.validate_transaction(old, new, removed,
                                      lambda a, b: int(a.version) - int(b.version))

    def test_strict_upgrade(self):
        old, new = Package(), Package(version='2')
        self.assertEqual(self.validate([old], [new], [old])[0]['name'], 'lsphp82')

    def test_no_updates(self):
        self.assertEqual(self.validate([Package()], [], []), [])

    def test_reject_downgrade_reinstall_removal_dependency_arch(self):
        old = Package(version='2')
        scenarios = [([Package()], [old]), ([old], [old]), ([], [old]),
                     ([Package('openssl', '3')], [old]),
                     ([Package(version='3', arch='aarch64')], [old]),
                     ([Package('lsphp83', '3')], []),
                     ([Package(version='3'), Package(version='4')], [old])]
        for incoming, outgoing in scenarios:
            with self.subTest(incoming=incoming), self.assertRaises(RuntimeError):
                self.validate([old], incoming, outgoing)

    @unittest.skipIf(os.name == 'nt', 'POSIX file permissions required; covered in Linux CI')
    def test_backup_digest_and_empty_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'backup'
            path.write_bytes(b'backup')
            path.chmod(0o600)
            self.assertEqual(u.backup_check(path, hashlib.sha256(b'backup').hexdigest())['size'], 6)
            with self.assertRaises(RuntimeError):
                u.backup_check(path, '0' * 64)
            path.write_bytes(b'')
            with self.assertRaises(RuntimeError):
                u.backup_check(path, '0' * 64)

    def test_window_start_inclusive_end_exclusive(self):
        now = dt.datetime(2026, 10, 22, tzinfo=dt.timezone.utc)
        u.window('2026-10-22T00:00:00Z', '2026-10-22T01:00:00Z', now)
        with self.assertRaises(RuntimeError):
            u.window('2026-10-21T00:00:00Z', '2026-10-22T00:00:00Z', now)

    def test_unsupported_os(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'os-release'
            for content in ('ID=ubuntu\nVERSION_ID=20.04', 'ID=almalinux\nVERSION_ID=7'):
                path.write_text(content)
                with self.assertRaises(RuntimeError):
                    u.platform_check(path)

    def test_supported_os_8_9_10(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'os-release'
            with patch.object(u.os, 'uname', return_value=SimpleNamespace(machine='x86_64'), create=True), \
                    patch.object(Path, 'is_dir', return_value=True), \
                    patch.object(u, 'run', return_value='LiteSpeed/1.8.3 Open'):
                for major in ('8', '9', '10'):
                    path.write_text('ID=almalinux\nVERSION_ID="{}.0"'.format(major))
                    self.assertEqual(u.platform_check(path), major)
                for release in ('22.04', '24.04'):
                    path.write_text('ID=ubuntu\nVERSION_ID="{}"'.format(release))
                    self.assertEqual(u.platform_check(path), 'ubuntu:' + release)

    def test_manual_commands_do_not_execute(self):
        report = {'backend': 'apt', 'installed': ['lsphp82:amd64=8.2.34'], 'warnings': []}
        with patch.object(u, 'run') as run:
            u.manual_commands([Package()], report)
        run.assert_not_called()
        self.assertIn('--simulate', report['manual_commands'][0])
        self.assertIn('--no-remove', report['manual_commands'][1])

    def test_proc_deleted_and_start_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pid = root / '123'
            pid.mkdir()
            (pid / 'stat').write_text('123 (a tricky ) name) ' + ' '.join(str(n) for n in range(3, 53)))
            with patch.object(u.os, 'readlink', return_value='/usr/local/lsws/lsphp81/bin/lsphp (deleted)'):
                result = u.processes(root)
            self.assertTrue(result[0]['deleted'])
            self.assertEqual(result[0]['start'], '22')

    def test_default_check_and_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix = str(Path(directory) / 'result')
            def fake(args, report):
                self.assertFalse(args.apply)
                report['preview'] = []
            with patch.object(u, 'execute', side_effect=fake), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(u.main(['--report-prefix', prefix]), 0)
            self.assertEqual(json.loads(Path(prefix + '.json').read_text())['status'], 'ok')
            self.assertIn('mode: "check"', Path(prefix + '.txt').read_text())

    def test_cli_apply_without_gates_fails_before_execution(self):
        result = subprocess.run([sys.executable, 'updater.py', '--apply'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('requires approval', result.stderr)

    def test_failure_report(self):
        with patch.object(u, 'execute', side_effect=RuntimeError('blocked')), contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(u.main([]), 2)
        self.assertEqual(json.loads(out.getvalue())['error'], 'blocked')

    def test_sigterm_only_targets_deleted_worker(self):
        stale = dict(pid=123, binary='/usr/local/lsws/lsphp82/bin/lsphp', deleted=True, start='22')
        active = dict(pid=124, binary=stale['binary'], deleted=False, start='23')
        args = u.parser().parse_args(['--window-start', '2026-10-22T00:00:00Z',
                                     '--window-end', '2026-10-22T01:00:00Z'])
        with patch.object(u, 'window'), patch.object(u, 'processes', side_effect=[[stale, active], [stale, active], []]), \
                patch.object(u.os, 'pidfd_open', return_value=9, create=True), \
                patch.object(u.os, 'close') as close, \
                patch.object(u.signal, 'pidfd_send_signal', create=True) as send:
            u.terminate_stale(args)
        send.assert_called_once_with(9, u.signal.SIGTERM)
        close.assert_called_once_with(9)

    def test_pid_reuse_skips_signal(self):
        stale = dict(pid=123, binary='/usr/local/lsws/lsphp82/bin/lsphp', deleted=True, start='22')
        reused = dict(stale, start='99')
        args = u.parser().parse_args([])
        with patch.object(u, 'window'), patch.object(u, 'processes', side_effect=[[stale], [reused], []]), \
                patch.object(u.os, 'pidfd_open', return_value=9, create=True), \
                patch.object(u.os, 'close'), \
                patch.object(u.signal, 'pidfd_send_signal', create=True) as send:
            u.terminate_stale(args)
        send.assert_not_called()

    def test_term_timeout_never_escalates(self):
        stale = dict(pid=123, binary='/usr/local/lsws/lsphp82/bin/lsphp', deleted=True, start='22')
        args = u.parser().parse_args([])
        with patch.object(u, 'window'), patch.object(u, 'processes', return_value=[stale]), \
                patch.object(u.time, 'monotonic', side_effect=[0, 61]), \
                patch.object(u.os, 'pidfd_open', return_value=9, create=True), \
                patch.object(u.os, 'close'), \
                patch.object(u.signal, 'pidfd_send_signal', create=True) as send:
            with self.assertRaisesRegex(RuntimeError, 'survived SIGTERM'):
                u.terminate_stale(args)
        send.assert_called_once_with(9, u.signal.SIGTERM)


if __name__ == '__main__':
    unittest.main()
