from contextlib import redirect_stderr
import datetime as dt
import io
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from urllib.error import URLError

import daily
import updater


class DailyMaintenanceTests(unittest.TestCase):
    def test_operator_snapshot_is_explicit_and_reported_as_unverified(self):
        import json

        path = MagicMock()
        path.is_symlink.return_value = False
        path.stat.return_value = SimpleNamespace(st_uid=0, st_mode=0o600)
        config = {'https_urls': ['https://example.com/'], 'operator_snapshot_confirmed': True}
        path.read_text.return_value = json.dumps(config)
        self.assertEqual(daily.load_config(path), config)
        self.assertEqual(updater.apply_backup(SimpleNamespace(daily=True, **config)),
                         {'method': 'operator-confirmed-snapshot', 'verified_by_updater': False})
        path.read_text.return_value = json.dumps(dict(config, restore_tested=True))
        with self.assertRaisesRegex(RuntimeError, 'Choose either'):
            daily.load_config(path)

    def test_window_matches_utc_calendar(self):
        now = dt.datetime(2026, 11, 26, 3, 5, tzinfo=dt.timezone.utc)
        self.assertEqual(daily.maintenance_window(now),
                         ('2026-11-26T03:00:00Z', '2026-11-26T04:00:00Z'))

    def test_https_checks_all_sites_before_reporting_failure(self):
        urls = ['https://failed.example/', 'https://healthy.example/']
        opener = MagicMock()
        response = MagicMock()
        response.__enter__.return_value.getcode.return_value = 200
        opener.open.side_effect = [URLError('unreachable'), response]
        results = []
        with patch('daily.build_opener', return_value=opener):
            with self.assertRaisesRegex(RuntimeError, 'failed.example'):
                daily.check_sites(urls, results)
        self.assertIn('error', results[0])
        self.assertEqual(results[1], {'url': urls[1], 'status': 200})

    def test_daily_health_failure_blocks_package_backend(self):
        args = SimpleNamespace(daily=True, health_urls=['https://example.com/'])
        report = {}
        with patch('updater.preflight'), patch('daily.check_sites',
                side_effect=RuntimeError('HTTPS health check failed')):
            with self.assertRaisesRegex(RuntimeError, 'HTTPS health check failed'):
                updater.execute(args, report)
        self.assertNotIn('backend', report)

    def test_daily_postflight_checks_https_after_package_change(self):
        args = SimpleNamespace(daily=True, terminate_stale=False)
        report = {'transaction_completed': True, 'php_after': {}, 'warnings': []}
        with patch('updater.daily_health') as check, patch('updater.processes', return_value=[]), \
                patch('site_audit.audit_sites', return_value=[]), patch('updater.run', return_value='active'):
            updater.postflight(args, report)
        check.assert_called_once_with(args, report, 'after')

    def test_daily_rejects_manual_security_scan(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as result:
            updater.main(['--daily', '--security-scan'])
        self.assertEqual(result.exception.code, 2)


if __name__ == '__main__':
    unittest.main()
