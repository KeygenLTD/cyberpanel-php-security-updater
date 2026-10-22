import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import site_audit as s


class SiteAudit(unittest.TestCase):
    def test_baselines_and_eol_are_not_exploit_claims(self):
        self.assertEqual(s.assessment('8.1.34'), 'eol-vendor-patch-evidence-required')
        self.assertIn('below-upstream', s.assessment('8.2.34'))
        self.assertIn('runtime-unverified', s.assessment('8.2.35'))
        self.assertEqual(s.assessment(None), 'unknown-version')
        self.assertEqual(s.assessment('8.6.0'), 'unknown-advisory-coverage')

    def test_comments_and_server_root(self):
        text = '# extprocessor fake { path /bad }\nextprocessor actual {\n path $SERVER_ROOT/lsphp83/bin/lsphp\n extUser alice\n}\n'
        self.assertEqual(s.processors(text), {'actual': ('/usr/local/lsws/lsphp83/bin/lsphp', 'alice')})

    @unittest.skipIf(os.name == 'nt', 'pwd is a POSIX module')
    def test_site_and_worker_uid_correlation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vhost = root / 'vhosts/example.invalid'
            vhost.mkdir(parents=True)
            (vhost / 'vhost.conf').write_text('scripthandler {\n add lsapi:app php\n}\nextprocessor app {\n path /usr/local/lsws/lsphp83/bin/lsphp\n extUser alice\n}\n')
            binary = '/usr/local/lsws/lsphp83/bin/lsphp'
            workers = [dict(pid=1, uid=42, binary=binary, deleted=True),
                       dict(pid=2, uid=99, binary=binary, deleted=True)]
            with patch('pwd.getpwnam', return_value=SimpleNamespace(pw_uid=42)):
                result = s.audit_sites({binary: '8.3.36'}, workers, root)
            self.assertEqual(result[0]['site'], 'example.invalid')
            self.assertEqual(result[0]['handlers'][0]['stale_pids'], [1])


if __name__ == '__main__':
    unittest.main()
