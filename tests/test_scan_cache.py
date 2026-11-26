import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import security_scan as scanner
from scan_cache import ScanCache, scan_cache


class ScanCacheTests(unittest.TestCase):
    def test_reuses_clean_and_flagged_files_without_losing_findings(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ('clean.php', 'flagged.php'):
                (root / name).write_text('sample')
            cache = ScanCache({})
            with patch.object(scanner.os, 'geteuid', return_value=0, create=True), \
                    patch.object(scanner, 'suspicious_persistence', return_value=[]), \
                    patch.object(scanner, 'classify_file', side_effect=lambda path, text:
                        (75, 'HIGH', ['test finding']) if path.name == 'flagged.php' else (0, 'CLEAN', [])) as classify:
                first = scanner.scan(roots=[root], cache=cache)
                second = scanner.scan(roots=[root], cache=cache)
                self.assertEqual(classify.call_count, 2)
                self.assertEqual(second['cached_classifications'], 2)
                self.assertEqual(second['findings'], first['findings'])

                path = root / 'flagged.php'
                previous = path.stat()
                path.write_text('edited')
                os.utime(str(path), ns=(previous.st_atime_ns, previous.st_mtime_ns))
                third = scanner.scan(roots=[root], cache=cache)
                self.assertEqual(classify.call_count, 3)
                self.assertNotEqual(third['findings'][0]['sha256'], first['findings'][0]['sha256'])

                scanner.scan(roots=[root], deep=True, cache=cache)
                self.assertEqual(classify.call_count, 5)

    @unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0, 'private cache requires root')
    def test_cache_survives_a_new_scan_and_invalidates_on_rule_change(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            path = root / 'sample.php'
            path.write_text('sample')
            directory = root / 'cache'
            with scan_cache('first', directory) as cache:
                cache.put('web', path, path.stat(), None)
            with scan_cache('first', directory) as cache:
                self.assertIsNone(cache.get('web', path, path.stat()))
                self.assertEqual(cache.hits, 1)
            with scan_cache('changed', directory) as cache:
                self.assertEqual(len(cache.entries), 0)


if __name__ == '__main__':
    unittest.main()
