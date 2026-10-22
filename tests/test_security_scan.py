import tempfile
from pathlib import Path
import unittest

import security_scan as s


class SecurityScanTests(unittest.TestCase):
    def test_known_shell_scores_critical_when_combined_with_execution(self):
        text = "<?php eval(base64_decode($_POST['x'])); system($_REQUEST['cmd']); ?>"
        score, severity, reasons = s.classify_file(Path('/home/site/public_html/uploads/phpshell2.php'), text)
        self.assertGreaterEqual(score, 80)
        self.assertEqual(severity, 'CRITICAL')
        self.assertTrue(any('shell' in reason.lower() for reason in reasons))

    def test_upload_php_without_execution_is_suspicious_not_critical(self):
        score, severity, reasons = s.classify_file(
            Path('/home/site/public_html/wp-content/uploads/2026/10/image.php'),
            "<?php echo 'hello'; ?>"
        )
        self.assertEqual(score, 30)
        self.assertEqual(severity, 'MEDIUM')
        self.assertTrue(reasons)

    def test_benign_php_has_no_score(self):
        score, severity, reasons = s.classify_file(
            Path('/home/site/public_html/index.php'),
            "<?php require __DIR__ . '/wp-blog-header.php'; ?>"
        )
        self.assertEqual(score, 0)
        self.assertEqual(severity, 'CLEAN')
        self.assertEqual(reasons, [])

    def test_non_php_extension_with_php_code_is_flagged(self):
        score, severity, reasons = s.classify_file(
            Path('/home/site/public_html/uploads/photo.jpg'),
            "<?php system($_GET['cmd']); ?>"
        )
        self.assertGreaterEqual(score, 35)
        self.assertIn('non-PHP extension', ' '.join(reasons))

    def test_quarantine_requires_matching_hash_and_writes_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / 'shell.php'
            source.write_text("<?php system($_GET['cmd']); ?>")
            digest = s.sha256_file(source)
            quarantine_root = base / 'quarantine'

            result = s.quarantine(source, digest, root=quarantine_root)

            self.assertFalse(source.exists())
            self.assertTrue(Path(result['target']).is_file())
            self.assertTrue(Path(result['manifest']).is_file())
            self.assertEqual(s.sha256_file(Path(result['target'])), digest)

    def test_quarantine_refuses_changed_file(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / 'shell.php'
            source.write_text('first')
            old_digest = s.sha256_file(source)
            source.write_text('changed')
            with self.assertRaises(RuntimeError):
                s.quarantine(source, old_digest, root=base / 'q')


if __name__ == '__main__':
    unittest.main()
