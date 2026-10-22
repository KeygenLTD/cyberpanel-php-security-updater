import contextlib
import io
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

    def test_live_progress_prints_root_progress_and_findings(self):
        finding = {'severity': 'HIGH', 'path': '/home/site/public_html/x.php', 'score': 70}
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            s.live_progress('root_start', index=1, total=2, root='/home/site/public_html')
            s.live_progress('progress', inspected=500, root_inspected=500, findings=0)
            s.live_progress('finding', finding=finding)
            s.live_progress('root_done', root_inspected=600, findings=1)
            s.live_progress('persistence_start')
            s.live_progress('persistence_done', persistence=2)
        text = out.getvalue()
        self.assertIn('[1/2] Scanning /home/site/public_html', text)
        self.assertIn('Files checked: 500', text)
        self.assertIn('[HIGH] /home/site/public_html/x.php', text)
        self.assertIn('Done: 600 files', text)
        self.assertIn('Persistence check complete: 2 indicator(s)', text)


if __name__ == '__main__':
    unittest.main()
