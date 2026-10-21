import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace as NS
import unittest

import apt_backend as backend


class FakePackage:
    def __init__(self, name='lsphp82', trusted=True):
        self.name = name
        self.installed = NS(version='1', architecture='amd64')
        self.candidate = NS(version='2', architecture='amd64', origins=[NS(trusted=trusted)])
        self.is_installed = self.is_upgradable = self.marked_upgrade = True
        self.marked_delete = self.marked_reinstall = False

    def mark_install(self, **kwargs):
        assert kwargs == dict(auto_fix=False, auto_inst=False, from_user=True)


class FakeCache(list):
    broken_count = 0

    def get_changes(self):
        return list(self)


class AptPolicy(unittest.TestCase):
    def test_upgrade(self):
        installed, incoming, preview = backend.plan(FakeCache([FakePackage()]), lambda a, b: int(a)-int(b))
        self.assertEqual(len(preview), 1)
        self.assertEqual(incoming[0].version, '2')

    def test_reject_untrusted_and_unrelated(self):
        for package in (FakePackage(trusted=False), FakePackage(name='openssl')):
            with self.assertRaises(RuntimeError):
                backend.plan(FakeCache([package]), lambda a, b: 1)

    def test_reject_removal_reinstall_downgrade(self):
        for flag in ('marked_delete', 'marked_reinstall', 'marked_upgrade'):
            package = FakePackage()
            setattr(package, flag, flag != 'marked_upgrade')
            with self.assertRaises(RuntimeError):
                backend.plan(FakeCache([package]), lambda a, b: -1)

    def test_reject_broken_dependencies(self):
        cache = FakeCache([FakePackage()])
        cache.broken_count = 1
        with self.assertRaises(RuntimeError):
            backend.plan(cache, lambda a, b: 1)


@unittest.skipUnless(os.environ.get('LSPHP_APT_CONTAINER_TEST') == '1'
                     and Path('/.dockerenv').exists(), 'Disposable Ubuntu container required')
class AptIntegration(unittest.TestCase):
    def test_signed_repository_real_upgrade_and_remove_rejection(self):
        import apt
        import apt_pkg
        with tempfile.TemporaryDirectory() as directory:
            top = Path(directory)
            top.chmod(0o755)
            repo = top / 'repo'
            repo.mkdir(mode=0o755)
            def build(version):
                package = top / ('package-' + version)
                (package / 'DEBIAN').mkdir(parents=True)
                (package / 'DEBIAN/control').write_text('Package: lsphp82\nVersion: {}\nArchitecture: all\nMaintainer: Test <test@example.invalid>\nDescription: Disposable integration fixture\n'.format(version))
                (package / 'opt/lsphp-test').mkdir(parents=True)
                (package / 'opt/lsphp-test/version').write_text(version)
                target = top / ('lsphp82_{}_all.deb'.format(version))
                subprocess.check_call(['dpkg-deb', '--build', str(package), str(target)])
                return target
            old, new = build('1'), build('2')
            subprocess.check_call(['dpkg', '-i', str(old)])
            (repo / new.name).write_bytes(new.read_bytes())
            (repo / 'Packages').write_bytes(subprocess.check_output(['dpkg-scanpackages', '.', '/dev/null'], cwd=str(repo)))
            (repo / 'Release').write_bytes(subprocess.check_output(['apt-ftparchive', 'release', '.'], cwd=str(repo)))
            home = top / 'gnupg'
            home.mkdir(mode=0o700)
            gpg = ['gpg', '--homedir', str(home), '--batch', '--passphrase', '']
            subprocess.check_call(gpg + ['--quick-gen-key', 'Fixture <test@example.invalid>', 'rsa2048', 'sign', '0'])
            key = top / 'key.gpg'
            key.write_bytes(subprocess.check_output(gpg + ['--export']))
            subprocess.check_call(gpg + ['--clearsign', '--output', str(repo / 'InRelease'), str(repo / 'Release')])
            source = Path('/etc/apt/sources.list.d/lsphp-fixture.list')
            source.write_text('deb [signed-by={}] file:{} ./\n'.format(key, repo))
            with apt_pkg.SystemLock():
                cache = apt.Cache(memonly=True)
                cache.update(raise_on_error=True)
                cache.open()
                installed, incoming, preview = backend.plan(cache, apt_pkg.version_compare)
                self.assertEqual(len(preview), 1)
                self.assertEqual(incoming[0].version, '2')
                cache.fetch_archives(allow_unauthenticated=False)
                self.assertTrue(cache.commit(allow_unauthenticated=False))
                cache.close()
            self.assertEqual(subprocess.check_output(['dpkg-query', '-W', '-f=${Version}', 'lsphp82']).decode(), '2')
            cache = apt.Cache(memonly=True)
            cache['lsphp82'].mark_delete(auto_fix=False)
            with self.assertRaises(RuntimeError):
                backend.plan(cache, apt_pkg.version_compare)
            cache.close()


if __name__ == '__main__':
    unittest.main()
