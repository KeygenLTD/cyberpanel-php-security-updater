"""Real DNF/RPM integration, exclusively in an opt-in disposable container.

All package installs use a temporary RPM installroot, never the host RPM database.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import updater as u


@unittest.skipUnless(os.environ.get('LSPHP_CONTAINER_TEST') == '1'
                     and Path('/.dockerenv').exists(), 'Disposable Linux container required')
class DnfIntegration(unittest.TestCase):
    def test_real_resolve_validate_transaction_and_rpm_postcheck(self):
        import dnf
        import rpm
        with tempfile.TemporaryDirectory() as directory:
            top = Path(directory)
            build = top / 'build'
            for child in ('BUILD', 'BUILDROOT', 'RPMS', 'SOURCES', 'SPECS', 'SRPMS'):
                (build / child).mkdir(parents=True)
            def make(version, name='lsphp82'):
                spec = build / 'SPECS' / (name + '.spec')
                spec.write_text('''Name: {name}
Version: {version}
Release: 1
Summary: Test-only package
License: MIT
BuildArch: noarch
%description
Synthetic fixture for isolated RPM integration tests only.
%install
mkdir -p %{{buildroot}}/opt/lsphp-updater-test
echo {version} > %{{buildroot}}/opt/lsphp-updater-test/{name}
%files
/opt/lsphp-updater-test/{name}
'''.format(name=name, version=version))
                subprocess.check_call(['rpmbuild', '--define', '_topdir ' + str(build), '-bb', str(spec)],
                                      stdout=subprocess.DEVNULL)
                return str(next((build / 'RPMS/noarch').glob('{}-{}-*.rpm'.format(name, version))))
            old_file, new_file = make('1'), make('2')
            unrelated = make('2', 'unrelated')
            root = top / 'root'
            root.mkdir()
            subprocess.check_call(['rpm', '--root', str(root), '--initdb'])
            subprocess.check_call(['rpm', '--root', str(root), '-i', old_file])
            compare = lambda a, b: rpm.labelCompare((str(a.epoch), a.version, a.release),
                                                    (str(b.epoch), b.version, b.release))
            with dnf.Base() as base:
                base.conf.installroot = str(root)
                base.conf.cachedir = str(top / 'cache')
                base.conf.persistdir = str(top / 'persist')
                base.conf.logdir = str(top)
                base.conf.install_weak_deps = False
                base.fill_sack(load_available_repos=False)
                installed = list(base.sack.query().installed())
                new = base.add_remote_rpms([new_file])[0]
                base.package_upgrade(new)
                base.resolve(allow_erasing=False)
                preview = u.validate_transaction(installed, list(base.transaction.install_set),
                                                 list(base.transaction.remove_set), compare)
                self.assertEqual(preview[0]['name'], 'lsphp82')
                base.do_transaction()
            self.assertEqual(subprocess.check_output(['rpm', '--root', str(root), '-q',
                             '--qf', '%{VERSION}', 'lsphp82']).decode(), '2')
            with dnf.Base() as base:
                base.conf.installroot = str(root)
                base.conf.cachedir = str(top / 'cache')
                base.conf.persistdir = str(top / 'persist')
                base.conf.logdir = str(top)
                base.fill_sack(load_available_repos=False)
                installed = list(base.sack.query().installed())
                base.package_install(base.add_remote_rpms([unrelated])[0])
                base.resolve(allow_erasing=False)
                with self.assertRaises(RuntimeError):
                    u.validate_transaction(installed, list(base.transaction.install_set),
                                           list(base.transaction.remove_set), compare)


if __name__ == '__main__':
    unittest.main()
