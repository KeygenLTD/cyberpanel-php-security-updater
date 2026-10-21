#!/usr/bin/env python3
"""Conservative LSPHP update coordinator. Python 3.6+ (EL8 platform-python)."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import shutil
import subprocess
import sys
import time
import tempfile

PACKAGE = re.compile(r'^lsphp[0-9]{2,3}(?:-[A-Za-z0-9_+.-]+)?$')
BINARY = re.compile(r'^/usr/local/lsws/lsphp[0-9]{2,3}/bin/lsphp$')


def run(args):
    return subprocess.check_output(args, stderr=subprocess.STDOUT,
                                   universal_newlines=True, timeout=60).strip()


def platform_check(path=Path('/etc/os-release')):
    values = {}
    for line in path.read_text().splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            values[key] = value.strip('"\'')
    major = values.get('VERSION_ID', '').split('.')[0]
    if values.get('ID') != 'almalinux' or major not in ('8', '10'):
        raise RuntimeError('Supported OS: AlmaLinux 8 and 10 only')
    if os.uname().machine not in ('x86_64', 'aarch64'):
        raise RuntimeError('Unsupported architecture')
    if not Path('/usr/local/CyberCP').is_dir():
        raise RuntimeError('CyberPanel installation not found')
    identity = run(['/usr/local/lsws/bin/lshttpd', '-v'])
    if not ('OpenLiteSpeed' in identity or re.search(r'LiteSpeed/[\d.]+ Open\b', identity)):
        raise RuntimeError('OpenLiteSpeed identity not verified')
    return major


def processes(root=Path('/proc')):
    result = []
    for entry in root.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            target = os.readlink(str(entry / 'exe'))
            deleted = target.endswith(' (deleted)')
            binary = target[:-10] if deleted else target
            if BINARY.fullmatch(binary):
                # stat comm may contain spaces and parentheses.
                start = (entry / 'stat').read_text().rsplit(')', 1)[1].split()[19]
                result.append(dict(pid=int(entry.name), binary=binary,
                                   deleted=deleted, start=start))
        except FileNotFoundError:
            continue
        except PermissionError:
            raise RuntimeError('Cannot inspect all /proc executables; run as root')
    return sorted(result, key=lambda p: p['pid'])


def validate_transaction(installed, incoming, outgoing, compare):
    """Allow only one-for-one upgrades; reject even new lsphp dependencies."""
    old = {(p.name, p.arch): p for p in installed}
    new = {(p.name, p.arch): p for p in incoming}
    removed = {(p.name, p.arch): p for p in outgoing}
    if (len(old) != len(installed) or len(new) != len(incoming)
            or len(removed) != len(outgoing)):
        raise RuntimeError('Ambiguous multiversion packages')
    if set(new) != set(removed):
        raise RuntimeError('Unexpected install/removal/architecture change')
    for key, pkg in new.items():
        previous = old.get(key)
        if (previous is None or not PACKAGE.fullmatch(pkg.name)
                or str(previous) != str(removed[key])
                or compare(pkg, previous) <= 0):
            raise RuntimeError('Transaction is not a strict installed LSPHP upgrade')
    return [dict(name=p.name, arch=p.arch, before=str(old[k]), after=str(p))
            for k, p in sorted(new.items())]


def window(start, end, now=None):
    def parse(value):
        parsed = dt.datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ')
        return parsed.replace(tzinfo=dt.timezone.utc)
    now = now or dt.datetime.now(dt.timezone.utc)
    if not parse(start) <= now < parse(end):
        raise RuntimeError('Outside maintenance window (UTC)')


def backup_check(path, expected):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
        raise RuntimeError('Backup must be a nonempty regular file, not a symlink')
    if path.stat().st_mode & 0o022:
        raise RuntimeError('Backup must not be group/world writable')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    if digest.hexdigest() != expected.lower():
        raise RuntimeError('Backup SHA256 mismatch')
    return dict(sha256=digest.hexdigest(), size=path.stat().st_size)


def versions(packages):
    result = {}
    for name in sorted(set(re.match(r'lsphp([0-9]+)', p.name).group(1)
                           for p in packages)):
        binary = '/usr/local/lsws/lsphp{}/bin/lsphp'.format(name)
        result[binary] = run([binary, '-n', '-r', 'echo PHP_VERSION;'])
    return result


def terminate_stale(args):
    # pidfd prevents PID reuse races; fail closed on kernels/Python lacking it.
    if not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'):
        raise RuntimeError('Race-safe SIGTERM requires Python pidfd APIs; use OLS restart workflow on EL8')
    for proc in processes():
        if not proc['deleted']:
            continue
        window(args.window_start, args.window_end)
        try:
            fd = os.pidfd_open(proc['pid'])
        except ProcessLookupError:
            continue
        try:
            if proc not in processes():
                continue
            signal.pidfd_send_signal(fd, signal.SIGTERM)
        finally:
            os.close(fd)
    deadline = time.monotonic() + args.term_timeout
    while any(p['deleted'] for p in processes()):
        window(args.window_start, args.window_end)
        if time.monotonic() >= deadline:
            raise RuntimeError('Stale workers survived SIGTERM; manual investigation required')
        time.sleep(1)


def execute(args, report):
    report['os_major'] = platform_check()
    import dnf
    import rpm
    if os.geteuid() != 0:
        raise RuntimeError('Root required to inspect processes and DNF cache reliably')
    report['ols_before'] = run(['systemctl', 'is-active', 'lsws'])
    if report['ols_before'] != 'active':
        raise RuntimeError('OpenLiteSpeed is not active')
    report['processes_before'] = processes()
    if args.terminate_stale and (not hasattr(os, 'pidfd_open')
                                or not hasattr(signal, 'pidfd_send_signal')):
        raise RuntimeError('SIGTERM unavailable safely on this Python/kernel; no update performed')
    if args.terminate_stale:
        os.close(os.pidfd_open(os.getpid()))
    configs = [Path('/usr/local/lsws/conf/httpd_config.conf')]
    configs.extend(Path('/usr/local/lsws/conf/vhosts').glob('*/*.conf'))
    report['configured_php'] = sorted(set(binary for config in configs if config.is_file()
        for binary in re.findall(r'/usr/local/lsws/lsphp[0-9]{2,3}/bin/lsphp', config.read_text())))
    with dnf.Base() as base:
        base.conf.read()
        if base.conf.installroot != '/':
            raise RuntimeError('Custom DNF installroot is unsupported')
        if not args.apply:
            # DNF's cache-only API still creates metadata locks; isolate those writes.
            shutil.copytree(base.conf.cachedir, args.scratch + '/cache',
                            ignore=shutil.ignore_patterns('packages', '*.rpm', '*.pid', '*.lock'))
            base.conf.cachedir = args.scratch + '/cache'
            base.conf.persistdir = args.scratch + '/persist'
            base.conf.logdir = args.scratch
            base.conf.gpgkey_dns_verification = False
        if set(base.conf.tsflags) - {'nodocs'}:
            raise RuntimeError('Unsafe/custom DNF tsflags; refusing transaction')
        base.conf.plugins = False
        base.conf.cacheonly = not args.apply
        base.conf.logfilelevel = 0
        base.conf.debuglevel = 0
        base.conf.best = True
        base.conf.install_weak_deps = False
        base.conf.gpgcheck = True
        base.read_all_repos()
        if not list(base.repos.iter_enabled()):
            raise RuntimeError('No enabled repositories')
        for repo in base.repos.iter_enabled():
            repo.skip_if_unavailable = False
            repo.gpgcheck = True
            if args.apply:
                repo.metadata_expire = 0
        if args.apply:
            base.fill_sack()
        else:
            base.fill_sack_from_repos_in_cache()
        installed = [p for p in base.sack.query().installed() if PACKAGE.fullmatch(p.name)]
        if not installed:
            raise RuntimeError('No installed LSPHP packages')
        report['installed'] = sorted(str(p) for p in installed)
        report['php_before'] = versions(installed)
        for binary in report['configured_php'] + [p['binary'] for p in report['processes_before']]:
            if binary not in report['php_before']:
                raise RuntimeError('Configured/running PHP is not managed by discovered RPMs')
        report['warnings'] = ['Cached metadata may be stale; this is not proof that PHP is secure.']
        if any(p['deleted'] for p in report['processes_before']):
            report['warnings'].append('Deleted LSPHP executables are still running; maintenance required.')
        for binary, version in report['php_before'].items():
            if tuple(int(x) for x in version.split('.')[:2]) <= (8, 1):
                report['warnings'].append('Upstream EOL: {} = {}; vendor backports require independent verification'.format(binary, version))
        for name in sorted(set(p.name for p in installed)):
            base.upgrade(name)
        base.resolve(allow_erasing=False)
        incoming = list(base.transaction.install_set)
        outgoing = list(base.transaction.remove_set)
        compare = lambda a, b: rpm.labelCompare((str(a.epoch), a.version, a.release),
                                                (str(b.epoch), b.version, b.release))
        report['preview'] = validate_transaction(installed, incoming, outgoing, compare)
        print(json.dumps({'transaction_preview': report['preview']}, indent=2), flush=True)
        if not args.apply:
            return
        report['backup'] = backup_check(args.backup, args.backup_sha256)
        window(args.window_start, args.window_end)
        if incoming:
            base.download_packages(incoming)
            for pkg in incoming:
                code, message = base.package_signature_check(pkg)
                if code != 0:
                    raise RuntimeError('RPM signature check failed: ' + message)
            window(args.window_start, args.window_end)
            report['transaction_started'] = True
            base.do_transaction()
            report['transaction_completed'] = True
            # Compare exact expected RPM state after the transaction.
            for pkg in incoming:
                actual = run(['rpm', '-q', '--qf', '%{EPOCHNUM}:%{VERSION}-%{RELEASE}',
                              pkg.name + '.' + pkg.arch])
                if actual != '{}:{}-{}'.format(pkg.epoch, pkg.version, pkg.release):
                    raise RuntimeError('Post-transaction RPM verification failed')
        report['php_after'] = versions(installed)
    if args.terminate_stale:
        terminate_stale(args)
    report['processes_after'] = processes()
    report['ols_after'] = run(['systemctl', 'is-active', 'lsws'])
    if report['ols_after'] != 'active' or any(p['deleted'] for p in report['processes_after']):
        raise RuntimeError('Post-check incomplete: OLS inactive or stale PHP workers remain')
    report['warnings'].append('CLI and service checks passed; verify each website through its real HTTP path.')


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    mode = p.add_mutually_exclusive_group()
    mode.add_argument('--check', action='store_true', help='default: cached, read-only preview')
    mode.add_argument('--apply', action='store_true')
    p.add_argument('--approve', choices=['APPLY-LSPHP-UPDATES'])
    p.add_argument('--backup')
    p.add_argument('--backup-sha256')
    p.add_argument('--restore-tested', action='store_true', help='operator attests restore was tested')
    p.add_argument('--window-start', help='UTC YYYY-MM-DDTHH:MM:SSZ')
    p.add_argument('--window-end', help='UTC YYYY-MM-DDTHH:MM:SSZ')
    p.add_argument('--terminate-stale', action='store_true')
    p.add_argument('--term-timeout', type=int, default=60)
    p.add_argument('--report-prefix', help='explicit output path; creates .json and .txt')
    return p


def main(argv=None):
    p = parser()
    args = p.parse_args(argv)
    if args.apply and not all((args.approve, args.backup, args.backup_sha256,
                               args.restore_tested, args.window_start, args.window_end)):
        p.error('--apply requires approval, backup + SHA256, restore attestation and maintenance window')
    if args.terminate_stale and not args.apply:
        p.error('--terminate-stale requires --apply')
    if not 1 <= args.term_timeout <= 3600:
        p.error('--term-timeout must be 1..3600')
    report = dict(schema=1, mode='apply' if args.apply else 'check', status='failed',
                  time=dt.datetime.now(dt.timezone.utc).isoformat())
    lock = None
    scratch = tempfile.TemporaryDirectory(prefix='lsphp-check-')
    args.scratch = scratch.name
    try:
        if args.apply:
            window(args.window_start, args.window_end)
            backup_check(args.backup, args.backup_sha256)
            import fcntl
            lock = open('/run/lock/cyberpanel-php-security-updater.lock', 'a')
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        execute(args, report)
        report['status'] = 'ok'
    except Exception as exc:
        report['error'] = str(exc)
    finally:
        if lock:
            lock.close()
        scratch.cleanup()
    encoded = json.dumps(report, indent=2, sort_keys=True)
    text = '\n'.join('{}: {}'.format(k, json.dumps(v, sort_keys=True)) for k, v in sorted(report.items())) + '\n'
    print(encoded)
    if args.report_prefix:
        for suffix, content in (('.json', encoded + '\n'), ('.txt', text)):
            # Exclusive create avoids clobbering files/symlinks, including as root.
            fd = os.open(args.report_prefix + suffix, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as stream:
                stream.write(content)
    return 0 if report['status'] == 'ok' else 2


if __name__ == '__main__':
    sys.exit(main())
