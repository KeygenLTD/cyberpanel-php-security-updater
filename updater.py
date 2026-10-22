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
    supported_alma = values.get('ID') == 'almalinux' and major in ('8', '9', '10')
    supported_ubuntu = values.get('ID') == 'ubuntu' and values.get('VERSION_ID') in ('22.04', '24.04')
    if not (supported_alma or supported_ubuntu):
        raise RuntimeError('Supported OS: AlmaLinux 8/9/10 and Ubuntu 22.04/24.04 only')
    if os.uname().machine not in ('x86_64', 'aarch64'):
        raise RuntimeError('Unsupported architecture')
    if not Path('/usr/local/CyberCP').is_dir():
        raise RuntimeError('CyberPanel installation not found')
    identity = run(['/usr/local/lsws/bin/lshttpd', '-v'])
    if not ('OpenLiteSpeed' in identity or re.search(r'LiteSpeed/[\d.]+ Open\b', identity)):
        raise RuntimeError('OpenLiteSpeed identity not verified')
    return major if supported_alma else 'ubuntu:' + values['VERSION_ID']


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
                                   deleted=deleted, start=start, uid=entry.stat().st_uid))
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
        output = run([binary, '-v'])
        match = re.search(r'^PHP\s+(\d+\.\d+\.\d+)\b', output, re.MULTILINE)
        if not match:
            raise RuntimeError('Cannot determine PHP version for {}'.format(binary))
        result[binary] = match.group(1)
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


def preflight(args, report):
    report['os_major'] = platform_check()
    if os.geteuid() != 0:
        raise RuntimeError('Root required for complete process/package inspection')
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


def inventory_report(installed, report):
    if not installed:
        raise RuntimeError('No installed LSPHP packages')
    report['installed'] = sorted(str(p) for p in installed)
    report['php_before'] = versions(installed)
    from site_audit import audit_sites
    report['sites_before'] = audit_sites(report['php_before'], report['processes_before'])
    for binary in report['configured_php'] + [p['binary'] for p in report['processes_before']]:
        if binary not in report['php_before']:
            raise RuntimeError('Configured/running PHP is not managed by discovered packages')
    report['warnings'] = ['Cached metadata may be stale; this is not proof that PHP is secure.']
    if any(p['deleted'] for p in report['processes_before']):
        report['warnings'].append('Deleted LSPHP executables are still running; maintenance required.')
    for binary, version in report['php_before'].items():
        if tuple(int(x) for x in version.split('.')[:2]) <= (8, 1):
            report['warnings'].append('Upstream EOL: {} = {}; vendor backports require independent verification'.format(binary, version))


def manual_commands(installed, report):
    names = ' '.join(sorted(set(p.name for p in installed)))
    if report['backend'] == 'apt':
        command = 'sudo apt-get --only-upgrade --no-remove --no-install-recommends install ' + names
        preview = command.replace('apt-get ', 'apt-get --simulate ', 1)
    else:
        command = 'sudo dnf --best --setopt=install_weak_deps=False upgrade ' + names
        preview = command.replace('dnf ', 'dnf --assumeno ', 1)
    report['manual_commands'] = [preview, command]
    report['warnings'].append('Manual commands are NOT executed or policy-enforced by this tool. Validate backup, window and exact transaction; decline unrelated changes.')


def execute(args, report):
    preflight(args, report)
    if report['os_major'].startswith('ubuntu:'):
        from apt_backend import execute_apt
        return execute_apt(args, report)
    import dnf
    import rpm
    report['backend'] = 'dnf4'
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
        inventory_report(installed, report)
        if args.manual:
            manual_commands(installed, report)
        for name in sorted(set(p.name for p in installed)):
            base.upgrade(name)
        base.resolve(allow_erasing=False)
        incoming = list(base.transaction.install_set)
        outgoing = list(base.transaction.remove_set)
        compare = lambda a, b: rpm.labelCompare((str(a.epoch), a.version, a.release),
                                                (str(b.epoch), b.version, b.release))
        report['preview'] = validate_transaction(installed, incoming, outgoing, compare)
        if args.json:
            print(json.dumps({'transaction_preview': report['preview']}, indent=2), flush=True)
        if not args.apply:
            return
        if args.secure_update:
            report['backup'] = {'operator_attested': True}
        else:
            report['backup'] = backup_check(args.backup, args.backup_sha256)
            window(args.window_start, args.window_end)
        if incoming:
            base.download_packages(incoming)
            for pkg in incoming:
                code, message = base.package_signature_check(pkg)
                if code != 0:
                    raise RuntimeError('RPM signature check failed: ' + message)
            if not args.secure_update:
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
            if args.secure_update:
                restart_marker = Path('/usr/local/lsws/admin/tmp/.lsphp_restart.txt')
                restart_marker.parent.mkdir(parents=True, exist_ok=True)
                restart_marker.touch()
                report['php_restart_marker'] = str(restart_marker)
        report['php_after'] = versions(installed)
    postflight(args, report)


def postflight(args, report):
    if args.terminate_stale:
        terminate_stale(args)
    report['processes_after'] = processes()
    from site_audit import audit_sites
    report['sites_after'] = audit_sites(report['php_after'], report['processes_after'])
    report['ols_after'] = run(['systemctl', 'is-active', 'lsws'])
    if report['ols_after'] != 'active':
        raise RuntimeError('Post-check incomplete: OpenLiteSpeed is inactive')
    stale = [p for p in report['processes_after'] if p['deleted']]
    if stale:
        if args.secure_update:
            report['warnings'].append('Stale PHP workers remain; restart marker was written and workers should recycle on subsequent requests.')
        else:
            raise RuntimeError('Post-check incomplete: stale PHP workers remain')
    report['warnings'].append('CLI and service checks passed; verify each website through its real HTTP path.')


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    mode = p.add_mutually_exclusive_group()
    mode.add_argument('--check', action='store_true', help='default: cached, read-only preview')
    mode.add_argument('--apply', action='store_true')
    mode.add_argument('--secure-update', action='store_true', help='scan, preview affected sites and update all installed LSPHP branches')
    p.add_argument('--manual', action='store_true', help='check and print manual commands; execute nothing')
    p.add_argument('--approve', choices=['APPLY-LSPHP-UPDATES'])
    p.add_argument('--backup')
    p.add_argument('--backup-sha256')
    p.add_argument('--restore-tested', action='store_true', help='operator attests restore was tested')
    p.add_argument('--window-start', help='UTC YYYY-MM-DDTHH:MM:SSZ')
    p.add_argument('--window-end', help='UTC YYYY-MM-DDTHH:MM:SSZ')
    p.add_argument('--terminate-stale', action='store_true')
    p.add_argument('--term-timeout', type=int, default=60)
    p.add_argument('--report-prefix', help='explicit output path; creates .json and .txt')
    p.add_argument('--json', action='store_true',
                   help='print full machine-readable JSON instead of the human summary')
    p.add_argument('--security-scan', action='store_true',
                   help='scan recent web files and persistence locations for compromise indicators')
    p.add_argument('--days', type=int, default=7,
                   help='security scan lookback window in days (default: 7)')
    p.add_argument('--since', help='security scan start date YYYY-MM-DD; scans from that date through now')
    p.add_argument('--deep', action='store_true',
                   help='security scan all supported web files, ignoring modification time')
    p.add_argument('--interactive', action='store_true',
                   help='review findings and optionally quarantine files interactively')
    return p



def human_summary(report):
    lines = ['CyberPanel PHP Security Updater', '']

    if report.get('status') != 'ok':
        lines.append('[FAILED] Check could not be completed.')
        error = report.get('error')
        if error:
            lines.append('Reason: {}'.format(error))
        lines.append('')
        if report.get('mode') == 'check':
            lines.append('No changes were made.')
        else:
            if report.get('transaction_completed'):
                lines.append('The package transaction completed, but post-validation failed.')
                lines.append('Review the detailed report before taking further action.')
            else:
                lines.append('No package transaction was completed.')
        lines.append('')
        lines.append('For technical details run again with --json.')
        return '\n'.join(lines)

    lines.append('[OK] OpenLiteSpeed is running.')

    configured = report.get('configured_php', [])
    versions_before = report.get('php_before', {})
    if configured:
        lines.append('')
        lines.append('PHP used by configured sites:')
        for binary in configured:
            version = versions_before.get(binary, 'unknown')
            lines.append('  {}  ({})'.format(version, binary))
    else:
        lines.append('')
        lines.append('[WARN] No absolute PHP handler was found in standard OLS configuration.')

    sites = [
        site for site in report.get('sites_before', [])
        if site.get('handlers')
    ]
    lines.append('')
    lines.append('Detected sites with resolved PHP handlers: {}'.format(len(sites)))
    for site in sites:
        lines.append('  - {}'.format(site.get('site', 'unknown')))

    preview = report.get('preview', [])
    lines.append('')
    if preview:
        lines.append('Available LSPHP package upgrades: {}'.format(len(preview)))
        branches = {}
        for item in preview:
            match = re.match(r'lsphp([0-9]{2,3})', item.get('name', ''))
            if match:
                branches[match.group(1)] = branches.get(match.group(1), 0) + 1
        if branches:
            lines.append('Upgrade candidates by PHP branch:')
            for branch in sorted(branches):
                label = '{}.{}'.format(branch[0], branch[1:]) if len(branch) == 2 else branch
                lines.append('  PHP {}: {} packages'.format(label, branches[branch]))
    else:
        lines.append('[OK] No LSPHP package upgrades are present in the current transaction preview.')

    warnings = report.get('warnings', [])
    if warnings:
        lines.append('')
        lines.append('Warnings:')
        for warning in warnings:
            lines.append('  - {}'.format(warning))

    lines.append('')
    if report.get('mode') == 'check':
        lines.append('No changes were made.')
        if preview:
            lines.append('To review the full technical result:')
            lines.append('  sudo bash bin/php-security-update --json')
    else:
        lines.append('[OK] Update workflow completed.')
        lines.append('Verify each website through its real HTTPS path before restoring traffic.')

    return '\n'.join(lines)



def update_impact_summary(report):
    preview = report.get('preview', [])
    branches = set()
    for item in preview:
        match = re.match(r'lsphp([0-9]{2,3})', item.get('name', ''))
        if match:
            branches.add(match.group(1))

    affected = []
    for site in report.get('sites_before', []):
        matched = []
        for handler in site.get('handlers', []):
            binary = handler.get('binary') or ''
            match = re.search(r'/lsphp([0-9]{2,3})/bin/lsphp', binary)
            if match and match.group(1) in branches:
                matched.append(handler.get('php_on_disk') or 'unknown')
        if matched:
            affected.append((site.get('site', 'unknown'), matched))

    print('')
    print('PHP update impact')
    print('  Package upgrades: {}'.format(len(preview)))
    if branches:
        labels = []
        for branch in sorted(branches):
            labels.append('{}.{}'.format(branch[0], branch[1:]) if len(branch) == 2 else branch)
        print('  PHP branches: {}'.format(', '.join(labels)))
    if affected:
        print('  Sites using PHP branches that will be updated:')
        for site, versions in affected:
            print('    - {} (PHP {})'.format(site, ', '.join(sorted(set(versions)))))
    else:
        print('  No configured site handler was resolved to an upgrading PHP branch.')
    return affected


def secure_update_flow(args):
    from security_scan import run_security_scan

    since = args.since or '2026-10-10'
    print('=== Phase 1/3: Security scan ===')
    scan_report = run_security_scan(days=args.days, deep=False, interactive=False, json_output=False, since=since)
    severe = [f for f in scan_report.get('findings', []) if f.get('score', 0) >= 55]
    if severe:
        from security_scan import interactive_review
        print('')
        print('[WARNING] HIGH/CRITICAL security findings detected: {}'.format(len(severe)))
        review_report = dict(scan_report)
        review_report['findings'] = severe
        interactive_review(review_report)
        proceed = input('Type CONTINUE to proceed to PHP update preview, or anything else to stop: ').strip()
        if proceed != 'CONTINUE':
            print('Stopped after security review; no packages were changed.')
            return 2

    scratch = tempfile.TemporaryDirectory(prefix='lsphp-secure-update-')
    lock = None
    try:
        args.scratch = scratch.name
        print('')
        print('=== Phase 2/3: PHP update preview ===')
        args.apply = False
        preview_report = dict(schema=1, mode='check', status='failed', time=dt.datetime.now(dt.timezone.utc).isoformat())
        execute(args, preview_report)
        preview_report['status'] = 'ok'
        update_impact_summary(preview_report)
        if not preview_report.get('preview'):
            print('')
            print('[OK] No LSPHP package upgrades are currently available.')
            return 0

        print('')
        backup = input('Do you have a current restorable backup/snapshot? [y/N]: ').strip().lower()
        if backup not in ('y', 'yes'):
            print('[WARN] No current restorable backup/snapshot was confirmed.')
            proceed_without_backup = input('Continue with the PHP update anyway? [y/N]: ').strip().lower()
            if proceed_without_backup not in ('y', 'yes'):
                print('Update cancelled; no packages were changed.')
                return 2
        confirm = input('Install all listed LSPHP upgrades now? [y/N]: ').strip().lower()
        if confirm not in ('y', 'yes'):
            print('Update cancelled; no packages were changed.')
            return 2

        print('')
        print('=== Phase 3/3: Applying PHP updates ===')
        import fcntl
        lock = open('/run/lock/cyberpanel-php-security-updater.lock', 'a')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        args.apply = True
        apply_report = dict(schema=1, mode='secure-update', status='failed', time=dt.datetime.now(dt.timezone.utc).isoformat())
        execute(args, apply_report)
        apply_report['status'] = 'ok'
        print(human_summary(apply_report))
        return 0
    finally:
        if lock:
            lock.close()
        scratch.cleanup()


def main(argv=None):
    p = parser()
    args = p.parse_args(argv)
    if args.secure_update:
        return secure_update_flow(args)
    if args.security_scan:
        if args.apply or args.manual or args.terminate_stale:
            p.error('--security-scan cannot be combined with package mutation modes')
        from security_scan import run_security_scan
        try:
            run_security_scan(days=args.days, deep=args.deep,
                              interactive=args.interactive, json_output=args.json,
                              since=args.since)
            return 0
        except (Exception, KeyboardInterrupt) as exc:
            if args.json:
                print(json.dumps({'schema': 1, 'mode': 'security-scan', 'status': 'failed',
                                  'error': str(exc)}, indent=2, sort_keys=True))
            else:
                print('CyberPanel Security Scan\n\n[FAILED] {}'.format(exc))
            return 2
    if args.deep or args.interactive or args.days != 7 or args.since:
        p.error('--days/--since/--deep/--interactive require --security-scan')
    if args.manual and args.apply:
        p.error('--manual is read-only and cannot be combined with --apply')
    if args.apply and not all((args.approve, args.backup, args.backup_sha256,
                               args.restore_tested, args.window_start, args.window_end)):
        p.error('--apply requires approval, backup + SHA256, restore attestation and maintenance window')
    if args.terminate_stale and not args.apply:
        p.error('--terminate-stale requires --apply')
    if not 1 <= args.term_timeout <= 3600:
        p.error('--term-timeout must be 1..3600')
    if args.report_prefix and any(os.path.lexists(args.report_prefix + suffix) for suffix in ('.json', '.txt')):
        p.error('Report files already exist; choose a fresh prefix')
    report = dict(schema=1, mode='apply' if args.apply else 'check', status='failed',
                  time=dt.datetime.now(dt.timezone.utc).isoformat())
    lock = None
    scratch = None
    try:
        scratch = tempfile.TemporaryDirectory(prefix='lsphp-check-')
        args.scratch = scratch.name
        if args.apply:
            window(args.window_start, args.window_end)
            backup_check(args.backup, args.backup_sha256)
            import fcntl
            lock = open('/run/lock/cyberpanel-php-security-updater.lock', 'a')
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        execute(args, report)
        report['status'] = 'ok'
    except (Exception, KeyboardInterrupt) as exc:
        report['error'] = str(exc)
    finally:
        if lock:
            lock.close()
        if scratch is not None:
            scratch.cleanup()
    encoded = json.dumps(report, indent=2, sort_keys=True)
    text = '\n'.join('{}: {}'.format(k, json.dumps(v, sort_keys=True)) for k, v in sorted(report.items())) + '\n'
    if args.json:
        print(encoded)
    else:
        print(human_summary(report))
    if args.report_prefix:
        created = []
        try:
            for suffix, content in (('.json', encoded + '\n'), ('.txt', text)):
                path = args.report_prefix + suffix

                # Never overwrite existing reports or symlinks.
                fd = os.open(
                    path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600
                )
                created.append(path)

                with os.fdopen(fd, 'w') as stream:
                    stream.write(content)

        except OSError:
            # Remove only files created by this invocation.
            for path in reversed(created):
                try:
                    os.unlink(path)
                except OSError:
                    pass
            raise
    return 0 if report['status'] == 'ok' else 2


if __name__ == '__main__':
    sys.exit(main())
