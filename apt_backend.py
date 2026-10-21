"""Ubuntu APT backend; imported only after OS/panel/service preflight."""
import contextlib
import json
import os

import updater as u


class DebPackage:
    def __init__(self, package, version):
        self.name = package.name.split(':')[0]
        self.arch = version.architecture
        self.version = version.version

    def __str__(self):
        return '{}:{}={}'.format(self.name, self.arch, self.version)


def plan(cache, compare, require_trust=True):
    installed = [DebPackage(p, p.installed) for p in cache
                 if p.is_installed and u.PACKAGE.fullmatch(p.name.split(':')[0])]
    for package in cache:
        if not package.is_installed or not u.PACKAGE.fullmatch(package.name.split(':')[0]):
            continue
        if package.is_upgradable:
            package.mark_install(auto_fix=False, auto_inst=False, from_user=True)
    if cache.broken_count:
        raise RuntimeError('APT dependencies are broken or additional packages are needed')
    incoming, outgoing = [], []
    for package in cache.get_changes():
        if (not package.is_installed or not package.marked_upgrade
                or package.marked_delete or package.marked_reinstall):
            raise RuntimeError('APT transaction contains install/removal/downgrade/reinstall')
        if require_trust and (not package.candidate.origins
                              or not all(origin.trusted for origin in package.candidate.origins)):
            raise RuntimeError('APT candidate is not from trusted signed metadata')
        incoming.append(DebPackage(package, package.candidate))
        outgoing.append(DebPackage(package, package.installed))
    preview = u.validate_transaction(installed, incoming, outgoing,
                                    lambda a, b: compare(a.version, b.version))
    return installed, incoming, preview


def execute_apt(args, report):
    import apt
    import apt_pkg
    apt_pkg.init_config()
    for key in ('APT::Get::AllowUnauthenticated', 'Acquire::AllowInsecureRepositories',
                'Acquire::AllowDowngradeToInsecureRepositories'):
        apt_pkg.config.set(key, 'false')
    apt_pkg.config.set('APT::Install-Recommends', 'false')
    apt_pkg.config.set('APT::Install-Suggests', 'false')
    apt_pkg.init_system()
    # Native lock covers resolution through commit; cache.commit uses APT's
    # reentrant system locking, and executes this marked dependency cache.
    lock = apt_pkg.SystemLock() if args.apply else contextlib.ExitStack()
    report['backend'] = 'apt'
    with lock:
        cache = apt.Cache(memonly=True)
        try:
            if args.apply:
                cache.update(raise_on_error=True)
                cache.open()
            held = u.run(['apt-mark', 'showhold']).split()
            if any(u.PACKAGE.fullmatch(name.split(':')[0]) for name in held):
                raise RuntimeError('LSPHP package is held; resolve hold explicitly before using this updater')
            installed = [DebPackage(p, p.installed) for p in cache
                         if p.is_installed and u.PACKAGE.fullmatch(p.name.split(':')[0])]
            u.inventory_report(installed, report)
            installed, incoming, preview = plan(cache, apt_pkg.version_compare)
            if args.manual:
                u.manual_commands(installed, report)
            report['preview'] = preview
            print(json.dumps({'transaction_preview': preview}, indent=2), flush=True)
            if not args.apply:
                return
            report['backup'] = u.backup_check(args.backup, args.backup_sha256)
            u.window(args.window_start, args.window_end)
            if incoming:
                # Fetch and authenticate first, then recheck the window before dpkg.
                cache.fetch_archives(allow_unauthenticated=False)
                u.window(args.window_start, args.window_end)
                os.environ['DEBIAN_FRONTEND'] = 'noninteractive'
                report['transaction_started'] = True
                if not cache.commit(allow_unauthenticated=False):
                    raise RuntimeError('APT commit did not complete')
                report['transaction_completed'] = True
                for package in incoming:
                    actual = u.run(['dpkg-query', '-W', '-f=${Version}',
                                    package.name + ':' + package.arch])
                    if actual != package.version:
                        raise RuntimeError('Post-transaction DPKG version verification failed')
            report['php_after'] = u.versions(installed)
        finally:
            cache.close()
    u.postflight(args, report)
