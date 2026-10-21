"""Local vhost exposure inventory; no exploit requests or webroot writes."""
from pathlib import Path
import re

ADVISORY = 'https://www.php.net/archive/2026.php#2026-10-21-5'
CVES = ['CVE-2026-109618', 'CVE-2026-109619']
FIXED = {(8, 2): (8, 2, 35), (8, 3): (8, 3, 36),
         (8, 4): (8, 4, 27), (8, 5): (8, 5, 12)}


def assessment(version):
    match = re.match(r'^(\d+)\.(\d+)\.(\d+)', version or '')
    if not match:
        return 'unknown-version'
    parsed = tuple(int(x) for x in match.groups())
    if parsed[:2] <= (8, 1):
        return 'eol-vendor-patch-evidence-required'
    if parsed[:2] not in FIXED:
        return 'unknown-advisory-coverage'
    if parsed < FIXED[parsed[:2]]:
        return 'below-upstream-fixed-version-vendor-backport-unverified'
    return 'at-or-above-upstream-fixed-version-runtime-unverified'


def processors(text):
    text = '\n'.join(line.split('#', 1)[0] for line in text.splitlines())
    result = {}
    for match in re.finditer(r'\bextprocessor\s+(\S+)\s*\{([^{}]*)\}', text, re.I):
        body = match.group(2)
        path = re.search(r'^\s*path\s+([^\s]+)', body, re.M | re.I)
        user = re.search(r'^\s*extUser\s+([^\s]+)', body, re.M | re.I)
        if path:
            binary = path.group(1).strip('"\'').replace('$SERVER_ROOT', '/usr/local/lsws')
            result[match.group(1)] = (binary, user.group(1) if user else None)
    return result


def audit_sites(php_versions, workers, root=Path('/usr/local/lsws/conf')):
    import pwd
    server = root / 'httpd_config.conf'
    shared = processors(server.read_text()) if server.is_file() else {}
    sites = []
    for config in sorted((root / 'vhosts').glob('*/*.conf')):
        text = config.read_text()
        clean = '\n'.join(line.split('#', 1)[0] for line in text.splitlines())
        handlers = sorted(set(re.findall(r'\badd\s+lsapi:([^\s,]+)\s+php\b', clean, re.I)))
        available = dict(shared)
        available.update(processors(text))
        entry = dict(site=config.parent.name, config=str(config), cves=CVES,
                     advisory=ADVISORY, handlers=[], scope='local-config-and-process-inference')
        for handler in handlers:
            binary, user = available.get(handler, (None, None))
            try:
                uid = pwd.getpwnam(user).pw_uid if user else None
            except KeyError:
                uid = None
            matching = [p for p in workers if uid is not None
                        and p.get('uid') == uid and p['binary'] == binary]
            entry['handlers'].append(dict(handler=handler, binary=binary, user=user,
                php_on_disk=php_versions.get(binary),
                assessment=assessment(php_versions.get(binary)),
                observed_pids=[p['pid'] for p in matching],
                stale_pids=[p['pid'] for p in matching if p['deleted']],
                attribution='uid-and-binary' if uid is not None else 'unresolved-user'))
        if not handlers:
            entry['note'] = 'No local PHP handler resolved; inherited/custom includes need manual review'
        sites.append(entry)
    return sites
