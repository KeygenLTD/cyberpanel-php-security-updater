#!/usr/bin/env python3
"""Read-only compromise/web-shell scanner with optional operator-approved quarantine."""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
try:
    import pwd
except ImportError:  # Windows unit-test compatibility; production target is Linux.
    pwd = None
import re
import shutil
import stat

TEXT_EXTENSIONS = {'.php', '.phtml', '.php5', '.php7', '.php8', '.phar', '.inc', '.htaccess', '.js'}
PHP_EXTENSIONS = {'.php', '.phtml', '.php5', '.php7', '.php8', '.phar', '.inc'}
KNOWN_SHELL_NAMES = re.compile(
    r'(?i)(?:^|[-_.])(c99|r57|wso|phpshell2?|b374k|filesman|alfa[-_ ]?shell|mini[-_ ]?shell|priv8)(?:[-_.]|$)'
)
UPLOAD_PATH = re.compile(r'(?i)/(?:wp-content/)?uploads?/')
COMMAND_EXEC = re.compile(r'(?i)\b(shell_exec|system|passthru|exec|popen|proc_open|pcntl_exec)\s*\(')
OBFUSCATION = re.compile(r'(?i)\b(base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin)\s*\(')
DYNAMIC_EVAL = re.compile(r'(?i)\b(eval|assert)\s*\(')
REQUEST_INPUT = re.compile(r'(?i)\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b')
REMOTE_IO = re.compile(r'(?i)\b(curl_exec|fsockopen|pfsockopen|stream_socket_client|socket_create)\s*\(')
VARIABLE_CALL = re.compile(r'(?i)\$[A-Za-z_][A-Za-z0-9_]*\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)')
LONG_ENCODED = re.compile(r'[A-Za-z0-9+/]{300,}={0,2}')
PERSISTENCE_TOKENS = re.compile(r'(?i)(curl|wget|bash\s+-c|python\s+-c|perl\s+-e|php\s+-r|nc\s|ncat|socat|/dev/tcp/)')

MAX_FILE_BYTES = 8 * 1024 * 1024
DEFAULT_QUARANTINE = Path('/var/lib/cyberpanel-php-security-updater/quarantine')


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def owner_name(uid):
    if pwd is None:
        return str(uid)
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def discover_web_roots(home=Path('/home')):
    roots = []
    if not home.is_dir():
        return roots
    for child in home.iterdir():
        candidate = child / 'public_html'
        if candidate.is_dir():
            roots.append(candidate)
    return sorted(set(roots))


def read_text_limited(path, max_bytes=MAX_FILE_BYTES):
    with path.open('rb') as stream:
        data = stream.read(max_bytes + 1)
    truncated = len(data) > max_bytes
    data = data[:max_bytes]
    return data.decode('utf-8', errors='replace'), truncated


def classify_file(path, text):
    reasons = []
    score = 0
    lower_path = path.as_posix().lower()
    suffix = path.suffix.lower()

    if KNOWN_SHELL_NAMES.search(path.name):
        score += 40
        reasons.append('Known web-shell family/name indicator')
    if suffix in PHP_EXTENSIONS and UPLOAD_PATH.search(lower_path):
        score += 30
        reasons.append('Executable PHP-family file inside an uploads directory')
    if COMMAND_EXEC.search(text):
        score += 20
        reasons.append('OS command execution primitive present')
    if OBFUSCATION.search(text):
        score += 15
        reasons.append('Obfuscation/decoder primitive present')
    if DYNAMIC_EVAL.search(text):
        score += 15
        reasons.append('Dynamic code evaluation primitive present')
    if REQUEST_INPUT.search(text) and (COMMAND_EXEC.search(text) or DYNAMIC_EVAL.search(text) or VARIABLE_CALL.search(text)):
        score += 30
        reasons.append('Request-controlled input reaches execution-like code')
    if REMOTE_IO.search(text):
        score += 10
        reasons.append('Outbound/network primitive present')
    if VARIABLE_CALL.search(text):
        score += 25
        reasons.append('Variable function invocation from request input')
    if LONG_ENCODED.search(text):
        score += 10
        reasons.append('Large encoded-looking blob present')
    if '<?php' in text[:2048].lower() and path.suffix.lower() not in PHP_EXTENSIONS:
        score += 35
        reasons.append('PHP code found in a non-PHP extension')

    score = min(score, 100)
    if score >= 80:
        severity = 'CRITICAL'
    elif score >= 55:
        severity = 'HIGH'
    elif score >= 30:
        severity = 'MEDIUM'
    elif score:
        severity = 'LOW'
    else:
        severity = 'CLEAN'
    return score, severity, reasons


def iter_recent_files(roots, cutoff, deep=False):
    seen = set()
    for root in roots:
        for current, dirs, files in os.walk(str(root), followlinks=False):
            dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', 'vendor'}]
            for name in files:
                path = Path(current) / name
                try:
                    st = path.lstat()
                except OSError:
                    continue
                if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                    continue
                if not deep and st.st_mtime < cutoff:
                    continue
                key = (st.st_dev, st.st_ino)
                if key in seen:
                    continue
                seen.add(key)
                yield path, st


def suspicious_persistence(days):
    cutoff = dt.datetime.now(dt.timezone.utc).timestamp() - (days * 86400)
    candidates = []
    paths = [Path('/etc/crontab'), Path('/etc/cron.d'), Path('/var/spool/cron'), Path('/etc/systemd/system'),
             Path('/tmp'), Path('/var/tmp'), Path('/dev/shm')]
    for base in paths:
        if not base.exists():
            continue
        iterable = [base] if base.is_file() else base.rglob('*')
        for path in iterable:
            try:
                st = path.lstat()
                if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) or st.st_mtime < cutoff or st.st_size > MAX_FILE_BYTES:
                    continue
                text, _ = read_text_limited(path)
            except (OSError, UnicodeError):
                continue
            if PERSISTENCE_TOKENS.search(text):
                candidates.append({
                    'path': str(path),
                    'modified': dt.datetime.fromtimestamp(st.st_mtime, dt.timezone.utc).isoformat(),
                    'owner': owner_name(st.st_uid),
                    'reason': 'Recent persistence/temp file contains command/downloader/network execution indicators'
                })
    return candidates


def related_log_hits(finding, limit=20):
    needle = Path(finding['path']).name
    hits = []
    for base in (Path('/home'), Path('/usr/local/lsws/logs'), Path('/var/log')):
        if not base.exists():
            continue
        try:
            files = base.rglob('*.log')
        except OSError:
            continue
        for log in files:
            if len(hits) >= limit:
                break
            try:
                if log.stat().st_size > 100 * 1024 * 1024:
                    continue
                with log.open('r', errors='replace') as stream:
                    for line_no, line in enumerate(stream, 1):
                        if needle in line:
                            hits.append({'log': str(log), 'line': line_no, 'text': line.rstrip()[:500]})
                            if len(hits) >= limit:
                                break
            except (OSError, UnicodeError):
                continue
    return hits


def scan(days=7, deep=False, roots=None):
    if os.geteuid() != 0:
        raise RuntimeError('Root required for complete security scan')
    roots = [Path(p) for p in (roots or discover_web_roots())]
    cutoff = dt.datetime.now(dt.timezone.utc).timestamp() - (days * 86400)
    findings = []
    inspected = 0
    for path, st in iter_recent_files(roots, cutoff, deep=deep):
        inspected += 1
        if st.st_size > MAX_FILE_BYTES:
            continue
        suffix = path.suffix.lower()
        try:
            if suffix not in TEXT_EXTENSIONS and path.name != '.htaccess':
                with path.open('rb') as probe:
                    head = probe.read(min(st.st_size, 128 * 1024))
                if b'<?php' not in head.lower() and b'<?= ' not in head.lower() and b'<?=' not in head.lower():
                    continue
            text, truncated = read_text_limited(path)
        except OSError:
            continue
        score, severity, reasons = classify_file(path, text)
        if not score:
            continue
        findings.append({
            'path': str(path),
            'score': score,
            'severity': severity,
            'reasons': reasons,
            'sha256': sha256_file(path),
            'size': st.st_size,
            'owner': owner_name(st.st_uid),
            'uid': st.st_uid,
            'mode': oct(stat.S_IMODE(st.st_mode)),
            'modified': dt.datetime.fromtimestamp(st.st_mtime, dt.timezone.utc).isoformat(),
            'truncated_analysis': truncated,
        })
    findings.sort(key=lambda x: (-x['score'], x['path']))
    high = [f for f in findings if f['score'] >= 55]
    compromise = 'HIGH CONFIDENCE' if any(f['score'] >= 80 and len(f['reasons']) >= 2 for f in findings) else (
        'SUSPICIOUS' if high else 'NO KNOWN INDICATORS FOUND'
    )
    return {
        'schema': 1,
        'mode': 'security-scan',
        'days': days,
        'deep': deep,
        'roots': [str(p) for p in roots],
        'files_inspected': inspected,
        'findings': findings,
        'persistence_findings': suspicious_persistence(days),
        'evidence_of_compromise': compromise,
        'time': dt.datetime.now(dt.timezone.utc).isoformat(),
    }


def quarantine(path, expected_sha256, root=DEFAULT_QUARANTINE):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise RuntimeError('Refusing to quarantine non-regular file or symlink')
    actual = sha256_file(path)
    if actual != expected_sha256:
        raise RuntimeError('File changed since scan; refusing quarantine')
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(str(root), 0o700)
    target_dir = root / actual
    target_dir.mkdir(mode=0o700, exist_ok=True)
    target = target_dir / path.name
    if target.exists():
        raise RuntimeError('Quarantine target already exists')
    metadata = {
        'original_path': str(path),
        'sha256': actual,
        'quarantined_at': dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    try:
        os.replace(str(path), str(target))
    except OSError:
        with path.open('rb') as src, target.open('xb') as dst:
            shutil.copyfileobj(src, dst, 1024 * 1024)
            dst.flush()
            os.fsync(dst.fileno())
        if sha256_file(target) != actual:
            target.unlink()
            raise RuntimeError('Quarantine copy verification failed')
        path.unlink()
    os.chmod(str(target), 0o600)
    manifest = target_dir / 'manifest.json'
    with manifest.open('x') as stream:
        json.dump(metadata, stream, indent=2, sort_keys=True)
        stream.write('\n')
    os.chmod(str(manifest), 0o600)
    return {'target': str(target), 'manifest': str(manifest), 'sha256': actual}


def evidence_preview(path, max_lines=80):
    path = Path(path)
    text, _ = read_text_limited(path, 128 * 1024)
    lines = text.splitlines()
    interesting = []
    patterns = (COMMAND_EXEC, OBFUSCATION, DYNAMIC_EVAL, REQUEST_INPUT, REMOTE_IO, VARIABLE_CALL)
    for idx, line in enumerate(lines, 1):
        if any(p.search(line) for p in patterns):
            interesting.append((idx, line[:500]))
            if len(interesting) >= max_lines:
                break
    return interesting


def human_summary(report):
    lines = ['CyberPanel Security Scan', '']
    lines.append('Web roots: {}'.format(len(report['roots'])))
    lines.append('Files inspected: {}'.format(report['files_inspected']))
    lines.append('Suspicious files: {}'.format(len(report['findings'])))
    lines.append('Persistence indicators: {}'.format(len(report['persistence_findings'])))
    lines.append('Evidence of compromise: {}'.format(report['evidence_of_compromise']))
    if report['findings']:
        lines.append('')
        for finding in report['findings']:
            lines.append('[{}] {}  score={}/100'.format(finding['severity'], finding['path'], finding['score']))
            lines.append('  SHA256: {}'.format(finding['sha256']))
            lines.append('  Modified: {}  Owner: {}'.format(finding['modified'], finding['owner']))
            for reason in finding['reasons']:
                lines.append('  - {}'.format(reason))
    if report['persistence_findings']:
        lines.append('')
        lines.append('Persistence / temp indicators:')
        for item in report['persistence_findings']:
            lines.append('  - {} ({})'.format(item['path'], item['reason']))
    lines.append('')
    lines.append('No files were deleted automatically.')
    return '\n'.join(lines)


def interactive_review(report):
    for finding in report['findings']:
        print('')
        print('[{}] {}  {}/100'.format(finding['severity'], finding['path'], finding['score']))
        while True:
            choice = input('[V]iew evidence  [L]ogs  [Q]uarantine  [I]gnore  [N]ext: ').strip().lower()
            if choice in ('i', 'n', ''):
                break
            if choice == 'v':
                rows = evidence_preview(finding['path'])
                if not rows:
                    print('No execution-oriented lines selected for preview.')
                for line_no, text in rows:
                    print('{:>6}: {}'.format(line_no, text))
            elif choice == 'l':
                hits = related_log_hits(finding)
                if not hits:
                    print('No related filename hits found in searched logs.')
                for hit in hits:
                    print('{}:{} {}'.format(hit['log'], hit['line'], hit['text']))
            elif choice == 'q':
                confirm = input('Type QUARANTINE to move this file out of the web root: ').strip()
                if confirm != 'QUARANTINE':
                    print('Cancelled.')
                    continue
                result = quarantine(finding['path'], finding['sha256'])
                print('Quarantined: {}'.format(result['target']))
                break
            else:
                print('Unknown choice.')


def run_security_scan(days=7, deep=False, interactive=False, json_output=False):
    if days < 1 or days > 3650:
        raise RuntimeError('--days must be 1..3650')
    report = scan(days=days, deep=deep)
    if json_output:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(human_summary(report))
    if interactive and report['findings']:
        interactive_review(report)
    return report
