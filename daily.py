"""Configuration and HTTPS checks for unattended LSPHP maintenance."""
import datetime as dt
import json
from pathlib import Path
import re
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


CONFIG = Path('/etc/cyberpanel-php-security-updater/daily.json')


def load_config(path=CONFIG):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError('Daily maintenance requires a regular configuration file')
    info = path.stat()
    if info.st_uid != 0 or info.st_mode & 0o077:
        raise RuntimeError('Daily configuration must be owned by root and private')
    config = json.loads(path.read_text())
    if not isinstance(config, dict):
        raise RuntimeError('Daily configuration must be a JSON object')
    urls = config.get('https_urls')
    if not isinstance(urls, list) or not urls or not all(isinstance(url, str) for url in urls):
        raise RuntimeError('Configure at least one HTTPS health URL')
    for url in urls:
        parsed = urlsplit(url)
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.fragment or any(c.isspace() for c in url)):
            raise RuntimeError('Health URLs must use HTTPS without credentials or fragments')
    backup = config.get('backup')
    digest = config.get('backup_sha256')
    if config.get('operator_snapshot_confirmed') is True:
        if any(key in config for key in ('backup', 'backup_sha256', 'restore_tested')):
            raise RuntimeError('Choose either a backup file or an operator-confirmed snapshot')
        return config
    if (not isinstance(backup, str) or not Path(backup).is_absolute()
            or not isinstance(digest, str) or not re.fullmatch(r'[0-9a-fA-F]{64}', digest)
            or config.get('restore_tested') is not True):
        raise RuntimeError('Daily maintenance requires an absolute backup path, SHA256 and restore attestation')
    return config


def maintenance_window(now):
    start = now.replace(hour=3, minute=0, second=0, microsecond=0)
    end = start + dt.timedelta(hours=1)
    return tuple(value.strftime('%Y-%m-%dT%H:%M:%SZ') for value in (start, end))


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def check_sites(urls, results):
    opener = build_opener(NoRedirect())
    for url in urls:
        try:
            request = Request(url, headers={'User-Agent': 'CyberPanel-PHP-Security-Updater'})
            with opener.open(request, timeout=15) as response:
                status = response.getcode()
                if not 200 <= status < 300:
                    raise RuntimeError('HTTP {}'.format(status))
        except (OSError, ValueError, RuntimeError) as exc:
            results.append({'url': url, 'error': str(exc)})
        else:
            results.append({'url': url, 'status': status})
    if any('error' in result for result in results):
        failed = ', '.join(result['url'] for result in results if 'error' in result)
        raise RuntimeError('HTTPS health check failed: ' + failed)
