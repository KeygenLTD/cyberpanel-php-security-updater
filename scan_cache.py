"""Private, best-effort cache for completed file classifications."""
from collections import OrderedDict
from contextlib import contextmanager
import json
import os
from pathlib import Path
import stat
import tempfile


DIRECTORY = Path('/var/lib/cyberpanel-php-security-updater/scan-cache')
MISS = object()
MAX_ENTRIES = 100000


def fingerprint(st):
    return [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns]


class ScanCache:
    def __init__(self, entries):
        self.entries = OrderedDict(entries)
        self.hits = 0

    def get(self, kind, path, st):
        key = kind + ':' + str(path)
        record = self.entries.get(key)
        if not isinstance(record, list) or len(record) != 2 or record[0] != fingerprint(st):
            return MISS
        self.entries.move_to_end(key)
        self.hits += 1
        return record[1]

    def put(self, kind, path, st, finding):
        # Never reuse a classification if the file changed while it was read.
        try:
            if fingerprint(path.lstat()) != fingerprint(st):
                return
        except OSError:
            return
        key = kind + ':' + str(path)
        self.entries[key] = [fingerprint(st), finding]
        self.entries.move_to_end(key)
        if len(self.entries) > MAX_ENTRIES:
            self.entries.popitem(last=False)


@contextmanager
def scan_cache(rules, directory=DIRECTORY):
    import fcntl

    cache = ScanCache({})
    lock = None
    ready = False
    try:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        info = directory.lstat()
        parent = directory.parent.stat()
        if (directory.resolve() != directory or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != 0 or info.st_mode & 0o077
                or parent.st_uid != 0 or parent.st_mode & 0o022):
            raise OSError('scan cache directory must be private and owned by root')
        lock = os.fdopen(os.open(str(directory / 'lock'),
                                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600), 'w')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        ready = True
        path = directory / 'results.json'
        if not path.is_symlink() and path.is_file():
            try:
                data = json.loads(path.read_text())
                if (isinstance(data, dict) and data.get('rules') == rules
                        and isinstance(data.get('entries'), dict)):
                    cache.entries = OrderedDict(list(data['entries'].items())[-MAX_ENTRIES:])
            except (OSError, ValueError):
                pass
    except OSError:
        ready = False
    try:
        yield cache if ready else None
        if ready:
            temp_name = None
            try:
                with tempfile.NamedTemporaryFile(mode='w', dir=str(directory), delete=False) as stream:
                    temp_name = stream.name
                    json.dump({'rules': rules, 'entries': cache.entries}, stream, separators=(',', ':'))
                os.replace(temp_name, str(path))
            except OSError:
                if temp_name is not None:
                    try:
                        os.unlink(temp_name)
                    except OSError:
                        pass
    finally:
        if lock is not None:
            lock.close()
