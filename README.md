# CyberPanel PHP Security Updater

Conservative, fail-closed LSPHP package updates for **AlmaLinux 8 and 10 + CyberPanel + OpenLiteSpeed**. No remote script execution, broad `dnf upgrade`, automatic SIGKILL, PHP branch migration, firewall changes or automatic rollback.

## Run

Clone and review a pinned revision, then one command runs the default check:

```bash
sudo bash bin/php-security-update
# Optional persistent JSON + text reports (prefix must not already exist):
sudo bash bin/php-security-update --check --report-prefix /root/php-check-20261022
```

Check reads RPM inventory, OLS identity/status, configured absolute PHP handlers and `/proc/PID/exe`, prints versions and a structured DNF transaction preview. DNF cache-only APIs create locks, so the tool copies metadata to a private temporary directory and isolates cache/persist/log writes there; temporary files are removed on exit. It does not refresh repositories, install packages, signal processes or change server configuration. Explicit report output writes only the requested files (0600). It requires root for reliable process visibility. Missing cache/repositories/bindings or unsupported systems fail closed, exit 2. Cache results are **not proof of current security coverage**. Refresh metadata separately under your normal operations procedure before checking.

Python bindings for **DNF4** and RPM must already exist. EL8 normally uses `/usr/libexec/platform-python` (3.6); EL10 uses `/usr/bin/python3`. No automatic dependency installation. DNF5-only installations are refused. AlmaLinux 9 and non-AlmaLinux systems are intentionally unsupported by this release. Repository availability and signing trust must be established by the administrator; the tool never adds repositories or imports keys.

## Apply gates

Prepare a restorable server snapshot/backup covering websites, databases, OLS/CyberPanel/PHP configuration and package state. Test its restoration independently, retain an accessible backup artifact and record its SHA256. The tool verifies that the supplied artifact is nonempty, a regular nonsymlink file, not group/world writable, and matches the supplied digest. `--restore-tested` is an **operator attestation**, not an automated proof that a checksum-matching file can restore the server. Snapshot providers should export an independently verifiable backup artifact; a text file containing a snapshot ID is not a backup.

```bash
sudo bash bin/php-security-update --apply \
  --approve APPLY-LSPHP-UPDATES \
  --backup /root/backups/server-backup.tar \
  --backup-sha256 YOUR_INDEPENDENTLY_RECORDED_SHA256 \
  --restore-tested \
  --window-start 2026-10-23T00:00:00Z \
  --window-end 2026-10-23T01:00:00Z \
  --report-prefix /root/php-apply-20261023
```

Use your actual future UTC window. Apply refreshes repository metadata and re-solves; its preview may differ from a previous cached check. The explicit approval authorizes the current strict LSPHP-only upgrade policy. The **same resolved transaction object** is inspected and executed; no second CLI solve. Only existing `lsphpNN[-extension]` packages with the same name and architecture and strictly greater RPM EVR may change. Any new package (even a PHP dependency), unmatched removal, downgrade, reinstall, architecture change, or unrelated update is blocked. Update required dependencies separately through reviewed maintenance. Weak dependency installation and DNF plugins are disabled. GPG checks are forced, missing/untrusted keys abort. Arbitrary transaction flags are refused. A local flock prevents overlapping tool apply runs; DNF/RPM still enforce their own locks and consistency checks. Do not run other package managers concurrently.

This updates to available repository versions, **not only packages labeled by errata as security fixes**: third-party LiteSpeed metadata may lack security advisories. It does not assert that an RPM fixes a particular CVE. Upstream PHP <=8.1 generates EOL warnings; vendor backports need separate evidence. Newer branch lifecycles must also be checked against the linked upstream schedule.

## Old workers and maintenance

Running and stale workers are discovered via `/proc/PID/exe`, not `ps` text. `(deleted)` binaries may keep serving old PHP after an RPM update or OLS restart. The default apply does not kill workers. If any remain, post-validation exits 2 even if packages were successfully installed; inspect `transaction_completed` before retrying.

`--terminate-stale` explicitly enables SIGTERM **inside the approved maintenance window**, using Linux pidfds plus process-start identity rechecks to avoid PID-reuse races. Only deleted executables under the supported LSPHP binary paths are targeted. The tool waits up to `--term-timeout` (default 60 seconds), then fails without SIGKILL. SIGTERM can interrupt active requests: drain traffic and arrange a maintenance page externally first. The window is checked before download/transaction and each signal/wait; an RPM transaction already in progress cannot safely be interrupted when the window expires. Reserve enough time for the entire operation.

**EL8 difference:** stock platform-python lacks pidfd APIs. Asking it to terminate workers fails before any update. Use a compatible administrator-managed Python with DNF4 bindings and kernel pidfd support, or follow OpenLiteSpeed's documented detached-PHP restart procedure during maintenance and rerun check. The wrapper deliberately prefers the OS DNF interpreter; it does not replace system Python. EL10 must also expose both pidfd APIs. No automatic OLS restart or restart marker is written.

After applying, the tool checks exact updated RPM EVRs, executes every discovered PHP binary with `-n` to read PHP_VERSION, checks `lsws` is active, and reports any stale workers. CLI versions and service status do **not** prove the PHP version served by each virtual host. Verify websites through their real HTTPS paths, application tests and monitoring before restoring traffic. PHP settings and extensions should be validated through those application tests. Config discovery covers standard `httpd_config.conf` and `conf/vhosts/*/*.conf` absolute handler paths; custom includes/relative handlers require manual review. No automatic rollback is attempted: DNF history undo is not a dependable backup strategy. On failure use the independently tested restore procedure.

JSON is printed to stdout (alongside an explicit preview); requested `.json` is a single JSON document. `.txt` contains readable key/value sections. Exit 0 = requested checks passed under the stated limits; 2 = blocked/failed/incomplete. Reports include package versions and process IDs and should be kept private. Partial transactions are reported and must be investigated. Keep terminal output if persistent reports cannot be written.

## Validation

```bash
python3 -m unittest discover -s tests -v
shellcheck bin/php-security-update
docker run --rm -e LSPHP_CONTAINER_TEST=1 -v "$PWD:/src:ro" -w /src almalinux:8 \
  bash -c 'dnf -y install python3 python3-dnf rpm-build && PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v'
# Repeat with almalinux:10.
```

Unit tests exercise transaction rejection, backups, maintenance windows, `/proc` parsing and CLI gates/reports. Integration tests build synthetic RPMs **only in tests**, resolve and execute real DNF transactions in a temporary installroot, verify RPM persistence and reject unrelated changes. They require explicit opt-in plus a disposable Docker environment. GitHub Actions runs lint/unit and the AlmaLinux 8/10 matrix. These do not replace a full CyberPanel/OLS VM staging test, real signed LiteSpeed repository testing, or application-level validation. No real server apply is performed as part of development.

## References

- [DNF Base API](https://dnf.readthedocs.io/en/latest/api_base.html)
- [DNF transaction API](https://dnf.readthedocs.io/en/latest/api_transaction.html)
- [OpenLiteSpeed detached PHP](https://docs.openlitespeed.org/config/php/detached/)
- [CyberPanel support](https://cyberpanel.net/support) (OS lists differ across pages; runtime capability gates remain mandatory)
- [PHP support lifecycle](https://www.php.net/supported-versions.php)

Production-oriented safeguards do not imply production certification. See validation results and deployment limitations before use.
