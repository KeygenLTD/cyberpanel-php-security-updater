# CyberPanel PHP Security Updater

Conservative, fail-closed LSPHP package updates for **AlmaLinux 8, 9 and 10 + CyberPanel + OpenLiteSpeed**. No remote script execution, broad `dnf upgrade`, automatic SIGKILL, PHP branch migration, firewall changes or automatic rollback.

## Quick start

Clone once:

```bash
git clone https://github.com/KeygenLTD/cyberpanel-php-security-updater.git
cd cyberpanel-php-security-updater
```

For the normal production workflow, use one command:

```bash
sudo bash bin/php-security-update --secure-update
```

The one-command workflow performs three guarded phases:

1. Scans website files changed/created since **2026-10-10** through the current time for web-shell and compromise indicators.
2. Shows HIGH/CRITICAL findings for interactive review, then shows the PHP package transaction preview and websites using PHP branches that will be affected. The operator may quarantine, inspect, stop, or explicitly continue.
3. After the operator confirms a current restorable backup/snapshot and types `UPDATE`, updates **all installed LSPHP branches** using the strict transaction policy, then performs post-update checks.

No file is automatically deleted. LOW/MEDIUM scan findings are reported but do not automatically block PHP package updates.

The plain command below remains a read-only package preview:

```bash
sudo bash bin/php-security-update
```

Example output:

```text
CyberPanel PHP Security Updater

[OK] OpenLiteSpeed is running.

PHP used by configured sites:
  8.4.25  (/usr/local/lsws/lsphp84/bin/lsphp)

Detected sites with resolved PHP handlers: 1
  - example.com

Available LSPHP package upgrades: 25
Upgrade candidates by PHP branch:
  PHP 8.4: 25 packages

No changes were made.
```

For full machine-readable output:

```bash
sudo bash bin/php-security-update --json
```

To also save persistent JSON and text reports:

```bash
sudo bash bin/php-security-update --check   --report-prefix /root/php-check-20261022
```

The check requires root for reliable process visibility. It does not install packages, signal processes, change server configuration, add repositories, or import signing keys.

Supported platforms in this release:

- AlmaLinux 8, 9 and 10
- Ubuntu 22.04 and 24.04
- CyberPanel
- OpenLiteSpeed

Required OS package-manager Python bindings must already exist. Unsupported or incomplete environments fail closed with exit code 2.

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

**EL8 difference:** stock platform-python lacks pidfd APIs. Asking it to terminate workers fails before any update. Use a compatible administrator-managed Python with DNF4 bindings and kernel pidfd support, or follow OpenLiteSpeed's documented detached-PHP restart procedure during maintenance and rerun check. The wrapper deliberately prefers the OS DNF interpreter; it does not replace system Python. EL9 and EL10 must also expose both pidfd APIs (stock EL9 Python 3.9 and kernel 5.14 provide the required baseline; runtime capability checks still apply). No automatic OLS restart or restart marker is written.

After applying, the tool checks exact updated RPM EVRs, executes every discovered PHP binary with `-n` to read PHP_VERSION, checks `lsws` is active, and reports any stale workers. CLI versions and service status do **not** prove the PHP version served by each virtual host. Verify websites through their real HTTPS paths, application tests and monitoring before restoring traffic. PHP settings and extensions should be validated through those application tests. Config discovery covers standard `httpd_config.conf` and `conf/vhosts/*/*.conf` absolute handler paths; custom includes/relative handlers require manual review. No automatic rollback is attempted: DNF history undo is not a dependable backup strategy. On failure use the independently tested restore procedure.

Human-readable output is printed by default. Use `--json` for the full machine-readable JSON document. Requested `.json` report files contain a single JSON document and `.txt` contains readable key/value sections. Exit 0 = requested checks passed under the stated limits; 2 = blocked/failed/incomplete. Reports include package versions and process IDs and should be kept private. Partial transactions are reported and must be investigated. Keep terminal output if persistent reports cannot be written.

## Validation

```bash
python3 -m unittest discover -s tests -v
shellcheck bin/php-security-update
docker run --rm -e LSPHP_CONTAINER_TEST=1 -v "$PWD:/src:ro" -w /src almalinux:8 \
  bash -c 'dnf -y install python3 python3-dnf rpm-build && PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v'
# Repeat with almalinux:9 and almalinux:10.
```

Unit tests exercise transaction rejection, backups, maintenance windows, `/proc` parsing and CLI gates/reports. Integration tests build synthetic RPMs **only in tests**, resolve and execute real DNF transactions in a temporary installroot, verify RPM persistence and reject unrelated changes. They require explicit opt-in plus a disposable Docker environment. GitHub Actions runs lint/unit and the AlmaLinux 8/9/10 matrix. These do not replace a full CyberPanel/OLS VM staging test, real signed LiteSpeed repository testing, or application-level validation. No real server apply is performed as part of development.

## References

- [DNF Base API](https://dnf.readthedocs.io/en/latest/api_base.html)
- [DNF transaction API](https://dnf.readthedocs.io/en/latest/api_transaction.html)
- [OpenLiteSpeed detached PHP](https://docs.openlitespeed.org/config/php/detached/)
- [CyberPanel support](https://cyberpanel.net/support) (OS lists differ across pages; runtime capability gates remain mandatory)
- [PHP support lifecycle](https://www.php.net/supported-versions.php)

Production-oriented safeguards do not imply production certification. See validation results and deployment limitations before use.

## Ubuntu 22.04 / 24.04

Ubuntu support requires CyberPanel, OpenLiteSpeed, and the OS-provided
python3-apt bindings. The updater does not install dependencies or add
package repositories.

- `--check`: inspect installed LSPHP packages and preview the transaction.
- `--manual`: show suggested commands without executing them.
- `--apply`: requires explicit approval, a verified backup, restore
  attestation, and a maintenance window.

APT transactions reject unrelated package changes, removals, reinstalls,
downgrades, and candidates without trusted signed repository metadata.
A successful CLI check does not replace live website verification.

Ubuntu APT integration tests run in disposable Ubuntu 22.04 and 24.04
containers in GitHub Actions. Production updates must first be validated
in a staging environment.
