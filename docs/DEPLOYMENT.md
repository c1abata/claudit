# Claudit deployment

Claudit is a single-host, loopback-only service. It does not install agents on
audited assets and it must run only with identities authorized for the declared
tenant, account, host or domain.

## Release acceptance

Run these checks from a complete source tree before copying it to an Ubuntu
host. They make no provider, DNS or dashboard network request.

```bash
./install-ubuntu.sh --dry-run
./tests/run.sh
git diff --check
```

The symbolic suite covers catalog binding, secure/weak/unavailable business DNS
data, CloudTrail empty/denied/malformed outcomes, Exchange normalization and
report drift. It is not a substitute for a read-only acceptance run with the
least-privilege identities of the target environment.

## Installation

Install `bash`, `jq`, `curl`, Python 3 and systemd first. Install provider CLIs
only for the providers that this host will audit. From the source tree:

```bash
sudo bash ./install-ubuntu.sh --no-start
sudo systemctl status claudit --no-pager
```

The installer places immutable application code in `/opt/claudit`, configuration
in `/etc/claudit`, and mutable state in `/var/lib/claudit`. It creates a
restricted `claudit` account and refuses symlinked persistent paths.

Review `/etc/claudit/service.json` and put only environment-variable values for
short-lived credentials in `/etc/claudit/claudit.env` (mode `0640`, root:claudit).
Never put tokens into a baseline, a command line, a report, or the repository.

Start and verify the local dashboard:

```bash
sudo systemctl enable --now claudit
sudo systemctl status claudit --no-pager
curl --fail http://127.0.0.1:8765/
```

The dashboard is intentionally loopback-only. Use an SSH tunnel from an
operator workstation when remote access is needed.

## Read-only target acceptance

Run a formal scope check first, then the smallest passive scope using a
least-privilege identity. Treat `unknown` and `error` as incomplete evidence,
not as a passing audit. Store reports in the protected service data directory.

```bash
sudo -u claudit /opt/claudit/claudit.sh formal --service Domain --domain example.com
sudo -u claudit /opt/claudit/claudit.sh passive --service AWS \
  --confirm-tenant-connection --aws-profile audit
```

Active mode requires its separate confirmation and must name every target.

## Upgrade and rollback

The installer backs up old baselines and wizard data under
`/var/lib/claudit/upgrade-backups/` before replacement and preserves existing
`/etc/claudit` files. To roll back, stop the service, restore a previously
verified `/opt/claudit` release and retain the current `/var/lib/claudit` data
until the restored version has passed `doctor` and its test suite.
