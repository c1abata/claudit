# Claudit deployment

Claudit is a single-host service. It binds the operational dashboard to
loopback by default. It does not install agents on audited assets and it must
run only with identities authorized for the declared tenant, account, host or
domain.

## Release acceptance

Run these checks from a complete source tree before copying it to an Ubuntu
host. They make no external provider or DNS request. HTTP integration tests use a temporary loopback server.

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

Install `bash`, `jq`, `curl`, Python 3, `dnsutils`, OpenSSH client and systemd
first. The installer also requires AWS CLI v2, Azure CLI and Google Cloud CLI;
it stops before making host changes when any prerequisite is unavailable. From
the source tree:

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

The dashboard is loopback-only by default. For an explicitly approved network
deployment, set `BindAddress` to `0.0.0.0` in `/etc/claudit/service.json`, then
set `CLAUDIT_DASHBOARD_PASSWORD` to a strong password of at least 24 characters
in `/etc/claudit/claudit.env` before restarting. The login username is `claudit`.
The process refuses a non-loopback bind without this configuration. Passwords
are not embedded in HTML or passed to audit children. All routes require login
when configured, including reports, assets, logs and session APIs.

Prefer a loopback bind and an SSH tunnel. For LAN use, restrict the source
subnet and terminate TLS at a controlled reverse proxy: Basic authentication
alone does not encrypt HTTP. Access the backend with its IP address or localhost;
custom Host headers are rejected. A reverse proxy must set the upstream Host
to the backend IP. Do not expose the standard-library server directly to the
public Internet.

Existing network-bound installations will refuse to start until this password
is configured. This source review did not update `/opt/claudit`, change the
installed service, or alter firewall policy.

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

## Persistent workspace and acceptance

Sessions live in `DataRoot/sessions`; reports and run metadata live in
`DataRoot/reports/dashboard`. Back up both. A session fixes its scope and baseline
at creation; a changed scope belongs in a new session. Each run copies its
baseline and control catalog into its output. Sessions are intentionally not
pruned with reports, so saved answers may outlive their source artifacts. Export
sessions before retention changes; archive makes them read-only, permanent
deletion is allowed only from the archive, and unreadable files can be moved to
the local quarantine from the cockpit.

Open the cockpit, create a scoped session, launch Formal, then a separately
authorized Passive run. Verify its successful exit and actual evidence, ask
about one control, and reopen the session after restarting. Active is optional
and needs its own authorization. Maximum two concurrent runs; a run exceeding
600 seconds is terminated and its incomplete evidence is not used for guidance.

Use the same deployment acceptance for desktop and narrow mobile screens.
A source-tree or fixture test is not proof of deployed LAN reachability or real
provider permissions.
