# Security model

Claudit is a private, read-only operator tool. It reads privileged control planes
and writes local evidence, so its reports and logs must be handled as sensitive
security data even when no credential is present.

## Trust boundaries

- Run from a controlled admin workstation with least-privilege read-only identities.
- Prefer `./claudit.sh formal`, `passive`, or the guided `wizard`; they enforce
  explicit scope and confirmation gates before any live collection.
- The dashboard defaults to loopback. A private-LAN bind must remain restricted
  by host firewall to the trusted operator subnet. Initial web authentication is
  disabled by default; enable `RequireAuthentication` when the network boundary
  is not sufficient. Never expose the standard-library server to the Internet.
- Keep `reports/`, private baselines and client profiles outside shared source history.
- Pass tokens and webhooks through process environment variables. Never place secrets in a baseline, profile, command history or tenant label.
- Formal Domain mode sends DNS queries only to the configured recursive DoH resolvers; it does not connect to the audited domain. Resolver operators can still observe queried names.
- The optional `dnsx` engine is disabled by default and receives only explicitly authorized domains. It runs without a shell, with a hard timeout and bounded captured output.

## Defensive behavior

Claudit validates baseline shape before use, contains individual check failures,
redacts common credential patterns at finding/report/log boundaries, HTML-encodes
reports, protects CSV/Markdown consumers from formula or markup injection, and
returns a non-zero exit code for high-impact or unevaluated results.

Redaction is a last line of defense, not a secret store. Review report artifacts
before sharing them outside the engagement boundary.

Dashboard icons are served only from the packaged `web/assets` tree through the
same canonical-path confinement used for report access. The server does not
serve arbitrary workspace files. The per-page request token protects mutations;
without web authentication, authorized LAN clients can read retained reports
and session data.

## Supported release

Security fixes target the current `0.3.x` line. Reproduce suspected issues with
synthetic data where possible and record the command, exit code and redacted
error; do not attach tenant exports or credentials.
