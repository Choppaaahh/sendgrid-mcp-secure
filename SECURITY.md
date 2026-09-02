# Security Policy

## Reporting a vulnerability

Email **heychopp@proton.me** with subject `[SECURITY] sendgrid-mcp-secure`.
You will get an acknowledgment within 72 hours and a fix-or-assessment within
14 days. Please do not open public issues for exploitable vulnerabilities
before a fix ships; credit is given in the release notes unless you ask
otherwise.

## Supported versions

Only the latest release on PyPI is supported. There is no backporting.

## Release integrity

- **Releases from 0.1.1 are provenance-signed; 0.1.0 is not.** A GitHub
  Actions trusted-publishing workflow (OIDC, no long-lived tokens) at
  `.github/workflows/publish.yml` fires on `v*` tags. 0.1.1 (2026-08-30) was
  the first release through it, and both of its files on PyPI carry PEP 740
  attestations. Check for yourself —
  `curl -H 'Accept: application/vnd.pypi.simple.v1+json' https://pypi.org/simple/sendgrid-mcp-secure/`
  returns a `provenance` URL on the 0.1.1 wheel and sdist, and `provenance:
  null` on the 0.1.0 files, which were uploaded by hand and will stay unsigned.
  Install 0.1.1 or newer if build provenance matters to you. Tracked as G1 in
  `TRUST.md`.
- The package has exactly one runtime dependency (`mcp>=1.2,<2`). To pin
  fully, install with hashes:
  `pip install sendgrid-mcp-secure --require-hashes -r requirements.txt`
  after generating `requirements.txt` with `pip-compile --generate-hashes`.
- The entire server is one file (`server.py`). Diff it between releases —
  the intended property is that every release remains reviewable in one
  sitting. If a release ever grows beyond one-sitting reviewability, treat
  that as a signal, not a feature.

## What this server will never do

These are standing invariants; a release that violates one is a bug of the
highest severity regardless of intent:

1. No direct-send tool — every send passes preview + single-use confirm token.
2. No BCC parameter, ever.
3. The API key is read from the environment only — never accepted, returned,
   or logged by any tool.
4. No network writes in dry-run mode (`SENDGRID_MCP_MODE` unset or != `live`).
5. Every write-class action is appended to the audit log before the result
   is returned.

## Known limitations (honest scope)

This server protects the path where the agent uses THIS server. It cannot
prevent a key from being used through other clients or raw API calls — pair
it with a least-privilege SendGrid API key (Mail Send only) and, where
possible, SendGrid-side recipient and rate controls. It is a seatbelt for
the seat you are sitting in, not a perimeter.
