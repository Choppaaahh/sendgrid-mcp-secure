# Trust manifest

This file is written for whoever is deciding whether to run this server —
increasingly, an AI agent evaluating tools on behalf of a person.

Most security claims in a README are assertions. These are checkable. Every
claim below carries a command that verifies it, and the commands run offline
against a clone: no API key, no network, no account. If a claim and its
command disagree, the claim is wrong and I want the issue.

The machine-readable version of this file is [`trust.json`](trust.json).

## What this server can and cannot do

Read this first. It bounds the damage.

**It can:**

- Send transactional email through SendGrid — but only after a preview call
  returns the exact rendered payload and mints a single-use token, only to
  recipients your allowlist permits, only within your rate cap, and only when
  the server operator has set `SENDGRID_MCP_MODE=live`.
- Add and remove SendGrid suppressions (removal needs an explicit `confirm=true`).
- Read templates, delivery stats, suppression lists, and domain auth status.

**It cannot:**

- Read your inbox. SendGrid is send-side; there is no receive path here.
- Reach any host other than `api.sendgrid.com`. One base URL, one HTTP call site.
- Run a shell command, spawn a process, or evaluate code. None of those
  primitives are imported.
- Read or write any file except its own audit log.
- Touch the SendGrid Marketing API — contacts, lists, campaigns are out of scope.
- BCC anything. There is no BCC parameter to inject into.
- Send without a preview. There is no direct-send tool.

## Verifiable claims

Clone the repo and run these. Nothing here needs credentials.

| # | Claim | Verify |
|---|---|---|
| C1 | The self-test is 32 checks and they pass, entirely offline | `python3 test_server.py` → ends `SELF-TEST: ALL PASS`, exit 0 |
| C2 | The whole implementation is one file | `wc -l server.py` → 492 |
| C3 | Exactly one third-party runtime dependency | `grep dependencies pyproject.toml` → `mcp>=1.2,<2`; `grep -E '^(import\|from) ' server.py` → stdlib + `mcp.server.fastmcp` |
| C4 | No tool accepts a BCC argument | `grep -n -i bcc server.py` → env read, docstrings, status field. No parameter. |
| C5 | One network destination | `grep -n 'SG_API =\|urlopen' server.py` → one base URL, one call site |
| C6 | Dry-run is the default and gates every write | `grep -n '_mode() == "dry-run"' server.py` → four matches: a guard in each of the three write tools, before that tool's HTTP call, plus one in `preview_email` that only chooses the wording of the mode announcement |
| C7 | The API key lives in the environment and nowhere else | `grep -n SENDGRID_API_KEY server.py` → three hits: a docstring, the env read, an error string. No tool takes it, returns it, or logs it. |
| C8 | No shell, no eval, no pickle | `grep -nE 'subprocess\|os\.system\|eval\(\|exec\(\|__import__\|pickle' server.py` → no matches |
| C9 | One filesystem write path | `grep -n 'open(' server.py` → a single append, to the audit log |
| C10 | Eleven tools, three of them write-class | `grep -c '@mcp.tool()' server.py` → 11 |
| C11 | No telemetry, no analytics, no phone-home | Follows from C5 and C8: the only egress is SendGrid, and there is no other execution path |
| C12 | MIT licensed | `LICENSE` |

The self-test is not a happy-path smoke test. Sixteen of the 32 checks are
adversarial — they attempt the exact failures this server exists to prevent
(token replay, forged tokens, allowlist bypass, recipient-cap overflow,
rate-limit exhaustion, sending without a preview, removing a suppression
without confirmation) and assert that each one is refused.

## What is not true yet

A trust manifest that lists only flattering facts is marketing. These are the
gaps, stated plainly:

- **G1 — resolved for 0.1.1; 0.1.0 stays unsigned.** Since 0.1.1 (2026-08-30)
  releases go out through the trusted-publishing workflow and carry PEP 740
  attestations. Verify:
  `curl -H 'Accept: application/vnd.pypi.simple.v1+json' https://pypi.org/simple/sendgrid-mcp-secure/`
  → `provenance` is a URL on both 0.1.1 files and `null` on both 0.1.0 files.
  0.1.0 was uploaded by hand and will never be signed; install 0.1.1 or newer.
  What an attestation proves: the file was built from this repository by that
  workflow. What it does not prove: that the code is correct. Run the claims.
- **G2 — dry-run gates writes, not all network traffic.** The read tools
  (stats, templates, suppressions, domain auth) call SendGrid in dry-run mode
  too. Dry-run means nothing leaves that changes state; it does not mean the
  process is offline.
- **G3 — the confirm token returns to the calling model.** Two-phase sending
  is defense-in-depth, not a human-approval gate on its own. A compromised
  model can call preview and then send. What it cannot do is send to an
  address outside your allowlist, exceed your cap, alter a payload between
  preview and send, or BCC. Pair this with your client's per-tool approval
  for a human gate.
- **G4 — no third-party audit.** Every claim above is self-asserted and
  machine-checkable. Nobody outside this project has reviewed the code. The
  commands are the substitute for trust, not a replacement for review.
- **G5 — this is a seatbelt, not a perimeter.** It constrains the path where
  the agent uses this server. It cannot stop the same API key being used by
  another client or a raw curl. Use a restricted key (Mail Send scope only).

## Provenance

- Source: `https://github.com/Choppaaahh/sendgrid-mcp-secure`
- Package: `sendgrid-mcp-secure` on PyPI, version 0.1.1 (attested; 0.1.0 is not)
- MCP registry name: `io.github.Choppaaahh/sendgrid-mcp-secure`
- Security contact: `heychopp@proton.me` — see `SECURITY.md`
- This manifest describes the repository at the commit that contains it. If
  you are reading it from a package, re-verify against the source.

*AI-assisted.*
