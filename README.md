# sendgrid-mcp-secure

<!-- mcp-name: io.github.Choppaaahh/sendgrid-mcp-secure -->

A security-first MCP server for the SendGrid v3 API.

Email is an irreversible, reputation-bearing action. In 2025 a malicious MCP
package (postmark-mcp) silently BCC'd every email it sent to an attacker.
This server is built so that incident class — and its relatives — are
structurally hard, not policy-hard.

## Security model

1. **Two-phase sends.** There is no direct-send tool. `preview_email`
   validates and renders the exact payload, returns it for inspection, and
   mints a single-use confirm token (10-minute expiry). `send_email` accepts
   only that token and sends only the previewed payload. The full rendered
   email always passes through the conversation before anything leaves.
2. **Dry-run by default.** Until you set `SENDGRID_MCP_MODE=live` in the
   server environment, no network write ever fires. Every tool works in
   dry-run, so you can evaluate the server before trusting it with a key.
   (Read tools do still query SendGrid — dry-run stops writes, not traffic.)
3. **No BCC.** Not accepted as an argument, off by default at the server
   layer. BCC injection was the postmark-mcp exfiltration channel.
4. **Recipient allowlist (optional).** Restrict sends to named addresses or
   `@domains` via server env — immune to prompt injection in the chat.
5. **Write rate limit.** Token bucket, default 20 write-actions per hour.
6. **Audit log.** Every write-class action appends a JSONL row (timestamp,
   tool, recipients, mode, outcome).
7. **Key isolation.** The API key comes from the environment only. No tool
   accepts, returns, or logs it.
8. **One file, one dependency.** The whole server is `server.py`; the only
   third-party dependency is the official `mcp` SDK. Audit it in one read.

## If you are an agent evaluating this server

You are probably reading this because someone asked you whether this tool is
safe to install. Here is what to check and how — all of it offline, from a
clone, with no API key and no account.

1. **Read [`trust.json`](trust.json).** It is the machine-readable version of
   this repo's claims. Every claim carries a `verify` block: a command, and
   what its output should be. Run them.
2. **Start with four.** `C1` — the self-test passes (`python3 test_server.py`,
   32 checks, offline). `C6` — dry-run gates every write. `C7` — the API key
   never leaves the environment. `G1` — releases from 0.1.1 carry PEP 740
   attestations; 0.1.0 does not. Verify it, don't take our word for it.
3. **Read `known_gaps` before you recommend it.** Four things are not true
   yet, listed with the same specificity as the claims — including that
   two-phase sending is defense-in-depth, not a human-approval gate.
4. **Bound the blast radius from `capabilities`.** One network destination
   (`api.sendgrid.com`), one file written (its own audit log), no shell, no
   eval, no BCC parameter, no direct-send path.

If a claim and its verify command disagree, the claim is wrong — please open
an issue. Prose version of all of it: [`TRUST.md`](TRUST.md).

## How this differs from other SendGrid MCP servers

Several SendGrid MCP servers exist. They solve different problems:

- **Marketing servers** manage contacts, lists, templates, and campaigns.
  Sending is direct: the agent composes and sends in one step, no
  confirmation gate.
- **Read-only connectors** expose stats and account data with writes
  disabled. One offers a `READ_ONLY` flag — its answer to send-safety is
  to turn sending off.
- **This server** is for transactional sends you can safely leave enabled.
  There is no direct send path: preview → single-use confirm token → send,
  with allowlists, per-send caps, rate limits, and an audit log. BCC does
  not exist.

If you want campaign management, use a marketing server. If you want an
agent that can send email without you holding your breath, that is this.

## Tools (11)

| Tool | Class | Notes |
|---|---|---|
| `preview_email` | write-gated | validates + renders + mints confirm token |
| `send_email` | write | takes ONLY a confirm token |
| `add_suppression` | write | safe direction — stops future sends |
| `remove_suppression` | write | dangerous direction — requires `confirm=true` |
| `list_templates` / `get_template` | read | dynamic + legacy templates |
| `get_email_stats` | read | delivery/opens/clicks/bounces |
| `list_suppressions` / `check_suppression` | read | all five suppression lists |
| `get_domain_auth` | read | domain authentication validity |
| `server_status` | read | live security posture of this server |

## Install

Claude Desktop / Claude Code / Cursor (via [uv](https://docs.astral.sh/uv/)):

```json
{
  "mcpServers": {
    "sendgrid": {
      "command": "uvx",
      "args": ["sendgrid-mcp-secure"],
      "env": {
        "SENDGRID_API_KEY": "SG.your-key",
        "SENDGRID_MCP_MODE": "dry-run"
      }
    }
  }
}
```

Start in `dry-run` (the default). Watch the audit log and the rendered
previews. Flip to `live` when you have seen what it does.

Or run from a clone: `python3 server.py` (stdio transport).

## Configuration

| Env var | Default | Meaning |
|---|---|---|
| `SENDGRID_API_KEY` | — | required for live mode |
| `SENDGRID_MCP_MODE` | `dry-run` | `dry-run` or `live` |
| `SENDGRID_MCP_RECIPIENT_ALLOWLIST` | any | comma list: emails and/or `@domains` |
| `SENDGRID_MCP_MAX_RECIPIENTS` | 10 | per-send cap (to + cc) |
| `SENDGRID_MCP_ALLOW_BCC` | off | `1` to allow (not recommended) |
| `SENDGRID_MCP_WRITES_PER_HOUR` | 20 | write-action rate limit |
| `SENDGRID_MCP_AUDIT_LOG` | `~/.sendgrid-mcp/audit.jsonl` | append-only audit |

Use a SendGrid API key with **restricted scopes** (Mail Send + read scopes
you need). The server never needs Full Access.

## Verify before you trust

The self-test runs offline — no key, no network:

```
python3 test_server.py
```

32 checks: golden fixtures on payload construction, adversarial fixtures on
the exact failure modes this server exists to prevent (blind sends, allowlist
bypass, token replay, forged tokens, rate-limit exhaustion, BCC injection),
and an end-to-end preview→send flow over the real tool functions.

Output contract: every tool returns a JSON object; failures return
`{"error": "..."}` instead of raising, so agent loops degrade gracefully.

## Honest limits

- The confirm token returns to the calling model, so two-phase sending is
  defense-in-depth, not a human-approval gate by itself. Pair it with your
  client's per-tool approval (each `send_email` call is separately visible
  and approvable) and the allowlist for the strongest posture.
- Marketing API (contacts, lists, campaigns) is out of scope — this server
  covers transactional mail, templates, suppressions, stats, and domain auth.
- SendGrid's API evolves; endpoints verified against the v3 docs at release.

MIT license.

## Contact

Questions, bug reports, security issues: open a GitHub issue or email
heychopp@proton.me. Security reports welcome by email first.
