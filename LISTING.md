# Listing metadata (for registry submissions — operator pastes from here)

*This file is submission prep; delete or keep, it ships fine either way.*

## Short description (one line, ~140 chars)

Security-first SendGrid MCP server: two-phase sends, dry-run by default,
recipient allowlists, rate limits, audit log, no BCC. One auditable file.

## Medium description (registry "about" fields)

A SendGrid v3 MCP server built for people who read the code before they
trust it. There is no direct-send tool: `preview_email` renders the exact
payload and mints a single-use confirm token; `send_email` accepts only
that token. Dry-run mode is the default — every tool works before you
provide a key. BCC is structurally absent (it was the exfiltration channel
in the 2025 postmark-mcp incident). Optional server-side recipient
allowlist, per-send caps, write rate limiting, and an append-only audit
log round out the posture. The whole server is one Python file with one
dependency (the official MCP SDK), plus 32 offline tests including
adversarial fixtures for token replay, forged tokens, allowlist bypass,
and rate-limit exhaustion.

## Tags / categories

email, sendgrid, transactional-email, security, audit, communication

## Submission targets

1. Glama — https://glama.ai (submit server; links GitHub repo)
2. mcp.so — submit form
3. Official MCP registry — https://registry.modelcontextprotocol.io
   (publish via `mcp-publisher` CLI from the repo; needs the repo public
   + a server.json — prep on request)
4. (later) PulseMCP / mcpservers.org as discovered

## Suggested repo topics (GitHub)

mcp, mcp-server, sendgrid, email, security, model-context-protocol
