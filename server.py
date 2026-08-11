#!/usr/bin/env python3
"""
sendgrid-mcp-secure — a security-first MCP server for the SendGrid v3 API.

Why this exists: email sends are irreversible, reputation-bearing actions, and
the 2025 postmark-mcp incident (a malicious MCP package that silently BCC'd
every email to an attacker) showed exactly how an email MCP server goes wrong.
This server is designed so that failure mode — and its relatives — are
structurally hard:

  * TWO-PHASE SENDS. There is no direct-send tool. `preview_email` validates
    and renders the exact payload, returns it for inspection, and mints a
    short-lived single-use confirm token. `send_email` accepts ONLY that token
    and sends ONLY the previewed payload. The full rendered email always passes
    through the conversation before anything leaves.
  * DRY-RUN BY DEFAULT. Until SENDGRID_MCP_MODE=live is set in the server env
    (not settable from any tool), no network write ever fires. Every tool works
    in dry-run, so you can evaluate the server without trusting it.
  * NO BCC unless the server operator opts in via env. BCC injection was the
    postmark-mcp exfiltration channel.
  * RECIPIENT ALLOWLIST (optional): restrict sends to named addresses/domains
    at the server layer, immune to prompt injection in the conversation.
  * WRITE RATE LIMIT: token bucket, default 20 write-actions/hour.
  * AUDIT LOG: every write-class action appends a JSONL row (timestamp, tool,
    recipients, mode, outcome). The log is append-only from this process.
  * KEY ISOLATION: the API key comes from the environment only. No tool
    accepts, returns, or logs it.
  * ONE FILE, ONE DEPENDENCY. The entire server is this file; the only
    third-party dependency is the official `mcp` SDK. Auditable in one read.

Output contract: every tool returns a JSON object; failures return
{"error": "..."} rather than raising, so agent loops degrade gracefully.

Env:
  SENDGRID_API_KEY                 required for live mode
  SENDGRID_MCP_MODE                "dry-run" (default) | "live"
  SENDGRID_MCP_AUDIT_LOG           path (default ~/.sendgrid-mcp/audit.jsonl)
  SENDGRID_MCP_RECIPIENT_ALLOWLIST comma-separated emails and/or @domains; empty = any
  SENDGRID_MCP_MAX_RECIPIENTS      per send, default 10
  SENDGRID_MCP_ALLOW_BCC           "1" to allow bcc, default off
  SENDGRID_MCP_WRITES_PER_HOUR     default 20

License: MIT.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from mcp.server.fastmcp import FastMCP

SG_API = "https://api.sendgrid.com"
CONFIRM_TOKEN_TTL_S = 600  # a preview is sendable for 10 minutes, once

mcp = FastMCP("sendgrid-secure")

# ---------------------------------------------------------------------------
# Config — read at call time (not import time) so tests and operators can
# adjust env without restarting; the mode can only ever come from the process
# environment, never from a tool argument.
# ---------------------------------------------------------------------------
def _mode() -> str:
    m = os.environ.get("SENDGRID_MCP_MODE", "dry-run").strip().lower()
    return "live" if m == "live" else "dry-run"


def _api_key() -> str | None:
    k = os.environ.get("SENDGRID_API_KEY", "").strip()
    return k or None


def _audit_path() -> Path:
    p = os.environ.get("SENDGRID_MCP_AUDIT_LOG", "").strip()
    return Path(p) if p else Path.home() / ".sendgrid-mcp" / "audit.jsonl"


def _allowlist() -> list[str]:
    raw = os.environ.get("SENDGRID_MCP_RECIPIENT_ALLOWLIST", "").strip()
    return [e.strip().lower() for e in raw.split(",") if e.strip()]


def _max_recipients() -> int:
    try:
        return max(1, int(os.environ.get("SENDGRID_MCP_MAX_RECIPIENTS", "10")))
    except ValueError:
        return 10


def _bcc_allowed() -> bool:
    return os.environ.get("SENDGRID_MCP_ALLOW_BCC", "0").strip() == "1"


def _writes_per_hour() -> int:
    try:
        return max(1, int(os.environ.get("SENDGRID_MCP_WRITES_PER_HOUR", "20")))
    except ValueError:
        return 20


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _valid_email(addr: str) -> bool:
    return bool(EMAIL_RE.match(addr or ""))


def _allowlist_ok(addr: str, allowlist: list[str]) -> bool:
    """Empty allowlist = any recipient. Entries are exact emails or @domains."""
    if not allowlist:
        return True
    a = addr.lower()
    for entry in allowlist:
        if entry.startswith("@"):
            if a.endswith(entry):
                return True
        elif a == entry:
            return True
    return False


# ---------------------------------------------------------------------------
# Write rate limit — token bucket shared by all write-class tools.
# ---------------------------------------------------------------------------
class _Bucket:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.tokens: float | None = None
        self.stamp = 0.0

    def take(self) -> bool:
        cap = float(_writes_per_hour())
        now = time.monotonic()
        with self.lock:
            if self.tokens is None:
                self.tokens = cap
                self.stamp = now
            self.tokens = min(cap, self.tokens + (now - self.stamp) * cap / 3600.0)
            self.stamp = now
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True
            return False

    def remaining(self) -> int:
        cap = float(_writes_per_hour())
        now = time.monotonic()
        with self.lock:
            if self.tokens is None:
                return int(cap)
            return int(min(cap, self.tokens + (now - self.stamp) * cap / 3600.0))


_bucket = _Bucket()

# ---------------------------------------------------------------------------
# Audit — append-only JSONL for every write-class action, both modes.
# ---------------------------------------------------------------------------
def _audit(tool: str, detail: dict) -> None:
    row = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "tool": tool, "mode": _mode(), **detail}
    path = _audit_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a") as f:
            f.write(json.dumps(row) + "\n")
    except OSError:
        pass  # an unwritable audit path must not block reads-only degradation


# ---------------------------------------------------------------------------
# HTTP — the only place the API key is used. Never logged, never returned.
# ---------------------------------------------------------------------------
def _sg(method: str, path: str, body: dict | None = None, timeout: int = 30):
    """Returns (status:int|None, data:dict|list|None, err:str|None)."""
    key = _api_key()
    if not key:
        return None, None, "SENDGRID_API_KEY not set"
    req = urllib.request.Request(
        SG_API + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {key}",
                 "Content-Type": "application/json"},
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode() or "null"
            return resp.status, json.loads(raw), None
    except urllib.error.HTTPError as e:
        return e.code, None, f"http {e.code}: {e.read().decode()[:200]}"
    except Exception as e:  # noqa: BLE001 — network layer collapses to err string
        return None, None, f"{type(e).__name__}: {e}"


# ---------------------------------------------------------------------------
# Pending previews — confirm tokens for the two-phase send.
# ---------------------------------------------------------------------------
_pending: dict[str, dict] = {}
_pending_lock = threading.Lock()


def _mint_token(payload: dict) -> str:
    tok = secrets.token_urlsafe(16)
    with _pending_lock:
        # single outstanding preview per token; stale ones expire on access
        _pending[tok] = {"payload": payload, "born": time.monotonic()}
        for t in [t for t, v in _pending.items()
                  if time.monotonic() - v["born"] > CONFIRM_TOKEN_TTL_S]:
            del _pending[t]
    return tok


def _claim_token(tok: str) -> dict | None:
    with _pending_lock:
        entry = _pending.pop(tok, None)
    if entry is None:
        return None
    if time.monotonic() - entry["born"] > CONFIRM_TOKEN_TTL_S:
        return None
    return entry["payload"]


def _build_send_payload(to: list[str], subject: str, from_email: str,
                        body_text: str, body_html: str, from_name: str,
                        cc: list[str], reply_to: str,
                        template_id: str, template_data: dict) -> tuple[dict | None, str | None]:
    """Validate + assemble a SendGrid v3 /mail/send payload. Returns (payload, err)."""
    allow = _allowlist()
    recipients = [a.strip() for a in (to or []) if a.strip()]
    ccs = [a.strip() for a in (cc or []) if a.strip()]
    if not recipients:
        return None, "no recipients"
    if len(recipients) + len(ccs) > _max_recipients():
        return None, f"recipient count {len(recipients) + len(ccs)} exceeds cap {_max_recipients()}"
    for a in recipients + ccs:
        if not _valid_email(a):
            return None, f"invalid email: {a}"
        if not _allowlist_ok(a, allow):
            return None, f"recipient not in server allowlist: {a}"
    if not _valid_email(from_email):
        return None, f"invalid from address: {from_email}"
    if reply_to and not _valid_email(reply_to):
        return None, f"invalid reply-to: {reply_to}"
    if not template_id and not (body_text or body_html):
        return None, "no content: provide body_text/body_html or template_id"
    if not subject and not template_id:
        return None, "subject required for non-template sends"

    pers: dict = {"to": [{"email": a} for a in recipients]}
    if ccs:
        pers["cc"] = [{"email": a} for a in ccs]
    if template_id and template_data:
        pers["dynamic_template_data"] = template_data
    payload: dict = {
        "personalizations": [pers],
        "from": {"email": from_email, **({"name": from_name} if from_name else {})},
    }
    if reply_to:
        payload["reply_to"] = {"email": reply_to}
    if template_id:
        payload["template_id"] = template_id
    else:
        payload["subject"] = subject
        content = []
        if body_text:
            content.append({"type": "text/plain", "value": body_text})
        if body_html:
            content.append({"type": "text/html", "value": body_html})
        payload["content"] = content
    return payload, None


# ---------------------------------------------------------------------------
# Tools — write class
# ---------------------------------------------------------------------------
@mcp.tool()
def preview_email(to: list[str], from_email: str, subject: str = "",
                  body_text: str = "", body_html: str = "", from_name: str = "",
                  cc: list[str] | None = None, reply_to: str = "",
                  template_id: str = "", template_data: dict | None = None) -> dict:
    """Validate and render an email WITHOUT sending it. Returns the exact
    payload that would go to SendGrid plus a single-use confirm_token
    (valid 10 minutes). Sending requires passing that token to send_email —
    there is no direct-send path. BCC is not accepted by design."""
    if not _bucket.take():
        return {"error": f"write rate limit reached ({_writes_per_hour()}/hour)"}
    payload, err = _build_send_payload(to, subject, from_email, body_text,
                                       body_html, from_name, cc or [],
                                       reply_to, template_id, template_data or {})
    if err:
        _audit("preview_email", {"outcome": "rejected", "reason": err})
        return {"error": err}
    tok = _mint_token(payload)
    _audit("preview_email", {"outcome": "previewed",
                             "recipients": to, "cc": cc or [],
                             "subject": subject or f"(template {template_id})"})
    return {"status": "previewed", "confirm_token": tok,
            "expires_in_seconds": CONFIRM_TOKEN_TTL_S,
            "mode": _mode(),
            "note": ("DRY-RUN mode: send_email will simulate, not send."
                     if _mode() == "dry-run" else
                     "LIVE mode: send_email with this token WILL send."),
            "rendered_payload": payload}


@mcp.tool()
def send_email(confirm_token: str) -> dict:
    """Send the email previously rendered by preview_email. Accepts ONLY a
    confirm token — the payload cannot be altered between preview and send.
    Tokens are single-use and expire after 10 minutes. In dry-run mode
    (the default) this simulates and audits but sends nothing."""
    payload = _claim_token(confirm_token)
    if payload is None:
        return {"error": "unknown or expired confirm_token — run preview_email again"}
    recipients = [t["email"] for t in payload["personalizations"][0]["to"]]
    if _mode() == "dry-run":
        _audit("send_email", {"outcome": "dry-run", "recipients": recipients})
        return {"status": "dry-run", "sent": False, "recipients": recipients,
                "note": "no network call made; set SENDGRID_MCP_MODE=live in the "
                        "server environment to enable real sends"}
    status, _, err = _sg("POST", "/v3/mail/send", payload)
    outcome = "sent" if status == 202 else f"failed ({err})"
    _audit("send_email", {"outcome": outcome, "recipients": recipients})
    if status == 202:
        return {"status": "sent", "sent": True, "recipients": recipients}
    return {"error": err or f"unexpected status {status}"}


_SUPPRESSION_PATHS = {
    "unsubscribes": "/v3/asm/suppressions/global",
    "bounces": "/v3/suppression/bounces",
    "blocks": "/v3/suppression/blocks",
    "spam_reports": "/v3/suppression/spam_reports",
    "invalid_emails": "/v3/suppression/invalid_emails",
}


@mcp.tool()
def add_suppression(email: str, kind: str = "unsubscribes") -> dict:
    """Add an address to a suppression list (default: global unsubscribes).
    Suppressing is the SAFE direction — it stops future sends to the address."""
    if kind != "unsubscribes":
        return {"error": "only kind='unsubscribes' supports manual add; "
                         "bounces/blocks/spam_reports are recorded by SendGrid"}
    if not _valid_email(email):
        return {"error": f"invalid email: {email}"}
    if not _bucket.take():
        return {"error": f"write rate limit reached ({_writes_per_hour()}/hour)"}
    if _mode() == "dry-run":
        _audit("add_suppression", {"outcome": "dry-run", "email": email, "kind": kind})
        return {"status": "dry-run", "email": email, "kind": kind}
    status, _, err = _sg("POST", "/v3/asm/suppressions/global",
                         {"recipient_emails": [email]})
    _audit("add_suppression", {"outcome": "added" if not err else f"failed ({err})",
                               "email": email, "kind": kind})
    return {"status": "added", "email": email} if not err else {"error": err}


@mcp.tool()
def remove_suppression(email: str, kind: str, confirm: bool = False) -> dict:
    """Remove an address from a suppression list. DANGEROUS direction — it
    re-enables sending to someone who bounced or unsubscribed, which can be a
    compliance violation. Requires confirm=true, is rate-limited, and audited."""
    if kind not in _SUPPRESSION_PATHS:
        return {"error": f"kind must be one of {sorted(_SUPPRESSION_PATHS)}"}
    if not _valid_email(email):
        return {"error": f"invalid email: {email}"}
    if not confirm:
        return {"error": "removing a suppression re-enables sending to this "
                         "address; call again with confirm=true if that is "
                         "genuinely intended"}
    if not _bucket.take():
        return {"error": f"write rate limit reached ({_writes_per_hour()}/hour)"}
    if _mode() == "dry-run":
        _audit("remove_suppression", {"outcome": "dry-run", "email": email, "kind": kind})
        return {"status": "dry-run", "email": email, "kind": kind}
    status, _, err = _sg("DELETE", f"{_SUPPRESSION_PATHS[kind]}/{email}")
    _audit("remove_suppression", {"outcome": "removed" if not err else f"failed ({err})",
                                  "email": email, "kind": kind})
    return {"status": "removed", "email": email, "kind": kind} if not err else {"error": err}


# ---------------------------------------------------------------------------
# Tools — read class
# ---------------------------------------------------------------------------
@mcp.tool()
def list_templates() -> dict:
    """List transactional email templates (dynamic + legacy)."""
    status, data, err = _sg("GET", "/v3/templates?generations=legacy,dynamic&page_size=100")
    if err:
        return {"error": err}
    items = (data or {}).get("result") or (data or {}).get("templates") or []
    return {"templates": [{"id": t.get("id"), "name": t.get("name"),
                           "generation": t.get("generation")} for t in items]}


@mcp.tool()
def get_template(template_id: str) -> dict:
    """Fetch one template with its versions (subject + content preview)."""
    status, data, err = _sg("GET", f"/v3/templates/{template_id}")
    if err:
        return {"error": err}
    return {"template": data}


@mcp.tool()
def get_email_stats(start_date: str, end_date: str = "",
                    aggregated_by: str = "day") -> dict:
    """Global email stats (requests/delivered/opens/clicks/bounces/spam)
    from start_date (YYYY-MM-DD). aggregated_by: day|week|month."""
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", start_date):
        return {"error": "start_date must be YYYY-MM-DD"}
    q = f"/v3/stats?start_date={start_date}&aggregated_by={aggregated_by}"
    if end_date:
        if not re.match(r"^\d{4}-\d{2}-\d{2}$", end_date):
            return {"error": "end_date must be YYYY-MM-DD"}
        q += f"&end_date={end_date}"
    status, data, err = _sg("GET", q)
    return {"stats": data} if not err else {"error": err}


@mcp.tool()
def list_suppressions(kind: str = "unsubscribes", limit: int = 50) -> dict:
    """List a suppression list: unsubscribes|bounces|blocks|spam_reports|invalid_emails."""
    if kind not in _SUPPRESSION_PATHS:
        return {"error": f"kind must be one of {sorted(_SUPPRESSION_PATHS)}"}
    status, data, err = _sg("GET", f"{_SUPPRESSION_PATHS[kind]}?limit={min(max(limit,1),500)}")
    return {"kind": kind, "entries": data} if not err else {"error": err}


@mcp.tool()
def check_suppression(email: str) -> dict:
    """Check whether an address appears on any suppression list. Run this
    before drafting mail to someone — sending to suppressed addresses hurts
    deliverability and may violate consent."""
    if not _valid_email(email):
        return {"error": f"invalid email: {email}"}
    hits = {}
    for kind, path in _SUPPRESSION_PATHS.items():
        suffix = f"/{email}" if kind != "unsubscribes" else f"/{email}"
        status, data, err = _sg("GET", f"{path}{suffix}")
        if err and status not in (404,):
            hits[kind] = f"check-failed: {err}"
        else:
            present = bool(data) and data != [] and status != 404
            if present:
                hits[kind] = "SUPPRESSED"
    return {"email": email,
            "suppressed": bool([v for v in hits.values() if v == "SUPPRESSED"]),
            "detail": hits or {"all_lists": "clear"}}


@mcp.tool()
def get_domain_auth() -> dict:
    """List authenticated sending domains and their DNS validity — the
    first thing to check when deliverability drops."""
    status, data, err = _sg("GET", "/v3/whitelabel/domains")
    if err:
        return {"error": err}
    return {"domains": [{"domain": d.get("domain"), "valid": d.get("valid"),
                         "default": d.get("default")} for d in (data or [])]}


@mcp.tool()
def server_status() -> dict:
    """This server's security posture: mode, rate-limit remaining, allowlist,
    caps, audit-log path, and whether an API key is present (never the key)."""
    return {"mode": _mode(),
            "api_key_present": _api_key() is not None,
            "writes_remaining_this_hour": _bucket.remaining(),
            "recipient_allowlist": _allowlist() or "any",
            "max_recipients_per_send": _max_recipients(),
            "bcc_allowed": _bcc_allowed(),
            "bcc_note": "bcc is disabled by design; the postmark-mcp incident "
                        "used silent BCC as its exfiltration channel",
            "audit_log": str(_audit_path()),
            "two_phase_send": "preview_email -> confirm_token -> send_email"}


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
