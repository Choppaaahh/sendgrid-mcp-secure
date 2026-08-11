#!/usr/bin/env python3
"""Self-test for sendgrid-mcp-secure. Runs entirely offline (dry-run mode,
no API key needed) — which is itself the point: every security property is
testable without trusting the server with credentials.

Golden fixtures are hand-derived; adversarial fixtures exercise the exact
failure modes the server exists to prevent (blind sends, allowlist bypass,
token replay, rate-limit exhaustion).
"""
import json
import os
import tempfile
import time
from pathlib import Path

os.environ["SENDGRID_MCP_MODE"] = "dry-run"
os.environ.pop("SENDGRID_API_KEY", None)
_audit_dir = tempfile.mkdtemp()
os.environ["SENDGRID_MCP_AUDIT_LOG"] = str(Path(_audit_dir) / "audit.jsonl")
os.environ["SENDGRID_MCP_WRITES_PER_HOUR"] = "50"

import server  # noqa: E402

OK = True


def check(name, cond):
    global OK
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    OK = OK and cond


# --- payload builder goldens -------------------------------------------------
p, err = server._build_send_payload(
    ["a@example.com"], "Hi", "me@mydomain.com", "hello", "", "Me", [], "", "", {})
check("golden: minimal payload builds", err is None)
check("golden: to == a@example.com",
      p["personalizations"][0]["to"] == [{"email": "a@example.com"}])
check("golden: from carries name", p["from"] == {"email": "me@mydomain.com", "name": "Me"})
check("golden: subject + one text part",
      p["subject"] == "Hi" and p["content"] == [{"type": "text/plain", "value": "hello"}])
check("golden: NO bcc key anywhere", "bcc" not in json.dumps(p))

p2, err2 = server._build_send_payload(
    ["a@example.com"], "", "me@mydomain.com", "", "", "", [], "",
    "d-12345", {"name": "Ada"})
check("golden: template send has template_id + dynamic data",
      err2 is None and p2["template_id"] == "d-12345"
      and p2["personalizations"][0]["dynamic_template_data"] == {"name": "Ada"}
      and "content" not in p2)

# --- adversarial: the failure modes this server exists to catch --------------
_, e = server._build_send_payload([], "s", "me@mydomain.com", "x", "", "", [], "", "", {})
check("adversarial: zero recipients rejected", e == "no recipients")

_, e = server._build_send_payload(["not-an-email"], "s", "me@mydomain.com", "x", "", "", [], "", "", {})
check("adversarial: malformed recipient rejected", "invalid email" in e)

_, e = server._build_send_payload(["a@example.com"], "s", "bad-from", "x", "", "", [], "", "", {})
check("adversarial: malformed from rejected", "invalid from" in e)

os.environ["SENDGRID_MCP_MAX_RECIPIENTS"] = "2"
_, e = server._build_send_payload(
    ["a@example.com", "b@example.com", "c@example.com"], "s", "me@mydomain.com",
    "x", "", "", [], "", "", {})
check("adversarial: recipient cap enforced (3 > cap 2)", "exceeds cap" in e)
os.environ["SENDGRID_MCP_MAX_RECIPIENTS"] = "10"

os.environ["SENDGRID_MCP_RECIPIENT_ALLOWLIST"] = "@mydomain.com, vip@other.com"
_, e = server._build_send_payload(["attacker@evil.com"], "s", "me@mydomain.com", "x", "", "", [], "", "", {})
check("adversarial: allowlist blocks outside address", "not in server allowlist" in e)
p3, e3 = server._build_send_payload(["ok@mydomain.com"], "s", "me@mydomain.com", "x", "", "", [], "", "", {})
check("allowlist: @domain entry admits domain member", e3 is None)
p4, e4 = server._build_send_payload(["vip@other.com"], "s", "me@mydomain.com", "x", "", "", [], "", "", {})
check("allowlist: exact-email entry admits that address", e4 is None)
os.environ["SENDGRID_MCP_RECIPIENT_ALLOWLIST"] = ""

_, e = server._build_send_payload(["a@example.com"], "s", "me@mydomain.com", "", "", "", [], "", "", {})
check("adversarial: empty content rejected", "no content" in e)

# --- confirm-token flow -------------------------------------------------------
tok = server._mint_token({"x": 1})
check("token: claim returns payload once", server._claim_token(tok) == {"x": 1})
check("adversarial: token replay rejected (single-use)", server._claim_token(tok) is None)
check("adversarial: unknown token rejected", server._claim_token("nope") is None)

tok2 = server._mint_token({"y": 2})
with server._pending_lock:
    server._pending[tok2]["born"] -= server.CONFIRM_TOKEN_TTL_S + 1
check("adversarial: expired token rejected", server._claim_token(tok2) is None)

# --- rate limiter -------------------------------------------------------------
os.environ["SENDGRID_MCP_WRITES_PER_HOUR"] = "3"
b = server._Bucket()
takes = [b.take() for _ in range(4)]
check("golden: bucket cap 3 -> T,T,T,F", takes == [True, True, True, False])
check("golden: remaining reads 0 after exhaustion", b.remaining() == 0)
os.environ["SENDGRID_MCP_WRITES_PER_HOUR"] = "50"

# --- T2-ENTRY-POINT: the real tool functions, end to end, dry-run -------------
prev = server.preview_email(
    to=["a@example.com"], from_email="me@mydomain.com",
    subject="E2E", body_text="entry-point test")
check("e2e: preview returns confirm_token + rendered payload",
      "confirm_token" in prev and prev["rendered_payload"]["subject"] == "E2E")
check("e2e: preview announces dry-run", prev["mode"] == "dry-run")

sent = server.send_email(confirm_token=prev["confirm_token"])
check("e2e: dry-run send simulates, sends nothing",
      sent["status"] == "dry-run" and sent["sent"] is False
      and sent["recipients"] == ["a@example.com"])

sent2 = server.send_email(confirm_token=prev["confirm_token"])
check("e2e adversarial: second send with same token rejected", "error" in sent2)

direct = server.send_email(confirm_token="forged-token")
check("e2e adversarial: forged token rejected", "error" in direct)

sup = server.remove_suppression(email="a@example.com", kind="bounces")
check("e2e adversarial: remove_suppression without confirm refused",
      "error" in sup and "confirm=true" in sup["error"])

st = server.server_status()
check("e2e: server_status reports dry-run + no key + audit path",
      st["mode"] == "dry-run" and st["api_key_present"] is False
      and st["audit_log"].endswith("audit.jsonl"))
check("e2e: bcc disabled by default", st["bcc_allowed"] is False)

reads = server.list_templates()
check("e2e: read tool degrades gracefully without key (no raise)",
      reads.get("error") == "SENDGRID_API_KEY not set")

# --- audit log ----------------------------------------------------------------
rows = [json.loads(l) for l in open(os.environ["SENDGRID_MCP_AUDIT_LOG"])]
check("audit: preview + send + suppression attempts all logged", len(rows) >= 2)
check("audit: rows carry ts/tool/mode",
      all("ts" in r and "tool" in r and "mode" in r for r in rows))
check("audit: API key never appears in audit",
      "SG." not in json.dumps(rows))

print(f"\nSELF-TEST: {'ALL PASS' if OK else 'FAILURES PRESENT'}")
raise SystemExit(0 if OK else 1)
