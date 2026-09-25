#!/usr/bin/env python3
"""
Agent simulation for the MCP Tool-Result Injection Screen (S1) demo.

The headline is a **before/after diff** on the SAME MCP `tools/call` — the tool
returns untrusted external text (a fetched web page, an email body) that an AI
agent is about to read and act on:

  * RAW (upstream A2D mock, no gateway)  → whatever the tool returns reaches the
    agent verbatim. A benign page is fine; a page carrying "IGNORE ALL PREVIOUS
    INSTRUCTIONS…" — or an email hiding instructions to the AI inside an HTML
    comment — reaches the model as if it were trusted tool output. This is
    indirect prompt injection: the payload rides in on data the agent asked for.
  * GOVERNED (same call, through the Flex Gateway with S1 applied) → S1 screens
    the result text *before the agent sees it*. Deterministic pre-checks
    (zero-width strip, HTML-entity/comment decode, phrase pre-flags) plus a typed
    "System 1" Jev judge score the text for injection. A benign result passes
    through **byte-identical**; an injected result is **withheld** — replaced with
    a valid MCP error result (`isError:true`) explaining the gateway held it back.
    No generated text ever enters the payload; all mutation stays in the policy.

Two tools live on the SAME server:
  * fetch_web_page     → store-hours (benign, allowed) | promo (obvious injection, blocked)
  * read_email_message → inv-1001   (benign, allowed) | phish-9 (hidden HTML-comment injection, blocked)

Usage:
    S1_GW_URL="https://<host>/tri-screen-demo/mcp" \\
    S1_RAW_URL="https://www.a2d-ai.com/api/platform/<serverId>/mcp" \\
    python3 agent.py
"""
import json, os, ssl, sys, urllib.request, urllib.error

GW = (sys.argv[1] if len(sys.argv) > 1 else os.environ.get("S1_GW_URL", "")).strip()
RAW = os.environ.get("S1_RAW_URL", "").strip()
if not GW:
    sys.exit("Set S1_GW_URL (governed MCP endpoint). See demo/env.local.sh.example")
_CTX = ssl.create_default_context(); _CTX.check_hostname = False; _CTX.verify_mode = ssl.CERT_NONE

CASES = [
    {"tool": "fetch_web_page", "arg": "pageTopic", "value": "store-hours",
     "kind": "benign", "note": "a plain store-information page — should pass through byte-identical"},
    {"tool": "fetch_web_page", "arg": "pageTopic", "value": "promo",
     "kind": "injected", "note": "a promo page carrying an in-band 'IGNORE ALL PREVIOUS INSTRUCTIONS…' payload"},
    {"tool": "read_email_message", "arg": "messageId", "value": "inv-1001",
     "kind": "benign", "note": "a normal invoice-notification email — should pass through byte-identical"},
    {"tool": "read_email_message", "arg": "messageId", "value": "phish-9",
     "kind": "injected", "note": "an email hiding AI-directed instructions inside an HTML comment"},
]
# Sentinel the withhold path stamps into the replacement error result.
WITHHELD_MARK = "withheld by the gateway"


def _post(url, body, sid=None):
    h = {"Content-Type": "application/json",
         "Accept": "application/json, text/event-stream",
         "Accept-Encoding": "identity"}
    if sid:
        h["mcp-session-id"] = sid
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST", headers=h)
    try:
        resp = urllib.request.urlopen(req, timeout=25, context=_CTX)
        return resp.status, resp.headers, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read().decode()


def _parse_sse(raw):
    data = []
    for line in raw.splitlines():
        if line.startswith("data:"):
            data.append(line[len("data:"):].lstrip())
        elif not line and data:
            break
    blob = "\n".join(data) if data else raw
    try:
        return json.loads(blob)
    except Exception:
        return {}


def handshake(url):
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                       "clientInfo": {"name": "s1-demo", "version": "1"}}}
    _, hdrs, _ = _post(url, init)
    sid = hdrs.get("mcp-session-id")
    if sid:
        _post(url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, sid)
    return sid


def call_tool(url, spec):
    sid = handshake(url)
    body = {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": spec["tool"], "arguments": {spec["arg"]: spec["value"]}}}
    status, _, raw = _post(url, body, sid)
    return status, _parse_sse(raw)


def result_text(rpc):
    """Concatenate the text of a tools/call result's content[] items."""
    result = rpc.get("result") or {}
    parts = [c.get("text") or "" for c in (result.get("content") or []) if c.get("type") == "text"]
    return "\n".join(parts), bool(result.get("isError"))


def preview(text, n=220):
    t = " ".join(text.split())
    return t if len(t) <= n else t[:n] + " …"


def main():
    print(f"🛡️  mcp tool-result injection screen  →  {GW}\n")
    print("Same MCP tools/call, seen twice: RAW (upstream mock) vs GOVERNED (through the")
    print("gateway, S1 in enforce). The tool returns untrusted external text; S1 screens it")
    print("for prompt injection BEFORE the agent acts. Benign passes byte-identical; an")
    print("injected result is withheld and replaced with an MCP error. No model in the payload.\n")
    for spec in CASES:
        label = "BENIGN" if spec["kind"] == "benign" else "INJECTED"
        print("╔" + "═" * 72)
        print(f"║  {spec['tool']}({spec['arg']}={spec['value']!r})  —  {label}")
        print(f"║  {spec['note']}")
        print("╚" + "─" * 72)

        raw_text = None
        if RAW:
            rstatus, rrpc = call_tool(RAW, spec)
            raw_text, r_err = result_text(rrpc)
            print(f"── RAW (upstream mock, no gateway) — HTTP {rstatus}  isError={r_err} ──")
            print(f"    text: {preview(raw_text)}")
            print()

        gstatus, grpc = call_tool(GW, spec)
        gov_text, g_err = result_text(grpc)
        print(f"── GOVERNED (gateway + S1) — HTTP {gstatus}  isError={g_err} ──")
        print(f"    text: {preview(gov_text)}")

        if spec["kind"] == "benign":
            verdict = "✅ ALLOWED byte-identical" if (raw_text is None or gov_text == raw_text) \
                else "⚠️  ALTERED (unexpected for benign)"
        else:
            withheld = g_err or (WITHHELD_MARK in gov_text.lower())
            leaked = raw_text is not None and raw_text in gov_text
            verdict = "🛑 WITHHELD — injection screened out" if (withheld and not leaked) \
                else "❌ INJECTION REACHED THE AGENT"
        print(f"    verdict: {verdict}")
        print()

    print("The upstream tool result is identical in both cases. The gateway reads the")
    print("untrusted text on the response leg, scores it for injection with deterministic")
    print("pre-checks plus a typed Jev judge, and withholds only what is actually injected —")
    print("so the agent never acts on 'instructions' that rode in on the data it fetched.")


if __name__ == "__main__":
    main()
