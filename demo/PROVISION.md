# Demo provisioning runbook (tool-result injection screen)

Stands up the live **MCP Tool-Result Injection Screen** (S1) demo with `anypoint-cli-v4`
+ the A2D MCP tools. S1 is a response-leg (`injectionPoint: outbound`) policy: it reads the
untrusted text a `tools/call` result returns (a fetched web page, an email body), scores it
for indirect prompt injection with deterministic pre-checks + a typed "System 1" Jev judge,
and — in `enforce` — **withholds** an injected result (replaces it with a valid MCP
`isError:true` result) while a benign result passes through **byte-identical**. No generated
text ever enters the payload; all mutation stays in the policy (Rust/wasm).

The demo runs the judge in **`mock`** mode (`jevProvider: mock` + `allowMock: true`) — a
deterministic in-policy lexical judge — so it needs **no external Jev/LLM key** and is fully
offline/reproducible. Swap in `typesafe`/`openai`/`openrouter`/… + `jevApiKey` for a real judge.

## Things this build wires up (fill each with your own tenant's values)

| Thing | Value |
|---|---|
| Anypoint org / env | `<orgId>` / Sandbox `<envId>` |
| A2D mock MCP server | `<mockServerId>` (two tools: `fetch_web_page`, `read_email_message`) |
| Mock URL | `https://www.a2d-ai.com/api/platform/<mockServerId>/mcp` |
| Exchange asset (MCP server) | `tool-result-injection-demo/1.0.0` (type `mcp`) |
| API Manager instance | `<apiInstanceId>` (label `tri-screen-demo`) |
| Flex gateway target | omni-gw-small `<gatewayTargetId>` (has a public URL), gatewayVersion `<ver>` |
| Applied policies | **MCP Support** (order 1) + `mcp-tool-result-injection-screen` **1.0.2** (id `<policyId>`) |
| Upstream (for the outbound apply) | `<upstreamId>` |
| Governed endpoint | `https://<gatewayPublicHost>/tri-screen-demo/mcp` |

## 1. A2D mock (two tools, benign + injected scenarios)

Create with `design_mcp_server` (type `mock`) + `add_mcp_tool`, or reuse an existing server.
Each tool selects its response by argument via `add_mock_scenario`:

- **`fetch_web_page`** (arg `pageTopic`): `store-hours` → a benign store-information page;
  `promo` → a marketing page carrying an in-band **"IGNORE ALL PREVIOUS INSTRUCTIONS…"** payload.
- **`read_email_message`** (arg `messageId`): `inv-1001` → a benign invoice email;
  `phish-9` → an email hiding AI-directed instructions inside an **HTML comment** (`<!-- SYSTEM: … -->`).

> **A2D gotcha:** a tool that declares an `output_schema` must return structured JSON, not
> plain text. These tools return text, so add them with **`output_schema: null`** (omit it);
> otherwise `tools/call` fails with "mock scenario must return structured content".

See [`mcp-metadata.json`](mcp-metadata.json) for the tool contracts this demo publishes.

## 2. Publish the policy (definition + flex impl) to Exchange

```bash
# from the repo root — each dir has a Makefile; `make release` publishes via anypoint-cli-v4 pdk.
# Publish the DEFINITION FIRST — `make release` on the flex impl runs config-gen against it.
make -C tool-result-injection-screen-definition release
make -C tool-result-injection-screen-flex       release
```
Already released: definition `mcp-tool-result-injection-screen` **1.0.2** + implementation
`tool-result-injection-screen-flex` **1.0.2**. (If API Manager reports "no implementation for
flexGateway version" when applying, wait ~10 min for Exchange indexing and retry.)

## 3. Publish + deploy the MCP Flex instance

```bash
anypoint-cli-v4 exchange:asset:upload --name "Tool-Result Injection Screen Demo" \
  --type mcp --status published --properties='{"platform":"a2d"}' \
  --files='{"mcp-metadata.json":"./mcp-metadata.json"}' tool-result-injection-demo/1.0.0

anypoint-cli-v4 api-mgr:api:manage tool-result-injection-demo 1.0.0 \
  --environment Sandbox --isFlex --type mcp --withProxy \
  --scheme http --port 8081 --path "/tri-screen-demo/" \
  --uri "https://www.a2d-ai.com/api/platform/<mockServerId>/" \
  --apiInstanceLabel tri-screen-demo
#   → Created new API with ID: <apiInstanceId>

anypoint-cli-v4 api-mgr:api:deploy <apiInstanceId> --environment Sandbox \
  --target <gatewayTargetId> --gatewayVersion <ver> --overwrite
```
> The upstream `--uri` is the mock surface **minus** the trailing `/mcp`
> (`https://www.a2d-ai.com/api/platform/<mockServerId>/`) — MCP Support re-appends the MCP path.
> Confirm `api-mgr:api:describe <apiInstanceId>` shows a non-null Deployment TargetID; the
> gateway target id + gatewayVersion come from an already-deployed instance on omni-gw-small.

## 4. Apply the policies (MCP Support first, then S1 — OUTBOUND)

MCP Support must be applied **first** (order 1) so the gateway speaks MCP framing (SSE +
`Mcp-Session-Id`); apply it before S1:

```bash
anypoint-cli-v4 api-mgr:policy:apply <apiInstanceId> mcp-support \
  --environment Sandbox --groupId 68ef9520-24e9-4cf2-b2f5-620025690913 \
  --policyVersion 1.0.1
```

S1 is an **outbound** policy (`injectionPoint: outbound`), so `api-mgr:policy:apply` requires an
**`--upstreamId`**. Fetch it from the deployed instance (applying MCP Support materialises the
upstream), then apply S1 with the demo config:

```bash
# Find the upstream id (routing[].upstreams[].id) of the deployed MCP instance:
anypoint-cli-v4 api-mgr:api:describe <apiInstanceId> --environment Sandbox --output json \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['routing'][0]['upstreams'][0]['id'])"

cp config.json.example config.json   # runs the mock judge; no creds needed
anypoint-cli-v4 api-mgr:policy:apply <apiInstanceId> mcp-tool-result-injection-screen \
  --environment Sandbox --groupId <orgId> --policyVersion 1.0.2 \
  --upstreamId <upstreamId> --configFile ./config.json
anypoint-cli-v4 api-mgr:api:redeploy <apiInstanceId> --environment Sandbox
```
`config.json` mirrors the `gcl.yaml` schema — see [`config.json.example`](config.json.example).
The demo uses `mode: enforce`, `failMode: closed`, `jevProvider: mock`, `allowMock: true`,
`onBlock: withhold`, `hiddenTextBoost: 0.15`; everything else takes built-in defaults.

> **Note on ordering:** the CLI has no `--order` flag; flex policy order follows apply sequence
> (MCP Support applied first ⇒ order 1). Verify with `api-mgr:policy:list <apiInstanceId>`.
>
> Upgrading an already-applied S1 to a new version: `api-mgr:policy:remove <apiInstanceId>
> <oldPolicyId>` then `apply` the new version with the same `--upstreamId`. Never delete +
> re-publish the *same* Exchange asset version — API Manager then fails `policy:apply` with
> `Schema … not found to validate instance`; bump the version instead.

## 5. Run

```bash
cp env.local.sh.example env.local.sh   # set S1_GW_URL (+ optional S1_RAW_URL for the diff)
source env.local.sh
./demo.sh
```

Expected — for each case the agent prints the RAW upstream result (through the mock) and the
GOVERNED result (through the gateway):
- `fetch_web_page(store-hours)` and `read_email_message(inv-1001)` → **ALLOWED byte-identical**.
- `fetch_web_page(promo)` and `read_email_message(phish-9)` → **WITHHELD**: the governed result
  is `isError:true` "The gateway withheld this tool result because it appears to contain
  instructions aimed at an AI agent (policy: tool-result-injection-screen)."

Quick manual check (initialize → capture mcp-session-id → notifications/initialized → tools/call over SSE):

```bash
GW="https://<gatewayPublicHost>/tri-screen-demo/mcp"
curl -sS -X POST "$GW" -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" -H "Accept-Encoding: identity" \
  -H "mcp-session-id: s-demo" --max-time 25 \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fetch_web_page","arguments":{"pageTopic":"promo"}}}' \
  | sed -n 's/^data: //p' | python3 -m json.tool
```

## Notes
- **MCP Support order 1 is mandatory** — it preserves the SSE framing + `Mcp-Session-Id` S1
  reads on the response leg. S1 second.
- **Egress:** in `mock` mode S1 makes no outbound judge call. With a real provider the policy
  calls `jevService` (`format: service`); confirm the gateway can reach it.
- **Enforce vs shadow:** flip `mode` to `shadow` to compute + log the decision without mutating
  the response (safe first deployment), then to `enforce`.
- **Fail-closed:** for tools that fetch arbitrary external content, `failMode: closed` withholds
  on a judge error/timeout rather than trusting the result.
- Keep the definition's top-level `description` ≤256 chars (the flex-impl publish enforces it).
