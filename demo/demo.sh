#!/usr/bin/env bash
# One-shot live demo driver for the MCP Tool-Result Injection Screen (S1).
#
#   source demo/env.local.sh   # sets S1_GW_URL (+ optional S1_RAW_URL) — see env.local.sh.example
#   ./demo/demo.sh
#
# Runs the injection-screen agent against the governed MCP endpoint (and, when
# S1_RAW_URL is set, the raw upstream mock) to show the SAME tools/call — benign
# text passing through byte-identical, injected text withheld by the gateway.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -z "${S1_GW_URL:-}" ]]; then
  echo "S1_GW_URL is not set. Run:  source demo/env.local.sh" >&2
  exit 1
fi

echo "════════════════════════════════════════════════════════════════════════"
echo " MCP Tool-Result Injection Screen — live demo"
echo " governed endpoint: ${S1_GW_URL}"
[[ -n "${S1_RAW_URL:-}" ]] && echo " raw upstream     : ${S1_RAW_URL}"
echo "════════════════════════════════════════════════════════════════════════"
echo
python3 "${HERE}/agent.py" "${S1_GW_URL}"
