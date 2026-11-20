#!/usr/bin/env bash
# demo.sh: the uBixGate story in five steps, against a running demo stack.
#
#   docker compose -f examples/demo/compose.yaml up -d --build
#   ./demo.sh
#
# It speaks MCP with plain curl so every request is visible. Needs bash, curl and jq.
# Override GATEWAY, IDP, AUDIT_LOG or SHARED to point it at a stack run another way.
set -euo pipefail

GATEWAY="${GATEWAY:-http://localhost:8080/mcp}"
IDP="${IDP:-http://localhost:9100}"
AUDIT_LOG="${AUDIT_LOG:-examples/demo/out/audit/audit.jsonl}"
SHARED="${SHARED:-examples/demo/out/shared}"
PROTO=2026-07-28
TRANSCRIPT=$(mktemp)
trap 'rm -f "$TRANSCRIPT"' EXIT

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

# mcp TOKEN METHOD NAME PARAMS: one JSON-RPC request; the response is appended to the
# transcript and printed.
mcp() {
    local body
    body=$(jq -cn --arg m "$2" --argjson p "$4" --arg v "$PROTO" \
        '{jsonrpc:"2.0", id:1, method:$m, params:($p + {_meta:{"io.modelcontextprotocol/protocolVersion":$v,
          "io.modelcontextprotocol/clientCapabilities":{}, "io.modelcontextprotocol/clientInfo":{name:"demo.sh",version:"1"}}})}')
    curl -fsS "$GATEWAY" -H "Authorization: Bearer $1" -H 'Content-Type: application/json' \
        -H 'Accept: application/json, text/event-stream' -H "MCP-Protocol-Version: $PROTO" \
        -H "Mcp-Method: $2" ${3:+-H "Mcp-Name: $3"} -d "$body" | tee -a "$TRANSCRIPT"
}
list() { mcp "$1" tools/list "" '{}' | jq -r '.result.tools[].name' | sed 's/^/  /'; }
call() { mcp "$1" tools/call "$2" "$(jq -cn --arg n "$2" --argjson a "$3" '{name:$n, arguments:$a}')" |
    jq -r '.result | (if .isError then "  ERROR: " else "  " end) + ([.content[].text] | join(" "))'; }

for _ in $(seq 1 60); do curl -fs "${GATEWAY%/mcp}/readyz" >/dev/null && break; sleep 1; done
curl -fs "${GATEWAY%/mcp}/readyz" >/dev/null || { echo "the gateway is not ready at ${GATEWAY%/mcp}/readyz"; exit 1; }
start_line=$(( $(wc -l < "$AUDIT_LOG" 2>/dev/null || echo 0) + 1 ))

say "0. No token, no entry"
curl -s -o /dev/null -D - "$GATEWAY" -X POST -d '{}' | grep -iE '^(HTTP|www-authenticate)' | sed 's/^/  /'

say "1. Alice (developers) and Bob (contractors) get tokens from the IdP, and see different tools"
ALICE=$(curl -fsS "$IDP/token?user=alice")
BOB=$(curl -fsS "$IDP/token?user=bob")
echo "alice sees:"; list "$ALICE"
echo "bob sees:"; list "$BOB"

say "2. Alice opens a ticket. The tracker requires a service token that only Vault and the gateway hold"
call "$ALICE" tickets__ticket_create '{"project":"myorg/web","title":"Login button does nothing"}'
SERVICE_TOKEN=$(cat "$SHARED/tickets-token")
if grep -qF "$SERVICE_TOKEN" "$TRANSCRIPT" || env | grep -qF "$SERVICE_TOKEN"; then
    echo "  FAIL: the service token reached the client"; exit 1
fi
echo "  The service token appears nowhere in what Alice received, nor in this script's environment."

say "3. Alice reads Shepherd, a stdio upstream the gateway runs as a child process"
call "$ALICE" shepherd__lane_list '{}'

say "4. Denials name the rule that decided"
echo "bob deletes a ticket:"
call "$BOB" tickets__ticket_delete '{"project":"myorg/web","id":1}'
echo "alice deletes a ticket outside myorg/:"
call "$ALICE" tickets__ticket_delete '{"project":"other/repo","id":1}'

say "5. The audit log: one line per call, argument values redacted unless a rule keeps them"
tail -n +"$start_line" "$AUDIT_LOG" | jq -c '{user, tool, decision, rule, status, latency_ms, args}'
