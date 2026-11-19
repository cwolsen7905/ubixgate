#!/usr/bin/env bash
# run-local.sh: the same demo without Docker. Builds uBixVault and uBixShepherd from
# their published sources, this checkout's gateway and demo services, starts them all on
# loopback in a temporary directory, runs ./demo.sh, and stops everything on exit.
#
#   examples/demo/run-local.sh
#
# Needs Go, git, curl and jq, and ports 8080, 8200, 9000 and 9100 free. Shepherd runs
# with its own home and daemon in the temporary directory, never touching ~/.shepherd.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=$(mktemp -d)
PIDS=()
cleanup() {
    SHEPHERD_HOME="$WORK/shepherd" SHEPHERD_NO_AUTOSTART=1 "$WORK/bin/shepherd" daemon stop >/dev/null 2>&1 || true
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
    wait 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

echo "building into $WORK/bin"
export GOBIN="$WORK/bin" CGO_ENABLED=0
go install github.com/cwolsen7905/ubixvault/cmd/ubixvault@v1.7.0   # uBixVault's module path
go install github.com/ubixsys/ubixshepherd/cmd/shepherd@v0.6.0-beta.1
(cd "$ROOT" && go build -o "$WORK/bin/" ./cmd/ubixgate ./examples/demo-idp ./examples/tickets)
export PATH="$WORK/bin:$PATH"

bg() { local log=$1; shift; "$@" > "$WORK/$log.log" 2>&1 & PIDS+=($!); }

mkdir -p "$WORK/vault" "$WORK/shared" "$WORK/audit" "$WORK/shepherd" "$WORK/workspace/web"
bg ubixvault ubixvault server -listen 127.0.0.1:8200 -data "$WORK/vault"
VAULT_ADDR=http://127.0.0.1:8200 SHARED="$WORK/shared" sh "$ROOT/examples/demo/vault-init.sh"

bg demo-idp env DEMO_IDP_ISSUER=http://127.0.0.1:9100 DEMO_IDP_AUDIENCE=http://localhost:8080/mcp \
    DEMO_IDP_LISTEN=127.0.0.1:9100 demo-idp
bg tickets env TICKETS_TOKEN_FILE="$WORK/shared/tickets-token" TICKETS_LISTEN=127.0.0.1:9000 tickets

# Shepherd: a private home, its daemon started here (not through launchd or systemd),
# and a one-repo workspace.
export SHEPHERD_HOME="$WORK/shepherd" SHEPHERD_NO_AUTOSTART=1
printf 'daemon:\n  listen: 127.0.0.1:0\n' > "$SHEPHERD_HOME/config.yaml"
bg shepherd shepherd daemon run
for _ in $(seq 1 40); do shepherd daemon status 2>/dev/null | grep -q 'running,' && break; sleep 0.25; done
git -C "$WORK/workspace/web" init -q -b main
git -C "$WORK/workspace/web" -c user.name=demo -c user.email=demo@example.com commit -q --allow-empty -m "first commit"
shepherd init "$WORK/workspace" --yes > /dev/null

# The compose config, pointed at loopback and the temporary directory.
sed -e 's#listen: ":8080"#listen: "127.0.0.1:8080"#' \
    -e 's#http://demo-idp:9100#http://127.0.0.1:9100#g' \
    -e 's#http://ubixvault:8200#http://127.0.0.1:8200#' \
    -e 's#http://tickets:9000#http://127.0.0.1:9000#' \
    -e "s#/shared/#$WORK/shared/#g" \
    -e "s#SHEPHERD_HOME: /data/shepherd#SHEPHERD_HOME: $SHEPHERD_HOME, SHEPHERD_NO_AUTOSTART: \"1\"#" \
    -e "s#path: /audit/audit.jsonl#path: $WORK/audit/audit.jsonl#" \
    "$ROOT/examples/demo/gateway.yaml" > "$WORK/gateway.yaml"
bg ubixgate ubixgate serve -config "$WORK/gateway.yaml"

cd "$ROOT"
AUDIT_LOG="$WORK/audit/audit.jsonl" SHARED="$WORK/shared" ./demo.sh
