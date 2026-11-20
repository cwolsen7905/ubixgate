#!/bin/sh
# vault-init.sh: prepare uBixVault for the demo. uBixVault has no dev mode, so this
# initialises it with two unseal key shares, unseals it, stores the tickets service token,
# and creates an AppRole the gateway logs in with.
#
# DEMO ONLY: the unseal keys and the root token are written to $SHARED in plain files.
# Never initialise a real vault like this.
#
# Environment: VAULT_ADDR (default http://ubixvault:8200), SHARED (default /shared).
# Writes: $SHARED/role_id, $SHARED/secret_id (for the gateway), $SHARED/tickets-token
# (for the fake tickets server only), $SHARED/init.json (keys, demo only).
# Needs: sh, curl, jq. Safe to run again: it reuses an existing initialisation.
set -eu

VAULT_ADDR="${VAULT_ADDR:-http://ubixvault:8200}"
SHARED="${SHARED:-/shared}"
mkdir -p "$SHARED"

api() { # api METHOD PATH [JSON]: call Vault with the root token, fail on HTTP errors
    curl -fsS -X "$1" -H "X-Vault-Token: ${ROOT:-}" ${3:+-d "$3"} "$VAULT_ADDR/v1/$2"
}

echo "vault-init: waiting for $VAULT_ADDR"
i=0
until curl -s -o /dev/null "$VAULT_ADDR/v1/sys/seal-status"; do
    i=$((i + 1)); [ "$i" -lt 60 ] || { echo "vault-init: Vault did not come up"; exit 1; }
    sleep 1
done

if [ "$(curl -s "$VAULT_ADDR/v1/sys/seal-status" | jq -r .initialized)" != true ]; then
    echo "vault-init: initialising (keys kept in $SHARED: demo only)"
    curl -fsS -X POST -d '{"secret_shares":2,"secret_threshold":2}' "$VAULT_ADDR/v1/sys/init" > "$SHARED/init.json"
    chmod 600 "$SHARED/init.json"
fi
ROOT=$(jq -r .root_token "$SHARED/init.json")

if [ "$(curl -s "$VAULT_ADDR/v1/sys/seal-status" | jq -r .sealed)" = true ]; then
    echo "vault-init: unsealing"
    for key in $(jq -r '.keys[]' "$SHARED/init.json"); do
        curl -fsS -X POST -d "{\"key\":\"$key\"}" "$VAULT_ADDR/v1/sys/unseal" > /dev/null
    done
fi

# The tickets service token: random, written to Vault and to a file only the fake
# tickets server reads. Demo users never see it.
if [ ! -s "$SHARED/tickets-token" ]; then
    head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$SHARED/tickets-token"
fi
TOKEN=$(cat "$SHARED/tickets-token")
api POST secret/data/mcp/tickets "{\"data\":{\"token\":\"$TOKEN\"}}" > /dev/null
echo "vault-init: stored secret/mcp/tickets"

# The gateway may read exactly the MCP credentials, nothing else.
api PUT sys/policies/acl/ubixgate '{"policy":"path \"secret/data/mcp/*\" { capabilities = [\"read\"] }"}' > /dev/null
api POST auth/approle/role/ubixgate '{"token_policies":["ubixgate"],"token_ttl":"1h","token_max_ttl":"24h"}' > /dev/null
api GET auth/approle/role/ubixgate/role-id | jq -r .data.role_id > "$SHARED/role_id"
api POST auth/approle/role/ubixgate/secret-id '{}' | jq -r .data.secret_id > "$SHARED/secret_id"
chmod 644 "$SHARED/role_id" "$SHARED/secret_id" "$SHARED/tickets-token"
echo "vault-init: AppRole ubixgate ready (policy: read secret/data/mcp/*)"
