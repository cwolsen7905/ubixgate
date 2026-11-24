#!/usr/bin/env bash
# hashicorp-vault.sh: run the gateway's Vault client, and the gateway itself, against a real
# HashiCorp Vault in a dev-mode container. Used by the hashicorp-vault CI job; runs anywhere
# with Docker. Publishes no host ports and uses its own network, so parallel runs do not
# collide.
#
# It prepares the server (KV v2, an AppRole with a short token TTL, and the database
# engine over a throwaway Postgres, which gives a real dynamic secret with a lease), then
# runs the TestHashiCorpVault Go test against it. The test covers: AppRole login, KV v2
# reads, the policy boundary, renewal of the gateway's token, a dynamic secret's lease and
# its revoke, and a call through the gateway that injects the KV v2 credential. After it,
# this script checks that the revoked lease's database user is gone.
#
# Everything here is throwaway: the root token and passwords are fixed demo values for a
# container that lives for one run on a private network.
set -euo pipefail

suffix="${CI_JOB_ID:-local$$}"
net="ubixgate-hcv-$suffix"
vault_c="ubixgate-hcv-vault-$suffix"
pg_c="ubixgate-hcv-pg-$suffix"
VAULT_IMAGE="${VAULT_IMAGE:-hashicorp/vault:1.18}"
PG_IMAGE="${PG_IMAGE:-postgres:16-alpine}"
GO_IMAGE="${GO_IMAGE:-golang:1.27}"
root=hcv-dev-root
kv_token="kv-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
work=$(mktemp -d) # outside the checkout; holds the throwaway AppRole credentials

cleanup() {
	local rc=$?
	if [ "$rc" != 0 ]; then
		echo "hashicorp-vault: failed; the last lines of the Vault log follow."
		docker logs --tail 40 "$vault_c" 2>&1 || true
	fi
	docker rm -f "$vault_c" "$pg_c" >/dev/null 2>&1 || true
	docker network rm "$net" >/dev/null 2>&1 || true
	rm -rf "$work"
	exit "$rc"
}
trap cleanup EXIT

vault() { docker exec -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN="$root" "$vault_c" vault "$@"; }
# Like vault, but passes this script's standard input on (docker exec drops it without -i).
vault_in() { docker exec -i -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN="$root" "$vault_c" vault "$@"; }

docker network create "$net" >/dev/null
docker run -d --name "$pg_c" --network "$net" --network-alias pg \
	-e POSTGRES_PASSWORD=pgpass "$PG_IMAGE" >/dev/null
docker run -d --name "$vault_c" --network "$net" --network-alias vault --cap-add IPC_LOCK \
	-e VAULT_DEV_ROOT_TOKEN_ID="$root" -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
	"$VAULT_IMAGE" server -dev >/dev/null

for _ in $(seq 1 60); do
	vault status >/dev/null 2>&1 && break
	sleep 1
done
vault status | grep -E '^(Version|Sealed)'
for _ in $(seq 1 60); do
	docker exec "$pg_c" pg_isready -U postgres -h 127.0.0.1 >/dev/null 2>&1 && break
	sleep 1
done
docker exec "$pg_c" pg_isready -U postgres -h 127.0.0.1

# KV v2 is mounted at secret/ by dev mode. One secret the gateway may read, one it may not.
vault kv put secret/mcp/tickets token="$kv_token" >/dev/null
vault kv put secret/other/private token=nope >/dev/null

# A dynamic secret: the database engine over the Postgres container.
vault secrets enable database >/dev/null
vault write database/config/pg plugin_name=postgresql-database-plugin allowed_roles=app \
	connection_url='postgresql://{{username}}:{{password}}@pg:5432/postgres?sslmode=disable' \
	username=postgres password=pgpass >/dev/null
vault write database/roles/app db_name=pg default_ttl=5m max_ttl=10m \
	creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';" \
	revocation_statements="DROP ROLE IF EXISTS \"{{name}}\";" >/dev/null

# What the gateway's identity may do: read the MCP credentials and one database role, and
# revoke leases. Its token lives 6 seconds unless renewed (the AppRole login is the
# configured method).
vault_in policy write ubixgate - >/dev/null <<'EOF'
path "secret/data/mcp/*"       { capabilities = ["read"] }
path "database/creds/app"      { capabilities = ["read"] }
path "sys/leases/revoke"       { capabilities = ["update"] }
EOF
vault auth enable approle >/dev/null
vault write auth/approle/role/ubixgate token_policies=ubixgate token_ttl=6s token_max_ttl=10m secret_id_num_uses=1 >/dev/null
vault read -field=role_id auth/approle/role/ubixgate/role-id >"$work/role_id"
# Each secret ID works once, so a client cannot quietly log in again: the token renewal
# test fails if renew-self does not work. The client and the gateway get one each.
vault write -f -field=secret_id auth/approle/role/ubixgate/secret-id >"$work/secret_id"
vault write -f -field=secret_id auth/approle/role/ubixgate/secret-id >"$work/gateway_secret_id"
chmod 755 "$work"
chmod 644 "$work/role_id" "$work/secret_id" "$work/gateway_secret_id"

mkdir -p "$HOME/.cache/ubixgate-go"
docker run --rm --network "$net" -v "$PWD:/src" -v "$work:/creds:ro" -w /src --user "$(id -u):$(id -g)" \
	-v "$HOME/.cache/ubixgate-go:/cache" \
	-e HOME=/tmp -e GOCACHE=/cache/build -e GOMODCACHE=/cache/mod -e GOFLAGS=-buildvcs=false \
	-e HCVAULT_ADDR=http://vault:8200 \
	-e HCVAULT_ROLE_ID_FILE=/creds/role_id \
	-e HCVAULT_SECRET_ID_FILE=/creds/secret_id -e HCVAULT_GATEWAY_SECRET_ID_FILE=/creds/gateway_secret_id \
	-e HCVAULT_ROOT="$root" -e HCVAULT_KV_TOKEN="$kv_token" -e HCVAULT_DB_PATH=database/creds/app \
	"$GO_IMAGE" go test -count=1 -v -run TestHashiCorpVault ./test | tee hashicorp-vault-output.txt

for want in "--- PASS: TestHashiCorpVault/kv2_read" "--- PASS: TestHashiCorpVault/token_renewal" \
	"--- PASS: TestHashiCorpVault/dynamic_lease_and_revoke" "--- PASS: TestHashiCorpVault/gateway_injects_the_kv2_credential"; do
	grep -qF -- "$want" hashicorp-vault-output.txt || { echo "hashicorp-vault: missing \"$want\""; exit 1; }
done

# The revoke must have dropped the database user the lease created.
left=$(docker exec "$pg_c" psql -U postgres -h 127.0.0.1 -Atc "select count(*) from pg_roles where rolname like 'v-%'")
[ "$left" = 0 ] || { echo "hashicorp-vault: $left database user(s) left after the revoke"; exit 1; }
echo "hashicorp-vault: the gateway worked against HashiCorp Vault (KV v2, AppRole, token renewal, lease and revoke)."
