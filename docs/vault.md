# Using uBixGate with a Vault server

uBixGate reads upstream credentials from a server that speaks the Vault HTTP API. Two are
tested: uBixVault and HashiCorp Vault. This page lists what the gateway needs from the
server and what the tests cover.

## What the gateway uses

| API | Used for |
|---|---|
| `POST auth/<mount>/login` | Logging in with `approle` or `kubernetes` |
| `GET auth/token/lookup-self` | Reading a `token` login's TTL |
| `POST auth/token/renew-self` | Renewing the gateway's own token at half its TTL; if that fails it logs in again |
| `GET <path>` | Reading a secret. KV v2 (`data` and `metadata` nested under `data`) is unwrapped |
| `PUT sys/leases/revoke` | Revoking a dynamic secret's lease once the gateway stops using it |
| `GET sys/health` | Readiness. 200, 429 and 473 count as healthy (the active node and standby nodes serve client requests); 472 (a disaster-recovery secondary), 501 and 503 do not |

The gateway never renews a dynamic secret's lease. It caps its cache at the lease and reads
a new credential when the old one expires.

## Where a lease is found

HashiCorp Vault puts `lease_id` and `lease_duration` at the top level of the response. uBixVault's
database engine puts them inside `data`. The gateway accepts either. A KV secret carries a
`lease_duration` too (a default TTL hint, no `lease_id`); the credential's own `ttl` setting
still caps the cache.

## A policy for the gateway's identity

Grant the least that works. For KV v2 secrets under `mcp/`, one database role and lease
revocation:

```hcl
path "secret/data/mcp/*"  { capabilities = ["read"] }
path "database/creds/app" { capabilities = ["read"] }
path "sys/leases/revoke"  { capabilities = ["update"] }
```

Renewing its own token needs no grant: Vault's `default` policy allows it.

## What CI covers

The `hashicorp-vault` job (`bin/ci/hashicorp-vault.sh`) starts a HashiCorp Vault dev-mode
container and a throwaway Postgres on a private Docker network, then runs the
`TestHashiCorpVault` Go test against them. It checks:

- AppRole login, with a token TTL of a few seconds and single-use secret IDs, so the renewal check below cannot pass by logging in again;
- KV v2 reads, a missing secret, and a path the policy forbids;
- renewal: reads keep working after the token's original TTL has passed;
- a database credential: the lease ID and duration arrive in the envelope, the lease exists,
  `Revoke` removes it, and the database user it created is dropped;
- a full gateway, built against that Vault, injecting the KV v2 credential into an upstream call.

Not covered against a real HashiCorp server: the `kubernetes` and `token` logins (fake
servers only), a sealed or standby node, namespaces, and Vault Enterprise features. The
gateway sends no `X-Vault-Namespace` header.
