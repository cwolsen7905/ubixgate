# uBixGate

An open-source gateway for the Model Context Protocol (MCP), written in Go.

Coding agents such as Claude Code, Cursor and OpenCode connect to one URL. Behind it,
uBixGate fronts any number of MCP servers and, for every tool call, answers four
questions:

| Question | How uBixGate answers it |
|---|---|
| Who is calling? | An OIDC access token, validated against your identity provider's keys |
| What may they use? | A deny-by-default rule list. Each caller only sees the tools they may call |
| Where does the upstream's credential come from? | Vault, read at call time. The agent never holds it |
| What did they do? | One JSON audit line per call: who, which tool, the decision, the rule that made it |

**Status: beta (`0.1.0-beta.1`).** It works end to end and is tested,
but it has had **no independent security review**, and its config format, audit fields
and metrics may still change between betas. Read [What it does not protect against](#what-it-does-not-protect-against)
before putting it in front of anything that matters.

**MCP revision:** targets **2026-07-28** and also accepts **2025-11-25** from clients.
Upstream servers are spoken to in whatever revision they support, down to 2025-11-25.

## Why

Once a team gives agents MCP servers, three problems show up together. Every agent
config carries its own copy of each server's API token. Everyone gets every tool, because
MCP servers rarely know who is calling. And nobody can say afterwards which person's agent
did what. uBixGate moves all three to one place: tokens stay in Vault, access is a reviewed
YAML file, and the audit log names the person, not just "the agent".

## How it works

```
 Claude Code ---+                                    +--> tickets  (HTTP, gets a header)
 Cursor --------+--> uBixGate  /mcp  ---------------+--> shepherd (stdio, gets an env var)
 your agent ----+    1 authenticate (JWT)            +--> ...
                     2 filter the catalog
                     3 authorize the call            reads keys from:   your IdP (JWKS)
                     4 inject the credential         reads secrets:     uBixVault or Vault
                     5 forward, then audit           writes:            audit.jsonl
```

For each `tools/call`, in one place:

1. **Authenticate.** The bearer token must be an RS256 or ES256 JWT signed by a key in the
   issuer's JWKS, with the right issuer, an audience equal to the gateway's own URL, and a
   valid `exp` and `nbf` (60 seconds of skew). `alg: none` and HS* are refused. A failure
   is a 401 that points the client at the gateway's
   [protected resource metadata](https://datatracker.ietf.org/doc/html/rfc9728).
2. **Route.** Tool names are `server__tool` (`tickets__ticket_create`). The gateway knows
   which upstream owns each one.
3. **Authorize.** The policy decides. A denial is returned as a tool error naming the rule:
   `denied by rule contractors-no-writes`. A per-user call limit applies here too.
4. **Inject and forward.** The upstream's credential is read from Vault (cached briefly)
   and attached: as a header for HTTP upstreams, as an environment variable when a stdio
   upstream is started. **The caller's own token is never sent upstream.**
5. **Audit.** Exactly one record per call, whatever the outcome.

`tools/list` runs authentication and the policy too: each caller gets only the tools some
rule would let them call, marked `cacheScope: private` so clients do not share the list.

## Try it in five minutes

You need Go 1.26 or later, git, curl and jq. With Docker:

```sh
docker compose -f examples/demo/compose.yaml up -d --build
./demo.sh
```

Without Docker, the same demo on loopback, built from published sources:

```sh
examples/demo/run-local.sh
```

The demo runs [uBixVault](https://github.com/ubixsys/ubixvault) (initialised and unsealed
by a one-shot script), a toy identity provider that mints real signed tokens for `alice`
(developers) and `bob` (contractors), a fake ticket tracker that refuses any request
without a service token stored in Vault, and [uBixShepherd](https://github.com/ubixsys/ubixshepherd)
as a stdio upstream. `demo.sh` speaks MCP with plain curl so every request is visible.

This is the real output of the Docker Compose demo (uBixVault 1.7.0, uBixShepherd
0.6.0-beta.1), as CI captured it on 2026-11-20. CI runs the Compose demo on every change
(`bin/ci/demo-compose.sh`), fails unless the 401, the service-token call and both denials
appear, and keeps the output as the job's `demo-output.txt` artifact.
`examples/demo/run-local.sh` runs the same script against the same config without Docker;
only the latencies differ.

```
== 0. No token, no entry
  HTTP/1.1 401 Unauthorized
  Www-Authenticate: Bearer resource_metadata="http://localhost:8080/.well-known/oauth-protected-resource/mcp"

== 1. Alice (developers) and Bob (contractors) get tokens from the IdP, and see different tools
alice sees:
  shepherd__lane_list
  shepherd__run_list
  shepherd__shepherd_status
  tickets__ticket_create
  tickets__ticket_delete
  tickets__ticket_list
bob sees:
  shepherd__lane_list
  shepherd__run_list
  shepherd__shepherd_status

== 2. Alice opens a ticket. The tracker requires a service token that only Vault and the gateway hold
  authenticated as svc-tickets: created ticket in myorg/web
  The service token appears nowhere in what Alice received, nor in this script's environment.

== 3. Alice reads Shepherd, a stdio upstream the gateway runs as a child process
  No open lanes. Open one with: shepherd lane open <name> --scope '<globs>'

== 4. Denials name the rule that decided
bob deletes a ticket:
  ERROR: denied by rule contractors-no-writes
alice deletes a ticket outside myorg/:
  ERROR: denied by rule default-deny

== 5. The audit log: one line per call, argument values redacted unless a rule keeps them
{"user":"alice","tool":"tickets__ticket_create","decision":"allow","rule":"devs-tickets-own-project","status":"ok","latency_ms":1,"args":{"project":"myorg/web","title":"[redacted]"}}
{"user":"alice","tool":"shepherd__lane_list","decision":"allow","rule":"devs-read-shepherd","status":"ok","latency_ms":1,"args":null}
{"user":"bob","tool":"tickets__ticket_delete","decision":"deny","rule":"contractors-no-writes","status":"denied","latency_ms":0,"args":{"id":"[redacted]","project":"[redacted]"}}
{"user":"alice","tool":"tickets__ticket_delete","decision":"deny","rule":"default-deny","status":"denied","latency_ms":0,"args":{"id":"[redacted]","project":"[redacted]"}}
```

To use the demo gateway from Claude Code while the stack is running:

```sh
claude mcp add --transport http ubixgate http://localhost:8080/mcp \
  --header "Authorization: Bearer $(curl -s 'localhost:9100/token?user=alice&client=claude-code')"
```

## Configure

One YAML file. Unknown keys are errors, and `ubixgate check FILE` validates a file
without starting anything. The demo's [gateway.yaml](examples/demo/gateway.yaml) is a
complete, commented example.

```yaml
listen: ":8080"
public_url: https://mcp.example.com/mcp   # the endpoint clients use, and the required token audience

identity:
  mode: jwt                                # or static: fixed tokens, loopback only, for local development
  issuer: https://idp.example.com
  jwks_url: https://idp.example.com/jwks
  claims: { user: email, groups: groups, client: azp }

vault:                                     # uBixVault (HashiCorp Vault: untested)
  address: https://vault.example.com
  auth: { method: approle, role_id_file: /run/role_id, secret_id_file: /run/secret_id }
  # or: { method: kubernetes, role: ubixgate }  or: { method: token, token_file: ... }

upstreams:
  - name: tickets                          # becomes the tool prefix: tickets__...
    transport: http
    url: http://tickets:9000/mcp
    credential: { path: secret/data/mcp/tickets, field: token, format: "Bearer {value}", ttl: 60s }
  - name: shepherd
    transport: stdio
    command: [shepherd, mcp]
    env: { SHEPHERD_HOME: /data/shepherd }
    # credential: { path: ..., field: ..., env: SOME_TOKEN }   # stdio: passed as an env var

limits: { per_user_per_minute: 120 }       # in memory, per replica
audit: { sink: file, path: /var/log/ubixgate/audit.jsonl }   # or sink: stdout
```

Keep upstream names short: some clients limit tool names to 64 characters, and the prefix
counts.

### Policy

Rules have a name, because the name is what a denial and the audit log show.

```yaml
policy:
  rules:
    - name: contractors-no-writes
      effect: deny
      when: { groups: [contractors] }
      server: "*"
      tools: ["*_create", "*_delete"]

    - name: devs-tickets-own-project
      effect: allow
      when: { groups: [developers], clients: [claude-code, cursor] }
      server: tickets
      tools: ["*"]
      args: { project: "myorg/*" }   # top-level string arguments, glob matched
      audit_args: [project]          # these values are logged; all others are redacted
```

| Rule of evaluation | Detail |
|---|---|
| Order | Deny rules first, then allow rules, each in file order. The first match decides. |
| Default | Nothing matches: denied by the built-in rule `default-deny`. |
| Matching | A rule matches when every field it sets matches. `when.users`, `when.groups` and `when.clients` match any listed value. |
| Globs | `*` matches any run of characters except `/`; `?` one character; `[...]` a class. |
| Arguments | Each argument named in `args` must be present, a string, and match. |
| Listing | A tool is listed if an allow rule matches it (ignoring `args`) and no deny rule without `args` matches it. So a listed tool can still be denied for its arguments. |
| Unknown tools | Answered as the policy would answer that name, so probing reveals nothing beyond your own list. The audit log records `unknown-tool`. |
| Reload | `SIGHUP` reloads the policy atomically. A file that fails validation is logged and ignored. Other changes need a restart. |

### Audit records

One JSON object per line. Field names are a versioned interface.

| Field | Meaning |
|---|---|
| `time`, `request_id` | When, and an ID also returned to the client in the result's `_meta` |
| `user`, `groups`, `client` | From the token. `client` comes from a signed claim |
| `client_declared` | What the client says it is. Recorded, never trusted |
| `server`, `tool` | The upstream and the full tool name |
| `decision`, `rule` | `allow` or `deny`, and the rule that decided |
| `status`, `reason` | `ok`, `tool_error`, `upstream_error`, `timeout` or `denied`; a reason such as `credential_unavailable` |
| `latency_ms` | Time spent in the gateway, including the upstream |
| `args` | Argument keys, with values `[redacted]` unless the rule's `audit_args` keeps them. With `audit.hash_args: true` and a `hash_key_file`, values become an HMAC so equal values can be correlated |

Requests that fail authentication get no audit record (there is no verified caller to
name). They are counted in `ubixgate_auth_failures_total` and logged.

## Run it

```sh
make build                                   # bin/ubixgate
bin/ubixgate check ubixgate.yaml
bin/ubixgate serve -config ubixgate.yaml     # -log-level debug for more
docker build -t ubixgate .                   # distroless, non-root; or use the released
                                             # ghcr.io/ubixsys/ubixgate:<version>
```

| Endpoint | Purpose |
|---|---|
| `<public_url path>` (`/mcp`) | The MCP endpoint, Streamable HTTP, stateless |
| `/.well-known/oauth-protected-resource/mcp` | RFC 9728 metadata naming the issuer |
| `/healthz` | The process is up |
| `/readyz` | Every upstream connected and listed, and Vault healthy; otherwise 503 naming what is not |
| `/metrics` | Prometheus: `ubixgate_tool_calls_total{server,decision,status}`, `ubixgate_tool_call_duration_seconds`, `ubixgate_auth_failures_total`, `ubixgate_upstream_up` |

Logs are JSON on stderr (`log/slog`). Grant the gateway's Vault identity read access to
exactly the configured credential paths, nothing else.

In Kubernetes, use the Helm chart in [deploy/charts/ubixgate](deploy/charts/ubixgate/README.md).
It takes the config above as a value, exposes only the MCP endpoint and its metadata on
the Ingress, and logs in to Vault with the pod's service account. It runs the image each
release publishes, `ghcr.io/ubixsys/ubixgate` (amd64 and arm64, signed with keyless
cosign; see [docs/RELEASING.md](docs/RELEASING.md#verifying-a-download)).

## Security model

uBixGate is a policy and attribution point for agents acting on behalf of authenticated
people. It assumes the agents are honest but fallible. It is not a sandbox: a call the
policy allows can still do everything that call can do.

### What it protects against

| Threat | How |
|---|---|
| An agent or a prompt leaking an upstream's token | The agent never receives it. It lives in Vault and in the gateway's memory |
| A user calling tools outside their role | Deny by default, checked on every call on the server side, not only in the listing |
| Finding out which tools exist | Each caller sees only their own tools; hidden and unknown tools are refused alike |
| Forged tokens, or tokens minted for another service | Signature, issuer, expiry and audience are checked; only RS256 and ES256 |
| The gateway acting as a confused deputy | The caller's token is never forwarded upstream |
| Not knowing who did what | One audit record per call with the person, client and deciding rule |
| One user exhausting an upstream | A per-user call limit |

### What it does not protect against

- **Prompt injection and hostile tool output.** Results are passed back unmodified. A tool
  can return text that steers the agent, or echo back a secret it holds.
- **Misuse within an allowed scope.** If a rule allows `project: myorg/*`, the caller may
  delete every ticket in `myorg`.
- **Arguments the upstream reads differently than the glob.** **Globs match the raw
  string. If an upstream normalises `myorg/..` or decodes `%2F`, an argument constraint can
  be bypassed. A constraint is only as strong as the upstream's own parsing.**
- **A compromised upstream.** It holds its injected credential and sees every call routed
  to it.
- **A compromised gateway host.** It holds a Vault token and cached credentials for every
  upstream. Scope its Vault policy tightly.
- **A user posing as another client.** The client name comes from a signed claim, but a
  user can run any program with their own token. Treat `client` as attribution, not a
  boundary, unless your IdP issues per-client tokens.
- **Shared state inside stdio upstreams.** One process serves every caller. If it keeps
  state between calls, users can see each other's effects there.
- **Tampering with the audit log by someone with file access.** The file is opened
  append-only, not made tamper-evident. Ship it off the host if that matters.
- **Denial of service** beyond the per-user limit, which is per replica.
- Anything an independent review would catch: **there has been none.**

## Limits of this beta

| Area | State |
|---|---|
| Vault servers | Tested against uBixVault (1.7.0, in CI through the Compose demo). HashiCorp Vault serves the same API but is untested; testing it is planned for a later release |
| Upstream credentials | One service credential per upstream. Upstream logs see the gateway, not the person; the audit log is the per-user record. Per-user credentials are on the roadmap |
| Policy engine | The YAML rules only. The evaluator sits behind one interface so another engine could be added |
| Leases | Dynamic secrets are read and their lease caps the cache, but leases are not revoked when unused; keep their TTLs short |
| Server-to-client requests | Not passed through (sampling, elicitation, roots). Upstream tools that need them will fail |
| Identity | OIDC JWTs. No SAML or SCIM |
| Not included | Admin UI, multi-tenancy, response filtering, plugins, rate limiting beyond the per-user limit |
| Platforms | Linux and macOS are tested. Windows builds and is untested |

## Develop

```sh
make check    # gofmt, vet, golangci-lint, prose style, size budget, tests with -race
```

The whole gateway is under 4,000 lines of non-test Go, and `make size-check` keeps it
that way: it should be readable in an afternoon. Start with
[internal/gateway/gateway.go](internal/gateway/gateway.go), which runs every call.

| Package | Job |
|---|---|
| `internal/identity` | JWT and static-token validation, JWKS cache, resource metadata |
| `internal/policy` | Rule matching and catalog filtering |
| `internal/secrets` | Vault-API client and credential cache |
| `internal/upstream` | stdio and HTTP upstream clients, credential injection |
| `internal/gateway` | The MCP front and the per-call steps; assembly from config |
| `internal/audit` | Records, redaction, the JSON-lines sink |
| `internal/config`, `internal/ops` | The YAML file; health, readiness, metrics, logging |
| `test/` | End-to-end tests with an in-process IdP, Vault and upstreams over both transports and both protocol revisions |

Built on the official [MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk). Its
only other direct dependencies are a YAML parser and the Prometheus client; JWT
validation uses the standard library.

Releases and versioning: [docs/RELEASING.md](docs/RELEASING.md),
[docs/VERSIONING.md](docs/VERSIONING.md). Changes: [CHANGELOG.md](CHANGELOG.md).

## License

BSD 3-Clause, see [LICENSE](LICENSE). The uBix names and logos are covered by
[TRADEMARKS.md](TRADEMARKS.md).
