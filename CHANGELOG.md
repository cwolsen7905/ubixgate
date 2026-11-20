# Changelog

All notable changes to uBixGate are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/) as described in
[docs/VERSIONING.md](docs/VERSIONING.md). While uBixGate is in beta, a change to a public
interface is listed under **Interface changes** in the release that makes it.

## [Unreleased]

### Added

- Requests from an upstream to the caller's client (elicitation, sampling, roots) pass
  through to the calling client under MCP 2026-07-28, when a policy rule with
  `client_requests` allows that kind for that tool. Each is audited as its own record.
  The upstream's request state is sealed to the user, tool and arguments, expires after
  10 minutes, and is refused for anyone else (`invalid-request-state`). Clients and upstreams on
  2025-11-25 are refused them. `request_state_key_file` shares the sealing key across
  replicas.
- A tamper-evident audit log: with `audit.chain_key_file`, each record carries an
  HMAC chained over the one before, continued across restarts, and
  `ubixgate audit verify` names the first edited, removed, inserted or reordered line.
  Lines deleted from the end are not detectable from the file alone.
- Unused dynamic-secret leases are revoked: when the cache replaces or drops a
  credential (after a grace period of the longest upstream timeout, so calls already
  sent can finish), when a stdio process holding one stops, at shutdown, and at once
  when a lease is issued without the configured field.
- `ubixgate policy explain`: the decision, deciding rule, what the caller is shown,
  whether the tool is listed and which arguments are logged, for a user, groups, client,
  tool and arguments, without a live call. It runs the same decision step as the gateway.
- Per-user upstream credentials: an HTTP upstream's `credential.path` may contain
  `{user}`, so each call uses the caller's own secret and the upstream sees the person.
  A caller without one is refused (status `denied`, reason `credential_unavailable`),
  never given the shared credential. `catalog_path` is the shared secret used only to
  connect and list tools.

### Changed

- The README's demo transcript is now the Docker Compose demo's real output, as CI
  captures it, instead of the loopback runner's.

### Fixed

- A dynamic secret's lease now caps the credential cache against uBixVault, which sends
  `lease_id` and `lease_duration` inside `data` rather than in the envelope. Before, the
  configured TTL applied, so a lease shorter than it could be served after it expired.

### Interface changes

- Policy rules take `client_requests`. A rule with it decides only those requests; a
  rule without it, as before, decides only calls.
- Audit records gain `client_request`, the statuses `input_required` and `not_sent`, and
  the reasons `client_request_denied` and `client_protocol`.
- Audit records may end with a `chain` field. Config: `audit.chain_key_file`.
- Config: `credential.catalog_path`. A `{user}` path is rejected on stdio upstreams.
- Upstreams no longer see the gateway declare the roots capability; it declares no
  client capabilities of its own.

## [0.1.0-beta.1] - 2026-11-19

The first public beta: one authenticated MCP endpoint in front of many MCP servers, with
per-call policy, credential injection from Vault and an audit record for every call. It
has had no independent security review; see the README's security model before relying
on it.

### Added

- `ubixgate serve`: a Streamable HTTP MCP endpoint (stateless) that accepts protocol
  revisions 2026-07-28 and 2025-11-25 from clients, in front of HTTP and stdio upstreams.
  Upstreams are spoken to in whatever revision they support, down to 2025-11-25. Tools are
  named `server__tool`.
- Authentication with OIDC access tokens: RS256 and ES256 only, issuer, audience equal to
  the gateway's URL, `exp` and `nbf` with 60 seconds of skew, a JWKS cache that picks up
  key rotation. JWT validation uses only the Go standard library. A static token mode for
  local development, refused on non-loopback addresses. RFC 9728 protected resource
  metadata, linked from every 401.
- A deny-by-default policy of named rules, matched on user, group, client, server, tool
  globs and top-level string argument globs. Deny rules are checked first; the first match
  decides. Each caller's `tools/list` shows only the tools they may call, with
  `cacheScope: private`. Denials name the deciding rule. The policy reloads on SIGHUP.
- Credential injection from a Vault-API server, tested against uBixVault (HashiCorp Vault
  speaks the same API but is not tested in this release), logged in with a token, AppRole
  or Kubernetes, renewed at half its TTL. HTTP upstreams get the
  credential as a header on every request, with one retry after a 401; stdio upstreams get
  it as an environment variable at start and are restarted when it expires. Reads are
  cached per credential, shared across concurrent calls, capped by the secret's lease and
  never served past expiry. The caller's own token is never forwarded.
- One JSON-lines audit record per tool call with request ID, user, groups, client,
  declared client, tool, decision, deciding rule, status, reason and latency. Argument
  values are redacted unless the deciding rule keeps them, or replaced by an HMAC.
- A per-user call limit (in memory, per replica).
- `/healthz`, `/readyz` (upstreams connected and Vault healthy), Prometheus `/metrics`,
  JSON logs, `ubixgate check` to validate a config.
- A container image, `ghcr.io/ubixsys/ubixgate`: distroless, non-root, for linux/amd64 and
  linux/arm64, signed with keyless cosign.
- A Helm chart in `deploy/charts/ubixgate`: a Deployment from the gateway's config as a
  value, a Service, and optionally an Ingress that exposes only the MCP endpoint and its
  protected resource metadata, a ServiceMonitor and a PodDisruptionBudget. Config changes
  roll the pods. It runs the published image by default.
- A demo: Docker Compose with uBixVault, a toy identity provider, a fake ticket tracker
  and uBixShepherd as a stdio upstream; `examples/demo/run-local.sh` runs the same demo
  without Docker; `demo.sh` walks through it with curl. CI runs the Compose demo on every
  change and checks its outcomes.
- Release tooling: `make check`, cross builds for six platforms, signed checksums, and
  release notes from this file. Releases are published only at
  https://github.com/ubixsys/ubixgate/releases.
