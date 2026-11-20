# Changelog

All notable changes to uBixGate are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/) as described in
[docs/VERSIONING.md](docs/VERSIONING.md). While uBixGate is in beta, a change to a public
interface is listed under **Interface changes** in the release that makes it.

## [Unreleased]

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
