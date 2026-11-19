# Changelog

All notable changes to uBixGate are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/) as described in
[docs/VERSIONING.md](docs/VERSIONING.md). While uBixGate is in beta, a change to a public
interface is listed under **Interface changes** in the release that makes it.

## [Unreleased]

### Added

- Repository skeleton: `make check` (gofmt, vet, golangci-lint, prose style, size budget,
  tests), GitLab CI with promotion from `dev` to `main`, GitHub Actions for CI and
  releases, and a `ubixgate version` command.
- Policy evaluator (`internal/policy`): named allow and deny rules matched on user,
  group, client, server, tool globs and top-level string argument globs; deny rules
  first, then allow, first match wins, default deny. Catalog filtering hides tools a
  caller can never call.
- JWT validation (`internal/identity`) with the standard library only: RS256 and ES256,
  issuer, audience equal to the gateway's URL, `exp` and `nbf` with 60 seconds of skew,
  JWKS caching with rotation on an unknown key ID. A static token mode for local
  development, and RFC 9728 protected resource metadata.
- `ubixgate serve`: one Streamable HTTP endpoint for MCP clients, accepting protocol
  revisions 2026-07-28 and 2025-11-25, in front of HTTP and stdio upstreams. Tools are
  named `server__tool` and each caller's `tools/list` is filtered by policy.
- Credential injection from a Vault-API server (uBixVault or HashiCorp Vault): a header
  per request for HTTP upstreams, an environment variable at spawn for stdio upstreams.
  The caller's own token is never forwarded.
- One JSON-lines audit record per tool call, with argument values redacted by policy.
- A per-user call limit (in memory, per replica), `/healthz`, `/readyz`, Prometheus
  `/metrics`, `ubixgate check` to validate a config, and policy reload on SIGHUP.
