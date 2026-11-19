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
