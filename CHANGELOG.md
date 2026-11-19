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
