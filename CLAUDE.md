# CLAUDE.md

Guidance for Claude Code (or any AI session) working in this repository.

## Where things stand

uBixGate is an MCP gateway in Go, in public beta: the latest release is
`v0.1.0-beta.2`. The README says what it does and its "Limits of this beta" table says
what it does not. The vision, requirements,
design and roadmap are kept by the maintainer outside this repo. A session's brief carries
what it needs from them.

What the beta does, in one paragraph: MCP clients connect to one Streamable HTTP endpoint.
For every call the gateway authenticates the caller (OIDC/JWT via JWKS, or a static token
for local development only), filters the aggregated `server__tool` catalog by policy,
authorizes the call against a deny-by-default YAML rule list, injects the upstream's
credential from a Vault-API server at call time, forwards the call, and writes one
JSON-lines audit record. The client's token is never forwarded upstream.

Not in the beta: an admin UI, multi-tenancy, rate limiting beyond a simple per-user call
limit, SAML or SCIM, response content filtering, plugins, token exchange for upstream credentials,
OPA or CEL policy engines. Do not build them; ask the maintainer.

## Code

Go, one binary (`cmd/ubixgate`), packages under `internal/`. `make check` is the gate:
gofmt, vet, golangci-lint, `prose-check`, `size-check`, the promote script tests and
`go test -race ./...`. `make build` gives `bin/ubixgate`, `make cross` the six release
targets, `make dist` their archives and `SHA256SUMS`.

| Package | Job |
|---|---|
| `cmd/ubixgate` | `serve`, `check` (validate a config), `version` |
| `internal/config` | Load and validate the YAML (unknown keys are errors); SIGHUP reload |
| `internal/identity` | JWT and static-token validation, claims to a `Principal`, protected resource metadata |
| `internal/policy` | Rule matching, catalog filtering, the `Decider` interface |
| `internal/upstream` | stdio and Streamable HTTP clients, catalog refresh, process restarts |
| `internal/secrets` | A small Vault-API client: login, read, renew, TTL cache |
| `internal/gateway` | The MCP server front: list and call, the per-call steps |
| `internal/audit` | Record type, redaction, JSON-lines sink |
| `internal/ops` | `/healthz`, `/readyz`, `/metrics`, `slog` setup |
| `test/` | Integration tests with an in-process fake IdP, fake Vault and fake upstreams |
| `examples/` | The demo: compose file, demo IdP, fake upstream, `demo.sh` |

Rules for the code:

- **Size budget.** Non-test Go under `cmd/` and `internal/` stays under 4,000 lines
  (`make size-check`, `make loc`). One person must be able to read it all in an afternoon.
  Prefer deleting code to adding it; raising the budget is the maintainer's call.
- **Dependencies.** The official MCP Go SDK (`github.com/modelcontextprotocol/go-sdk`), a
  YAML parser, the Prometheus client and the OpenTelemetry SDK with its OTLP/HTTP
  exporter. Nothing else without asking. JWT validation uses
  the standard library (`crypto/*`), not a JOSE package. The Vault client is our own.
- **Protocol.** Clients may use MCP revision 2026-07-28 or 2025-11-25. Upstreams are spoken
  to in whatever they negotiate; some (stdio servers in particular) top out at 2025-11-25.
- **Security rules that never bend.** Deny by default. Accept only RS256 and ES256, never
  `none` or HS*. `aud` must equal the configured public URL. Never forward the client's
  token upstream. Never log a credential or an unredacted argument value. Every exit from
  a tool call, including errors, writes exactly one audit record.
- **Policy sits behind one interface** (`Decide(ctx, Request) (Decision, error)`) so
  another engine can be added later. Only the YAML evaluator is built.
- **Tests.** Table tests for policy and JWT validation; `httptest` fakes for Vault, the IdP
  and HTTP upstreams; a real child process for stdio upstreams. No Docker in `go test`.
- Structured logs with `log/slog`. Errors are wrapped with context (`fmt.Errorf("...: %w")`).

## Releases

GitHub is the public home and where releases are published: GitLab push-mirrors protected
branches and tags to it, GitHub's default branch is `main`, and
`.github/workflows/release.yml` builds, signs (keyless cosign) and publishes a GitHub
Release for each `v*` tag, with notes from its `CHANGELOG.md` section. It refuses a tag that
is not on `main`. Work lands on `dev` by merge request; a green `dev` is fast-forwarded to
`main` by `promote-to-main` (`bin/promote.sh`: never forced, refuses a diverged `main`).
Read [docs/RELEASING.md](docs/RELEASING.md) before cutting one and
[docs/VERSIONING.md](docs/VERSIONING.md) for what the number promises. **Agents never tag
or publish a release unasked.**

## This repo is public

It is mirrored to GitHub, and mirroring copies whole branches with their history, so
**anything committed here is public**. Write every doc, comment and commit message for a
stranger:

- No private product names, internal hostnames, private MR numbers, or anyone's working
  notes. State the lesson in general terms instead.
- Planning material (requirements, design rationale, roadmap, open questions) lives in the
  maintainer's private documents, never here, and is never copied in. Public docs are
  written fresh, in their own words, and describe what has shipped.
- The `public-boundary` CI job fails if the tree matches the `PUBLIC_BOUNDARY_PATTERN` CI
  variable (set in project settings, deliberately not in the repo). Public uBix projects
  (uBixVault, uBixShepherd, uBixCore, ubixsys.com) are fine to name.
- No secrets in the repo. The demo's credentials are throwaway values generated at start.

## Prose style

Applies to the README, docs, comments, commit messages and MR descriptions.

- **No em dashes or en dashes.** Restructure the sentence or use a colon or comma.
  Hyphens in compound words are fine. `make prose-check` enforces it.
- Plain sentences, tables for comparisons, written for someone who has never seen the
  project.
- Honest status labels: say what is experimental, untested or missing.

## Ground rules

- **The maintainer decides scope, stack and naming.** Bring open questions with the
  trade-offs and a recommendation. Ask before adding a dependency, going beyond the beta's
  scope, or tagging or publishing anything.
- **uBixVault and uBixShepherd are separate repos; do not change them from here.** If the
  gateway needs something from either, write it up as a proposal for the maintainer.
- Work lands on `dev`, the integration branch; `main` is moved only by promotion. Work on a
  branch (`feat/<topic>`, `fix/<topic>`, `docs/<topic>`, `chore/<topic>`) and land it on
  `dev` by MR, with Conventional Commit messages (`feat(policy): ...`).
- **Agents never approve their own work.** The `require-approval` job needs a person.

## Keeping the docs coherent

- The README describes what ships, the demo with its real output, the MCP revision
  targeted and the threat model's limits. Update it in the same change as the behaviour.
- Every user-visible change gets a `CHANGELOG.md` entry under `[Unreleased]`; interface
  changes go under **Interface changes**.
