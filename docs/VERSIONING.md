# Versioning

uBixGate follows [Semantic Versioning](https://semver.org/). The number describes the
stability of the gateway's public interfaces:

| Interface | What it covers |
|---|---|
| The CLI | `ubixgate` commands and their flags |
| The config file | Every key in the YAML config, including the policy rule format |
| The MCP surface | How tools are named (`server__tool`), how a denial is reported, which protocol revisions are accepted |
| The audit record | Field names and meanings in the JSON-lines audit log |
| Ops endpoints | `/healthz`, `/readyz` and the names and labels of the `/metrics` series |

For a released version, `MAJOR` means a backward-incompatible change to one of these,
`MINOR` new capability that keeps existing use working, and `PATCH` fixes only.

## What `0.x` and `-beta.N` mean here

- **`0.x.y-beta.N`**: a beta. **Interfaces may still change between betas.** Every such
  change is listed in [CHANGELOG.md](../CHANGELOG.md) under **Interface changes**, with
  what to do about it.
- **`0.x.y-rc.N`**: a release candidate. No interface changes are planned before `0.x.y`.
- **`0.x.y`**: a change that breaks existing use moves the minor number.
- **`1.0.0`** will mean the interfaces above are stable.

The first release is `v0.1.0-beta.1`.

## What the version does not promise

It says nothing about security maturity. A beta has had no independent security review,
and neither has any release until the README says otherwise.
