# uBixGate

An open-source gateway for the Model Context Protocol (MCP), written in Go. MCP clients
such as Claude Code, Cursor and OpenCode connect to one endpoint. Behind it, uBixGate
fronts many MCP servers and, for every tool call, checks who is calling, decides whether
the call is allowed, attaches the upstream's credential from Vault so the agent never
holds it, and writes an audit record.

**Status: under construction.** Nothing here is usable yet. The first public beta,
`v0.1.0-beta.1`, is in progress. This README will describe what ships, how to run the
demo, and what the gateway does and does not protect against.

## Build

```sh
make build      # bin/ubixgate
make check      # the full gate: gofmt, vet, lint, prose style, size budget, tests
```

## License

BSD 3-Clause, see [LICENSE](LICENSE). The uBix names and logos are covered by
[TRADEMARKS.md](TRADEMARKS.md).
