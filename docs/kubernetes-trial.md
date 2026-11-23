# Trying the Helm chart on a cluster

This page is a recipe for a throwaway install of the chart in
[deploy/charts/ubixgate](../deploy/charts/ubixgate/README.md), to see a pod become ready
and an MCP client list tools through it. It is for testing, not a production setup. It was
run against a real k3s cluster with the published image `0.1.0-beta.2`: the chart installed
with no changes, the pod went ready, and `tools/list` worked.

## Static token mode does not work in a pod

The quickest way to authenticate locally is `identity.mode: static`, but the gateway
refuses it unless `listen` is a loopback address, and in a pod it must listen on all
addresses. So a trial needs a real token source: a test identity provider that publishes a
JWKS and mints tokens whose audience is the gateway's `public_url`. The demo's
`examples/demo-idp` does exactly that for the users `alice` and `bob`.

## What you need

| Part | Choice for a trial |
|---|---|
| Namespace | A scratch one, for example `ubixgate-test` |
| Identity provider | `examples/demo-idp` as a pod and Service in the same namespace. Set its `DEMO_IDP_ISSUER` to the Service URL and `DEMO_IDP_AUDIENCE` to the gateway's `public_url` |
| Upstream | Any MCP server over Streamable HTTP, such as a pod running `examples/tickets` (that one expects a service token from Vault; for a trial without Vault, use an upstream that needs no credential) |
| Vault | Optional. Leave the `vault` block out of `config` if no upstream has a `credential`, and the gateway starts without it |
| Access | `kubectl port-forward`, so nothing is exposed outside the cluster |

## Values

Set `config.public_url` to the URL your client will use. With a port-forward that is
`http://localhost:8080/mcp`, and the IdP must mint tokens with exactly that audience.

```yaml
image:
  tag: "0.1.0-beta.2"
config:
  public_url: http://localhost:8080/mcp
  identity:
    mode: jwt
    issuer: http://idp.ubixgate-test.svc:9100
    jwks_url: http://idp.ubixgate-test.svc:9100/jwks
    claims: { user: sub, groups: groups, client: azp }
  upstreams:
    - { name: tickets, transport: http, url: "http://tickets.ubixgate-test.svc:9000/mcp" }
  audit: { sink: stdout }
  policy:
    rules:
      - { name: devs-tickets, effect: allow, when: { groups: [developers] }, server: tickets, tools: ["*"] }
```

```
helm upgrade --install ubixgate deploy/charts/ubixgate -n ubixgate-test -f values.yaml
kubectl -n ubixgate-test rollout status deploy/ubixgate
kubectl -n ubixgate-test port-forward svc/ubixgate 8080:8080
```

## Checking it

```
curl -s localhost:8080/healthz      # ok
curl -s localhost:8080/readyz       # ready
curl -si localhost:8080/mcp -d '{}' # 401 with a Www-Authenticate header
```

Get a token for `alice` from the test IdP (port-forward its Service too), then list tools
with plain curl. MCP revision 2026-07-28 requires a `_meta` protocol version on each
request, so for a quick curl send `MCP-Protocol-Version: 2025-11-25`, or use a real MCP
client, which negotiates it for you.

```
curl -s localhost:8080/mcp \
  -H "Authorization: Bearer $TOKEN" -H 'MCP-Protocol-Version: 2025-11-25' \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

The reply lists the upstream's tools as `tickets__ticket_list` and so on, filtered by the
policy for the caller's groups.

## Server-side checks of the optional parts

`helm upgrade --dry-run=server` with the Ingress, ServiceMonitor, PodDisruptionBudget and
two replicas turned on was accepted by a real API server. Those parts were checked that
way, not run: the trial exposed nothing outside the cluster.
