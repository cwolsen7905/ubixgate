# ubixgate Helm chart

Runs uBixGate in Kubernetes as a Deployment with a Service, and optionally an Ingress, a
Prometheus Operator ServiceMonitor and a PodDisruptionBudget.

**Status: beta, like the gateway.** The chart is linted and rendered in CI, and the config
it renders is validated by `ubixgate check`. It has not yet been installed in a cluster as
part of CI. Report what you find.

## Before you install

1. **Build and push an image.** No official image is published yet. Build the `Dockerfile`
   at the repo root and push it to a registry your cluster can pull from:

   ```sh
   docker buildx build --platform linux/amd64,linux/arm64 \
     --build-arg VERSION=0.1.0-beta.1 -t registry.example.com/ubixgate:0.1.0-beta.1 --push .
   ```

2. **Write the gateway's config** as the `config` value. It is the same file described in
   the main README, and the chart refuses to render without `config.public_url`. Check it
   first: `ubixgate check ubixgate.yaml`.

3. **Give the gateway a Vault identity**, if any upstream has a credential. With uBixVault
   or HashiCorp Vault in the cluster, the Kubernetes login method needs no files: create a
   Vault role bound to this release's service account (named after the release, for
   example `ubixgate` in namespace `mcp`) and a policy that can read exactly the configured
   credential paths. Then:

   ```yaml
   config:
     vault:
       address: http://ubixvault.vault.svc:8200
       auth: { method: kubernetes, role: ubixgate }
   ```

## Install

```sh
helm install ubixgate deploy/charts/ubixgate -n mcp --create-namespace -f my-values.yaml
```

A minimal `my-values.yaml`:

```yaml
image:
  repository: registry.example.com/ubixgate

config:
  public_url: https://mcp.example.com/mcp
  identity:
    mode: jwt
    issuer: https://idp.example.com
    jwks_url: https://idp.example.com/jwks
  vault:
    address: http://ubixvault.vault.svc:8200
    auth: { method: kubernetes, role: ubixgate }
  upstreams:
    - name: tickets
      transport: http
      url: http://tickets.tools.svc:9000/mcp
      credential: { path: secret/data/mcp/tickets, field: token, format: "Bearer {value}" }
  audit: { sink: stdout }
  policy:
    rules:
      - name: devs-tickets
        effect: allow
        when: { groups: [developers] }
        server: tickets
        tools: ["*"]

ingress:
  enabled: true
  className: nginx
  tlsSecret: mcp-example-tls
```

## What to know

| Topic | Behaviour |
|---|---|
| `listen` | Set by the chart to `containerPort` (8080). Leave it out of `config` |
| Changing the config or policy | `helm upgrade` rolls the pods, because the config's checksum is a pod annotation. SIGHUP reload is not used in Kubernetes. With `existingConfigMap`, restart the Deployment yourself |
| Ingress | Exposes only the MCP endpoint (exact path) and `/.well-known/oauth-protected-resource`. Host and path come from `config.public_url`, so they always match the token audience. TLS ends at the Ingress and a TLS Secret is required |
| Metrics and health | `/metrics`, `/healthz` and `/readyz` are on the Service port but not on the Ingress. Readiness fails until every upstream has listed its tools and Vault answers |
| Audit | `audit: { sink: stdout }` sends records to the pod log, the simplest choice here. A `file` sink needs a writable volume (`extraVolumes`, `extraVolumeMounts`); the root filesystem is read-only |
| Several replicas | Works: the endpoint is stateless. The per-user call limit is per replica, and each replica runs its own stdio upstream processes |
| stdio upstreams | The image holds only `ubixgate`. A stdio upstream's binary must be in the image, so build your own image on top of it, or run the server as an HTTP upstream instead |
| AppRole or token login | Mount the files from a Secret with `extraVolumes` and `extraVolumeMounts`, and point `role_id_file`, `secret_id_file` or `token_file` at them. Set `serviceAccount.automount: false` if nothing needs the service account token |
| Static token mode | Not usable: it requires a loopback listen address |

Every value is described in [values.yaml](values.yaml).

## Checking the chart

`make chart-check` (needs `helm` and Go) lints the chart, renders it with every part
switched on (`ci/test-values.yaml`), runs `ubixgate check` on the rendered config, and
confirms the chart refuses to render without its required values.
