#!/usr/bin/env bash
# Checks the Helm chart: lint, render with every part on, validate the rendered config
# with `ubixgate check`, and confirm the chart refuses to render without its required
# values. HELM and UBIXGATE may name other commands (CI runs both in containers).
set -euo pipefail

HELM=${HELM:-helm}
UBIXGATE=${UBIXGATE:-go run ./cmd/ubixgate}
chart=deploy/charts/ubixgate
values=$chart/ci/test-values.yaml
out=.chart-check
rm -rf "$out" && mkdir -p "$out"
trap 'rm -rf "$out"' EXIT

$HELM lint --strict "$chart" -f "$values"
$HELM template t "$chart" -f "$values" >"$out/all.yaml"
for kind in ConfigMap Deployment Service ServiceAccount Ingress ServiceMonitor PodDisruptionBudget; do
	grep -q "^kind: $kind\$" "$out/all.yaml" || { echo "chart-check: no $kind rendered"; exit 1; }
done

# The config file as the pod sees it: the ConfigMap's ubixgate.yaml block, unindented.
$HELM template t "$chart" -f "$values" --show-only templates/configmap.yaml |
	awk '/^  ubixgate.yaml: \|/ {on=1; next} on {sub(/^    /, ""); print}' >"$out/ubixgate.yaml"
grep -q '^listen: :8080$' "$out/ubixgate.yaml" || { echo "chart-check: listen not set from containerPort"; exit 1; }
$UBIXGATE check "$out/ubixgate.yaml"

# Each required value must stop the render with its own message.
refuse() {
	local want=$1
	shift
	if $HELM template t "$chart" "$@" >/dev/null 2>"$out/err"; then
		echo "chart-check: rendered without $want"
		exit 1
	fi
	grep -q "$want" "$out/err" || { echo "chart-check: expected an error naming $want, got:"; cat "$out/err"; exit 1; }
}
refuse image.repository --set config.public_url=https://mcp.example.com/mcp
refuse config.public_url --set image.repository=r
refuse ingress.tlsSecret -f "$values" --set ingress.tlsSecret=

echo "chart checks pass."
