#!/usr/bin/env bash
# demo-compose.sh: build and start the Docker Compose demo, run demo.sh against it, and
# check the outcomes the README shows. Used by the demo-compose CI job; runs anywhere with
# Docker and the compose plugin. Publishes no host ports, so parallel runs do not collide.
set -euo pipefail

project="ubixgate-demo-${CI_JOB_ID:-local}"
compose=(docker compose -p "$project" -f examples/demo/compose.yaml -f examples/demo/compose.ci.yaml)
out=demo-output.txt

cleanup() {
	local rc=$?
	if [ "$rc" != 0 ]; then
		echo "demo-compose: failed; the last lines of each service's log follow."
		"${compose[@]}" logs --no-color --tail 40 || true
	fi
	"${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
	# The containers write examples/demo/out as root; remove it from a container too.
	docker run --rm -v "$PWD/examples/demo:/d" alpine:3.20 rm -rf /d/out >/dev/null 2>&1 || true
	exit "$rc"
}
trap cleanup EXIT

docker compose version
"${compose[@]}" up -d --build

docker run --rm --network "${project}_default" -v "$PWD:/src" -w /src \
	-e GATEWAY=http://ubixgate:8080/mcp -e IDP=http://demo-idp:9100 \
	alpine:3.20 sh -c 'apk add --no-cache bash curl jq >/dev/null && bash demo.sh' | tee "$out"

for want in \
	"401 Unauthorized" \
	"authenticated as svc-tickets" \
	"denied by rule contractors-no-writes" \
	"denied by rule default-deny"; do
	grep -qF "$want" "$out" || { echo "demo-compose: expected \"$want\" in the demo output"; exit 1; }
done
echo "demo-compose: the Compose demo ran and showed every expected outcome."
