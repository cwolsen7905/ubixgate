#!/bin/sh
# Seed a one-repo Shepherd workspace (first start only), then run the gateway. The
# gateway starts `shepherd mcp` itself as a stdio upstream; Shepherd starts its own
# daemon on first use.
set -eu
export SHEPHERD_HOME=/data/shepherd
if [ ! -f "$SHEPHERD_HOME/config.yaml" ]; then
    mkdir -p "$SHEPHERD_HOME" /data/workspace/web
    printf 'daemon:\n  listen: 127.0.0.1:0\n' > "$SHEPHERD_HOME/config.yaml"
    git -C /data/workspace/web init -q -b main
    git -C /data/workspace/web -c user.name=demo -c user.email=demo@example.com commit -q --allow-empty -m "first commit"
    shepherd init /data/workspace --yes > /dev/null
fi
exec ubixgate serve -config /etc/ubixgate/ubixgate.yaml
