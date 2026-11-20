# syntax=docker/dockerfile:1
# Images for the demo, one target each:
#   gateway   ubixgate plus the shepherd binary and git, with a seeded workspace, so the
#             gateway can run Shepherd as a stdio upstream
#   demo-idp  the toy identity provider
#   tickets   the fake ticket tracker
FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/ubixgate ./cmd/ubixgate \
 && CGO_ENABLED=0 go build -o /out/demo-idp ./examples/demo-idp \
 && CGO_ENABLED=0 go build -o /out/tickets ./examples/tickets
# Shepherd from its published source, pinned.
ARG SHEPHERD_VERSION=v0.6.0-beta.1
RUN CGO_ENABLED=0 GOBIN=/out go install github.com/ubixsys/ubixshepherd/cmd/shepherd@$SHEPHERD_VERSION

FROM gcr.io/distroless/static-debian12:nonroot AS demo-idp
COPY --from=build /out/demo-idp /usr/local/bin/demo-idp
ENTRYPOINT ["/usr/local/bin/demo-idp"]

FROM gcr.io/distroless/static-debian12:nonroot AS tickets
COPY --from=build /out/tickets /usr/local/bin/tickets
ENTRYPOINT ["/usr/local/bin/tickets"]

FROM debian:bookworm-slim AS gateway
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 10001 gate \
 && mkdir -p /data && chown gate /data
COPY --from=build /out/ubixgate /out/shepherd /usr/local/bin/
COPY examples/demo/gateway-entrypoint.sh /usr/local/bin/gateway-entrypoint.sh
USER gate
ENTRYPOINT ["/usr/local/bin/gateway-entrypoint.sh"]
