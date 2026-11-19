# syntax=docker/dockerfile:1
# The gateway image: one static binary on distroless, running as a non-root user.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
    -ldflags "-s -w -X github.com/ubixsys/ubixgate/internal/version.Version=$VERSION" \
    -o /out/ubixgate ./cmd/ubixgate

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ubixgate /usr/local/bin/ubixgate
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/ubixgate"]
CMD ["serve", "-config", "/etc/ubixgate/ubixgate.yaml"]
