# syntax=docker/dockerfile:1
#
# Builds one AgentBox service binary into a minimal, non-root image.
#
#   docker build -f deploy/Dockerfile --build-arg CMD=netgw -t agentbox/netgw .
#
# CMD is one of: controller, netgw, mcpgw. (mcpbridge needs a runtime for the
# MCP server it wraps; see Dockerfile.mcp-node.)
# Pin the base images by digest when publishing (see the packaging task).

FROM golang:1.26 AS build
ARG CMD
ARG VERSION=0.0.0-dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN test -n "$CMD" && CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X github.com/Oleg-Imanilov/agent-box/internal/version.Version=${VERSION}" \
    -o /out/service ./cmd/${CMD} \
 && mkdir /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/service /usr/local/bin/service
# /data is the controller's SQLite directory; created owned by the unprivileged
# user so a fresh named volume mounted there is writable.
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/service"]
HEALTHCHECK --interval=10s --timeout=4s --start-period=5s --retries=3 CMD ["/usr/local/bin/service", "healthcheck"]
