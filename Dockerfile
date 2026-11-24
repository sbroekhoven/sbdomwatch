# syntax=docker/dockerfile:1

# Base image versions are written out in FROM so Dependabot can update them.

# The build stage runs on the builder's own platform and cross-compiles for
# the target, so multi-arch images need no emulation for the Go build.
FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine3.24 AS build
ENV GOWORK=off
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG VERSION=dev
ARG TARGETOS TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/sbdomwatch ./cmd/sbdomwatch

FROM alpine:3.24.4
RUN apk add --no-cache ca-certificates tzdata \
 && addgroup -S -g 10001 sbdomwatch \
 && adduser -S -D -H -u 10001 -G sbdomwatch -s /sbin/nologin sbdomwatch \
 && mkdir -p /data /etc/sbdomwatch \
 && chown sbdomwatch:sbdomwatch /data
COPY --from=build /out/sbdomwatch /usr/local/bin/sbdomwatch
USER 10001:10001
WORKDIR /data
VOLUME /data
EXPOSE 8480
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8480/healthz || exit 1
ENTRYPOINT ["sbdomwatch"]
CMD ["serve"]
