# syntax=docker/dockerfile:1

ARG GO_VERSION=1.27.4
ARG ALPINE_VERSION=3.24.4

FROM golang:${GO_VERSION}-alpine3.24 AS build
RUN apk add --no-cache git
# domping is a private module: fetch it from GitHub directly, with a token
# passed as a BuildKit secret. The token only lives in this RUN's
# environment; it is never written to a layer or to git config.
ENV GOPRIVATE=github.com/sbroekhoven/* GOWORK=off
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=secret,id=github_token,env=GITHUB_TOKEN \
    GIT_CONFIG_COUNT=1 \
    GIT_CONFIG_KEY_0="url.https://x-access-token:${GITHUB_TOKEN}@github.com/.insteadOf" \
    GIT_CONFIG_VALUE_0="https://github.com/" \
    go mod download
COPY . .
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/sbdomwatch ./cmd/sbdomwatch

FROM alpine:${ALPINE_VERSION}
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
