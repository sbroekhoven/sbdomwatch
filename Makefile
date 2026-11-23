BINARY  := sbdomwatch
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build test vet lint config docker up down clean

all: lint test build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/sbdomwatch

# The race detector needs cgo; only the tests use it, the binary stays static.
test:
	go test -race ./...

vet:
	go vet ./...

lint: vet
	@unformatted=$$(gofmt -l .); if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi
	@if command -v staticcheck >/dev/null 2>&1; then staticcheck ./...; else echo "staticcheck not installed, skipping"; fi

# Create local config.yaml and .env from the examples if they do not exist,
# and put a random API token in .env when it has none.
config:
	@test -f config.yaml || cp config.example.yaml config.yaml
	@test -f .env || (umask 077 && cp .env.example .env)
	@if grep -q '^SBDOMWATCH_TOKEN=$$' .env; then \
		umask 077 && token=$$(openssl rand -hex 32) && \
		awk -v t="$$token" '/^SBDOMWATCH_TOKEN=$$/ { print "SBDOMWATCH_TOKEN=" t; next } { print }' .env > .env.tmp && \
		mv .env.tmp .env && echo "generated SBDOMWATCH_TOKEN in .env"; \
	fi

# The image build fetches the private domping module with a GitHub token,
# taken from GITHUB_TOKEN or else from the GitHub CLI.
docker: config
	GITHUB_TOKEN=$${GITHUB_TOKEN:-$$(gh auth token)} SBDOMWATCH_VERSION=$(VERSION) docker compose build

up: config
	GITHUB_TOKEN=$${GITHUB_TOKEN:-$$(gh auth token)} SBDOMWATCH_VERSION=$(VERSION) docker compose up --build

down:
	docker compose down

clean:
	go clean
	@test ! -d bin || find bin -type f -name '$(BINARY)' -delete
