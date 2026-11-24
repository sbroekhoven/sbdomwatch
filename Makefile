BINARY  := sbdomwatch
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
STATICCHECK := honnef.co/go/tools/cmd/staticcheck@v0.8.2

.PHONY: all build test vet lint config docker up down logs e2e clean

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
	go run $(STATICCHECK) ./...

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

docker: config
	SBDOMWATCH_VERSION=$(VERSION) docker compose build

# One command from a clean checkout: config and token, build, start, and
# wait until the container is healthy.
up: config
	SBDOMWATCH_VERSION=$(VERSION) docker compose up --build --detach --wait
	@echo "sbdomwatch is up on http://127.0.0.1:8480 (make logs, make down)"
	@echo "CLI in the container: docker compose exec sbdomwatch sbdomwatch ls"

logs:
	docker compose logs --follow

# The whole flow against the running service, with real DNS and RDAP.
e2e: up
	./scripts/e2e.sh

down:
	docker compose down

clean:
	go clean
	@test ! -d bin || find bin -type f -name '$(BINARY)' -delete
