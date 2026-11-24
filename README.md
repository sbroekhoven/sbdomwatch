# sbdomwatch

A standalone domain and DNS watcher. You add a domain with a reason; sbdomwatch
records a baseline of its DNS and RDAP data, and from then on reports every
meaningful change as an event: a new MX record on a typosquat, a nameserver or
registrar change on your own domain, a CNAME pointing at something that no
longer exists, a registration that is about to expire.

It is the base of the sb tool family: sbsquat (typosquat detection) and sbcti
add domains through the API, sbalert will deliver the notifications.

## Quick start

Needs Docker with Compose, `openssl`, and the GitHub CLI (`gh`) logged in with
read access to the private `domping` repository.

```sh
make up        # config.yaml + .env with a random token, build, start, wait until healthy
make e2e       # optional: the whole flow against real DNS and RDAP
```

The service listens on `127.0.0.1:8480` only. Use the CLI inside the container:

```sh
docker compose exec sbdomwatch sbdomwatch add degir0.com --template candidate \
  --reason "seen in CT, profile degiro" --origin typosquat --tag profile=degiro
docker compose exec sbdomwatch sbdomwatch ls
```

or build it locally (`make build`) and run `./bin/sbdomwatch`; it reads the
token from `./.env`. For the short name: `alias sbdw=sbdomwatch`.

## How it works

1. **Add** a watch: domain, template (`owned`, `candidate`, `third-party`) and
   a reason. Adding the same domain again merges origins and tags.
2. **Baseline**: three observations a few minutes apart. Fields that differ
   between them (round-robin A records) are learned as volatile and ignored.
   A `baseline_complete` event carries the inventory. An unregistered domain
   baselines after one observation.
3. **Watch**: every observation is compared with the baseline as sets
   (order and TTLs do not matter). A difference must be seen twice in a row
   before it becomes an event; a failed lookup never counts as a change. A
   first registration fires `registered` immediately.
4. **Deliver**: events are stored first and then delivered to sinks (Discord,
   a generic signed JSON webhook) with retries, so nothing is lost while a
   sink is down.

Checks: DNS (A, AAAA, CNAME, MX, NS, TXT, CAA, SOA through your resolvers) and
RDAP (registration, registrar, registry nameservers, statuses, dates) through
[domping](https://github.com/sbroekhoven/domping). Both are rate limited.

### Events

| Type | When | Severity |
| --- | --- | --- |
| `baseline_complete` | baseline finished (or `rebaseline`), payload is the inventory | info |
| `registered` | RDAP now shows the domain as registered | high |
| `dropped` | the domain is no longer registered | medium |
| `mx_appeared` | MX records where there were none | high |
| `ns_changed` | nameservers changed (DNS or registry) | high, critical for owned |
| `registrar_changed` | registrar changed | high |
| `record_added`, `record_changed`, `record_removed` | any other difference | medium |
| `expiring` | owned domain within `expiry_warning` of its expiry date, once per date | medium |
| `dangling_cname` | the CNAME target no longer resolves | high for owned |

Candidates are archived after 90 days without a notable change, unless they
have a `manual` origin.

## CLI

```
sbdomwatch serve                              run the service
sbdomwatch add <domain> --template T --reason R [--origin O] [--reference REF] [--tag k=v] [--interval 30m]
sbdomwatch import <file|-> --template T --reason R ...   one domain per line, all or nothing
sbdomwatch ls [--state S] [--tag k=v] [--origin O] [--all] [--stale]
sbdomwatch show <domain>
sbdomwatch history <domain> [--since 7d] [--limit N]
sbdomwatch events [--since 24h] [--type T] [--domain D] [--severity high]
sbdomwatch pause | resume | archive <domain>
sbdomwatch confirm <domain>                   owned: confirm the baseline after reviewing it
sbdomwatch rebaseline <domain> [--relearn]    accept the current state as the new baseline
sbdomwatch version
```

Global flags: `--url`, `--env-file` (default `./.env`), `-o table|json`.
Exit codes: 0 ok, 1 error, 2 invalid input, 3 not found.

## API

JSON over HTTP under `/v1` with `Authorization: Bearer $SBDOMWATCH_TOKEN`.
[`internal/api/openapi.yaml`](internal/api/openapi.yaml) is the source of
truth and is served at `/openapi.yaml`; tests keep it in line with the routes
and types. `GET /healthz` needs no token.

```sh
curl -s -H "Authorization: Bearer $SBDOMWATCH_TOKEN" -H "X-Actor: sbsquat" \
  -d '{"domain":"degir0.com","template":"candidate","reason":"permutation of degiro.nl","origin":"typosquat"}' \
  http://127.0.0.1:8480/v1/watches
```

## Configuration

`config.yaml` (see [`config.example.yaml`](config.example.yaml)) holds
everything except secrets. Secrets come only from the environment or `.env`:

| Variable | Purpose |
| --- | --- |
| `SBDOMWATCH_TOKEN` | API token, at least 32 characters (`make config` generates one) |
| `SBDOMWATCH_DISCORD_WEBHOOK` | Discord sink, on when set |
| `SBDOMWATCH_WEBHOOK_URL`, `SBDOMWATCH_WEBHOOK_SECRET` | generic JSON webhook, optionally HMAC-signed |
| `SBDOMWATCH_URL` | where the CLI finds the API (default `http://127.0.0.1:8480`) |

A secret-looking key in `config.yaml` is a startup error, and webhook URLs and
tokens never appear in logs.

## Development

```sh
make test      # go test -race ./...
make lint      # gofmt, go vet, staticcheck
make build     # static binary in bin/
```

`domping` is a private module: set `GOPRIVATE=github.com/sbroekhoven/*` (the
Makefile does). The Docker build gets a GitHub token as a BuildKit secret from
`GITHUB_TOKEN` or `gh auth token`; CI uses the repository secret
`DOMPING_TOKEN`. Unit tests need no network: DNS runs against an in-process
server, RDAP and webhooks against `httptest`.

Design and build plan: [`docs/PLAN.md`](docs/PLAN.md).
