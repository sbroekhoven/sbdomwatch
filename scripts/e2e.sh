#!/usr/bin/env bash
# End-to-end check against the service started by `make up`: health, API
# description, add a watch, wait for real DNS and RDAP observations, then
# history, events, error cases and clean-up. It uses the CLI inside the
# container, so it needs nothing but Docker and curl. Exits non-zero on the
# first failure.
set -euo pipefail

domain="${E2E_DOMAIN:-example.com}"
cli() { docker compose exec -T sbdomwatch sbdomwatch "$@"; }
step() { printf '\n== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

step "health and API description"
curl -fsS http://127.0.0.1:8480/healthz | grep -q '"ok"' || fail "healthz"
curl -fsS http://127.0.0.1:8480/openapi.yaml | head -1 | grep -q 'openapi: 3.1.0' || fail "openapi.yaml"
code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8480/v1/watches)
[ "$code" = 401 ] || fail "API without token answered $code, want 401"

step "add $domain (an empty reason must be refused)"
if cli add "$domain" --template owned --reason "" >/dev/null 2>&1; then fail "empty reason accepted"; fi
cli add "$domain" --template owned --reason "e2e test" --tag e2e=yes
upper=$(printf '%s' "$domain" | tr '[:lower:]' '[:upper:]')
cli add "$upper." --template owned --reason "e2e merge" | grep -q merged || fail "second add did not merge"

step "wait for the first DNS and RDAP observations"
out=""
for _ in $(seq 1 30); do
  out=$(cli history "$domain" || true)
  if grep -q ' dns ' <<<"$out" && grep -q ' rdap ' <<<"$out"; then break; fi
  sleep 2
done
echo "$out"
grep -q ' dns ' <<<"$out" || fail "no DNS observation"
grep -q ' rdap ' <<<"$out" || fail "no RDAP observation"

step "show, ls, events"
cli show "$domain"
cli ls --tag e2e=yes | grep -q "$domain" || fail "ls --tag"
cli events --since 1h
cli confirm "$domain" 2>&1 | grep -q 'not complete' || fail "confirm before the baseline was accepted"
set +e
cli show not-watched-sbdw-e2e.com >/dev/null 2>&1
rc=$?
set -e
[ "$rc" -eq 3 ] || fail "show of an unknown domain exited $rc, want 3"

step "clean up"
cli archive "$domain"
printf '\nOK: end-to-end flow passed\n'
