#!/usr/bin/env bash
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
WF="$REPO/regress_test/P01-direct-secret-curl.yml"
A=$(cd "$REPO" && python3 main.py "$WF")
B=$(cd /tmp    && python3 "$REPO/main.py" "$WF")
if [ "$A" = "$B" ]; then
  echo "PASS: output giong nhau khi chay tu hai thu muc khac nhau"
else
  echo "FAIL: output khac nhau"; diff <(echo "$A") <(echo "$B"); exit 1
fi