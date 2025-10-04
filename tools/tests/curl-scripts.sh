#!/usr/bin/env bash
set -euo pipefail
BASE=${BASE:-http://localhost:8088}

echo "== First request sets cookie =="
curl -si $BASE/ | tee /tmp/h.txt | grep -i 'set-cookie: Clearance=' || true

echo "== Second request should be 200 and no challenge =="
COOKIE=$(grep -i 'set-cookie: Clearance=' /tmp/h.txt | sed -E 's/Set-Cookie: (Clearance=[^;]+).*/\1/I')
curl -si --cookie "$COOKIE" $BASE/ | head -n1

echo "== Headless UA to /login should get 302 to /__uam =="
curl -si -A "curl/8.0" $BASE/login | grep -E ' 302|/__uam' || true
