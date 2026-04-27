#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

make -s clean || true
make -s || true

# 16 bytes (32 hex chars)
IN=00112233445566778899aabbccddeeff
echo "Running RC2 demo with IN=$IN" >&2
../public/rc2_demo "$IN"
