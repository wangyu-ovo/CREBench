#!/bin/bash

GHIDRA_ANALYZE="/opt/ghidra/ghidra_11.0.1_PUBLIC/support/analyzeHeadless"
GHIDRA_SCRIPTS="/opt/ghidra/customScripts"
DECOMPILE="DecompileToJson.java"

binary="$1"
if [ ! -f "$binary" ]; then
    echo "File not found $binary"
    exit 1
fi

# Resolve to an absolute path
binary="$(cd "$(dirname "$binary")" && pwd)/$(basename "$binary")"

# Create a temp directory next to the binary
tmp_dir="$(dirname "$binary")/ghidra_tmp_$(basename "$binary")"
mkdir -p "$tmp_dir"

${GHIDRA_ANALYZE} "$tmp_dir" DummyProj -scriptpath "$GHIDRA_SCRIPTS" -import "$binary" \
    -postscript "$DECOMPILE" "$tmp_dir/output.json" > "$tmp_dir/run.log" 2>&1

if [ -f "$tmp_dir/output.json" ]; then
    cat "$tmp_dir/output.json"
else
    echo "Output file not generated, error in decompilation!"
    cat "$tmp_dir/run.log"
    exit 1
fi
