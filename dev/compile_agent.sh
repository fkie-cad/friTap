#!/bin/bash
# Rebuild the friTap agent bundle from agent/*.ts. Idempotent: re-running
# without changes produces a byte-identical output (CI's agent-build-check
# job depends on that — see .github/workflows/ci.yml).
#
# Entry/output are parameterized (defaults reproduce the historical, public
# behavior exactly, so CI's `./dev/compile_agent.sh` is byte-identical):
#   ENTRY  build entry .ts        (default: agent/fritap_agent.ts — the PUBLIC bundle)
#   OUT    output bundle .js      (default: friTap/fritap_agent.js — the shipped bundle)
# To build the full (private) bundle from a private clone:
#   ENTRY=agent/fritap_agent_full.ts OUT=friTap/fritap_agent_full.js ./dev/compile_agent.sh
#
# Toolchain pin: frida-compile, typescript, and @types/frida-gum are
# exact-pinned in package.json. Run `npm ci` once before this script to
# guarantee package-lock.json is honored.
set -euo pipefail
cd "$(dirname "$0")/.."

ENTRY="${ENTRY:-agent/fritap_agent.ts}"
OUT="${OUT:-friTap/fritap_agent.js}"

# Bridge install is the only non-deterministic step here. Skip it if both
# bridges are already present in node_modules — frida-pm doesn't pin via
# the lockfile, so re-running it can pull a different patch version and
# silently break determinism.
if [ -d node_modules/frida-objc-bridge ] && [ -d node_modules/frida-java-bridge ]; then
    echo "[compile_agent.sh] bridges already present in node_modules — skipping frida-pm install"
else
    echo "[compile_agent.sh] installing frida-pm bridges"
    frida-pm install frida-objc-bridge frida-java-bridge
fi

echo "[compile_agent.sh] rebuilding $OUT from $ENTRY"
frida-compile "$ENTRY" -o "$OUT"

echo "[compile_agent.sh] done. Agent: $(wc -c < "$OUT") bytes"
