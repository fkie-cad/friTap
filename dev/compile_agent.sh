#!/bin/bash
# Rebuild friTap/fritap_agent.js from agent/*.ts. Idempotent: re-running
# without changes produces a byte-identical output (CI's agent-build-check
# job depends on that — see .github/workflows/ci.yml).
#
# Toolchain pin: frida-compile, typescript, and @types/frida-gum are
# exact-pinned in package.json. Run `npm ci` once before this script to
# guarantee package-lock.json is honored.
set -euo pipefail
cd "$(dirname "$0")/.."

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

echo "[compile_agent.sh] rebuilding friTap/fritap_agent.js"
frida-compile agent/fritap_agent.ts -o friTap/fritap_agent.js

echo "[compile_agent.sh] done. Agent: $(wc -c < friTap/fritap_agent.js) bytes"
