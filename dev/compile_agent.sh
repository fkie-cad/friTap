#!/bin/bash
# Rebuild the friTap Frida agent bundles from agent/*.ts. Idempotent: re-running
# without changes produces byte-identical output (CI's agent-build-check job runs
# this script bare and asserts `git diff --exit-code -- friTap/fritap_agent.js`,
# so the intercept bundle MUST stay byte-identical — see .github/workflows/ci.yml).
#
# friTap ships TWO independent agents:
#   * the INTERCEPT agent  agent/fritap_agent.ts    -> friTap/fritap_agent.js
#     (the main TLS/protocol hooking agent, tracked in git)
#   * the MEMORY-SCAN agent agent/memory_scan_agent.ts -> friTap/fritap_memscan.js
#     (the hook-free heap secret scanner, -ms/--memory-scan; gitignored artifact)
#
# Usage:  ./dev/compile_agent.sh [target]
#   both        (DEFAULT) build the intercept and memory-scan agents, plus the
#               full agent when agent/fritap_agent_full.ts exists (private
#               clones only; silently skipped otherwise)   (alias: all)
#   intercept   build only the intercept agent   (aliases: agent, main, tls)
#   ms          build only the memory-scan agent (aliases: memory_scan, memscan)
#   full        build the full/private intercept agent
#               (agent/fritap_agent_full.ts -> friTap/fritap_agent_full.js;
#                only present in a private clone)
#   -h|--help   show this help
#
# Whenever the full agent is built, a sidecar friTap/fritap_agent_full.js.src is
# written with the sha256 of friTap/fritap_agent.js. At runtime friTap only
# auto-loads the full bundle if that hash still matches the public bundle.
#
# Back-compat escape hatch: if ENTRY and/or OUT are set in the environment, a
# single custom bundle is built from them EXACTLY as before (the target arg is
# ignored), so existing invocations keep working:
#   ENTRY=agent/fritap_agent_full.ts OUT=friTap/fritap_agent_full.js ./dev/compile_agent.sh
#   ENTRY=agent/memory_scan_agent.ts OUT=friTap/fritap_memscan.js    ./dev/compile_agent.sh
#
# Toolchain pin: frida-compile, typescript, and @types/frida-gum are
# exact-pinned in package.json. Run `npm ci` once before this script to
# guarantee package-lock.json is honored.
set -euo pipefail
cd "$(dirname "$0")/.."

usage() {
    sed -n '2,36p' "$0" | sed 's/^# \{0,1\}//'
}

# Always use the pinned Node frida-compile from node_modules (the same binary
# `npm run build` uses), NOT whatever `frida-compile` a PATH shim resolves to
# (e.g. the Python frida-tools shim is a DIFFERENT tool and produces a different,
# non-deterministic bundle). Fall back to PATH only if node_modules is absent.
FRIDA_COMPILE="./node_modules/.bin/frida-compile"
if [ ! -x "$FRIDA_COMPILE" ]; then
    FRIDA_COMPILE="frida-compile"
fi

TARGET="${1:-both}"
case "$TARGET" in
    -h|--help|help) usage; exit 0 ;;
esac

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

# Compile one entry -> one bundle and report its size.
build_one() {
    local entry="$1" out="$2" label="$3"
    echo "[compile_agent.sh] rebuilding $out from $entry ($label)"
    "$FRIDA_COMPILE" "$entry" -o "$out"
    echo "[compile_agent.sh] done. $label: $(wc -c < "$out") bytes"
}

# Record which public bundle the full bundle was built alongside (sha256 of
# fritap_agent.js, hex only => deterministic across machines).
write_full_sidecar() {
    local sidecar="$FULL_OUT.src" digest
    if command -v sha256sum >/dev/null 2>&1; then
        digest="$(sha256sum "$INTERCEPT_OUT" | cut -d' ' -f1)"
    else
        digest="$(shasum -a 256 "$INTERCEPT_OUT" | cut -d' ' -f1)"
    fi
    printf '%s\n' "$digest" > "$sidecar"
    echo "[compile_agent.sh] wrote $sidecar (sha256 of $INTERCEPT_OUT)"
}

build_full() {
    build_one "$FULL_ENTRY" "$FULL_OUT" "full intercept agent"
    write_full_sidecar
}

# Canonical agent entries.
INTERCEPT_ENTRY="agent/fritap_agent.ts";        INTERCEPT_OUT="friTap/fritap_agent.js"
MEMSCAN_ENTRY="agent/memory_scan_agent.ts";     MEMSCAN_OUT="friTap/fritap_memscan.js"
FULL_ENTRY="agent/fritap_agent_full.ts";        FULL_OUT="friTap/fritap_agent_full.js"

# Explicit ENTRY/OUT override => a single custom build, historical behavior
# (defaults reproduce the old bare invocation for anything still relying on it).
if [ -n "${ENTRY:-}" ] || [ -n "${OUT:-}" ]; then
    resolved_out="${OUT:-$INTERCEPT_OUT}"
    build_one "${ENTRY:-$INTERCEPT_ENTRY}" "$resolved_out" "custom"
    # When the custom build targets the full bundle, keep its hash sidecar in
    # sync too (same pin build_full writes), reusing write_full_sidecar.
    if [ "$resolved_out" = "$FULL_OUT" ]; then
        write_full_sidecar
    fi
    exit 0
fi

case "$TARGET" in
    both|all)
        # Intercept first so CI's byte-identity check on fritap_agent.js sees the
        # exact same build as before; then the memory-scan agent.
        build_one "$INTERCEPT_ENTRY" "$INTERCEPT_OUT" "intercept agent"
        build_one "$MEMSCAN_ENTRY"   "$MEMSCAN_OUT"   "memory-scan agent"
        # Full agent only exists in private clones; skipped silently elsewhere so
        # the public agent-build-check is unaffected.
        if [ -f "$FULL_ENTRY" ]; then
            build_full
        fi
        ;;
    intercept|agent|main|tls)
        build_one "$INTERCEPT_ENTRY" "$INTERCEPT_OUT" "intercept agent"
        ;;
    ms|memory_scan|memscan)
        build_one "$MEMSCAN_ENTRY"   "$MEMSCAN_OUT"   "memory-scan agent"
        ;;
    full)
        if [ ! -f "$FULL_ENTRY" ]; then
            echo "[compile_agent.sh] $FULL_ENTRY not found (private-clone only)" >&2
            exit 1
        fi
        build_full
        ;;
    *)
        echo "[compile_agent.sh] unknown target '$TARGET'" >&2
        echo "  valid targets: both (default) | intercept | ms | full  (see --help)" >&2
        exit 2
        ;;
esac

echo "[compile_agent.sh] all requested bundles built."
