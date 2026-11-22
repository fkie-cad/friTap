#!/usr/bin/env bash
#
# End-to-end verification of friTap's Apple TLS capture path on macOS
# (Apple silicon). Device-free: it builds a local HTTPS server plus a
# CFNetwork/BoringSSL client and drives friTap against them.
#
#   ./dev/macos_verify/verify.sh              # run every applicable check
#   ./dev/macos_verify/verify.sh --keep       # keep the work dir for inspection
#   ./dev/macos_verify/verify.sh --list       # show the checks and exit
#   ./dev/macos_verify/verify.sh --chromium-only  # only the chrome:* / electron:* checks
#
# Exits non-zero if any check fails. Every check prints the numbers it asserted
# on, so a pass is auditable rather than a bare "ok".
#
# Background: friTap #65 (iOS 16) was a crash during instrumentation. The bugs
# behind it are reproducible on macOS because iOS and macOS share
# /usr/lib/libboringssl.dylib and the same SSL_CTX layout — which is what makes
# this rig a meaningful stand-in for a jailbroken device.

set -uo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
RIG_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

KEEP_WORKDIR=0
LIST_ONLY=0
CHROMIUM_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --keep) KEEP_WORKDIR=1 ;;
        --list) LIST_ONLY=1 ;;
        --chromium-only) CHROMIUM_ONLY=1 ;;
        -h|--help) sed -n '2,20p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
FAILED_NAMES=()

# Processes we start, killed by the EXIT trap so a failed check never leaks a
# TLS server or a half-instrumented target into the user's machine.
STARTED_PIDS=()
# Long-running friTaps (chromium_checks.sh start_fritap): the EXIT trap stops
# them with SIGINT first so they detach instead of staying attached.
FRITAP_PIDS=()

# ---------------------------------------------------------------------------
# output helpers
# ---------------------------------------------------------------------------

if [ -t 1 ]; then
    C_OK=$'\033[32m'; C_BAD=$'\033[31m'; C_WARN=$'\033[33m'
    C_DIM=$'\033[2m'; C_OFF=$'\033[0m'
else
    C_OK=""; C_BAD=""; C_WARN=""; C_DIM=""; C_OFF=""
fi

section() { printf '\n%s=== %s ===%s\n' "$C_DIM" "$1" "$C_OFF"; }
detail()  { printf '      %s%s%s\n' "$C_DIM" "$1" "$C_OFF"; }
pass()    { PASS_COUNT=$((PASS_COUNT + 1)); printf '%s PASS %s %s\n' "$C_OK" "$C_OFF" "$1"; }
skip()    { SKIP_COUNT=$((SKIP_COUNT + 1)); printf '%s SKIP %s %s\n' "$C_WARN" "$C_OFF" "$1"; }
fail()    {
    FAIL_COUNT=$((FAIL_COUNT + 1)); FAILED_NAMES+=("$1")
    printf '%s FAIL %s %s\n' "$C_BAD" "$C_OFF" "$1"
}

cleanup() {
    # Before the targets die, so friTap detaches rather than losing its session.
    for pid in ${FRITAP_PIDS+"${FRITAP_PIDS[@]}"}; do
        alive "$pid" && stop_fritap "$pid"
    done
    for pid in ${STARTED_PIDS+"${STARTED_PIDS[@]}"}; do
        kill -9 "$pid" 2>/dev/null
    done
    # Anything the rig spawned indirectly (friTap spawn mode starts its own copy,
    # and tls_fork spawns a child of its own).
    pkill -9 -f "$WORK/tls_client" 2>/dev/null
    pkill -9 -f "$WORK/tls_fork" 2>/dev/null
    # The separate Chrome instance of the chrome:* checks, helpers included.
    pkill -9 -f "$WORK/chrome_ud" 2>/dev/null
    # friTap writes its debug log into the cwd it was started from, i.e. the repo
    # root. Remove only the ones this run created — a concurrent friTap session
    # may legitimately own others.
    if [ -f "${WORK:-}/.started" ]; then
        find "$REPO_ROOT" -maxdepth 1 -name 'fritap_debug_*.log' \
             -newer "$WORK/.started" -delete 2>/dev/null
    fi
    if [ "$KEEP_WORKDIR" = "1" ]; then
        printf '\nwork dir kept: %s\n' "$WORK"
    else
        [ -n "${WORK:-}" ] && rm -rf "$WORK"
    fi
}

# ---------------------------------------------------------------------------
# run a command with a wall-clock bound
#
# Deliberately not GNU `timeout`: macOS does not ship it, and requiring
# `brew install coreutils` just to verify a build would be a silly dependency.
#
# friTap's output goes to a FILE, not a pipe. Two structural reasons:
#   1. friTap logs to stderr, so a pipe would need 2>&1 to catch anything.
#   2. Every check below greps the same output more than once, which needs a
#      file — and these runs are bounded with `kill -9`, so nothing that
#      depends on friTap's own teardown can be relied on here anyway.
# Every caller redirects and greps the file afterwards.
# ---------------------------------------------------------------------------
run_bounded() {
    local seconds=$1 outfile=$2
    shift 2
    "$@" >"$outfile" 2>&1 &
    local cmd_pid=$!
    ( sleep "$seconds"; kill -9 "$cmd_pid" 2>/dev/null ) &
    local killer_pid=$!
    wait "$cmd_pid" 2>/dev/null
    local rc=$?
    kill -9 "$killer_pid" 2>/dev/null
    wait "$killer_pid" 2>/dev/null
    return $rc
}

# fritap_cmd <fritap args...>: friTap from this checkout, run from the repo root,
# unbuffered. It execs python, so call it only in a background job or subshell
# (then `$!` is friTap itself); in the foreground it would replace this script.
fritap_cmd() {
    exec env PYTHONUNBUFFERED=1 FRITAP_VERIFY_CWD="$REPO_ROOT" \
        python -c 'import os, runpy, signal, sys
# Background jobs of a non-interactive shell start with SIGINT ignored; restore
# it so a SIGINT before friTap installs its own handler still stops it.
signal.signal(signal.SIGINT, signal.default_int_handler)
os.chdir(os.environ["FRITAP_VERIFY_CWD"])
sys.argv = ["fritap"] + sys.argv[1:]
runpy.run_module("friTap.friTap", run_name="__main__")' "$@"
}

# run_fritap <seconds> <outfile> <fritap args...>
#
# friTap runs until interrupted, so every capture check is bounded and the
# non-zero "killed" status is expected rather than a failure — the checks below
# assert on the keylog file and the captured output, never on the exit code.
run_fritap() {
    local seconds=$1 outfile=$2
    shift 2
    run_bounded "$seconds" "$outfile" fritap_cmd "$@"
}

# A keylog file is only good if it has lines AND every line is well formed.
# `readKeylogLine` once appended heap garbage past the NUL terminator, which
# produced a plausible-looking file full of unusable keys — hence both checks.
count_keys()      { [ -f "$1" ] && wc -l < "$1" | tr -d ' ' || echo 0; }
# count_malformed <keylog> [line regex]: lines not matching the regex (default: upper-case hex).
count_malformed() {
    [ -f "$1" ] || { echo 0; return; }
    grep -cvE "${2:-^[A-Z_0-9]+ [0-9A-F]+ [0-9A-F]+\$}" "$1" || true
}
alive() { kill -0 "$1" 2>/dev/null; }

# stop_fritap <pid> [outfile]: SIGINT (clean detach), SIGKILL after 25 s as a
# last resort. Sets FRITAP_DETACHED=1 only if friTap exited on its own within
# the bound AND logged the SIGINT teardown; FRITAP_RC is its exit status.
FRITAP_STOP_SECONDS=25
stop_fritap() {
    local pid=$1 outfile=${2:-} deadline=$((SECONDS + FRITAP_STOP_SECONDS)) killed=0
    FRITAP_DETACHED=0
    kill -INT "$pid" 2>/dev/null
    while alive "$pid" && [ $SECONDS -lt $deadline ]; do sleep 1; done
    if alive "$pid"; then kill -9 "$pid" 2>/dev/null; killed=1; fi
    wait "$pid" 2>/dev/null
    FRITAP_RC=$?
    if [ "$killed" = 0 ] && [ -n "$outfile" ] && grep -q "Ctrl+C detected" "$outfile" 2>/dev/null; then
        FRITAP_DETACHED=1
    fi
}

# ---------------------------------------------------------------------------
# checks
# ---------------------------------------------------------------------------

CHECK_NAMES=(
    "repo:unit-tests            python unit suite (what CI gates)"
    "repo:agent-build           agent bundle rebuilds and is deterministic"
    "capture:attach             attach mode captures well-formed keys"
    "capture:spawn              spawn mode captures without killing the target"
    "capture:handshake          both agent startup handshake stages complete"
    "timeout:fires              a too-small --script-load-timeout aborts with a real diagnostic"
    "timeout:disabled           --script-load-timeout 0 disables the bound"
    "probe:reports              --probe reports the platform and installs no hooks"
    "capture:openssl-python     a non-system libssl (Homebrew/pyenv OpenSSL) is hooked"
    "list:exits                 -ll lists libraries and exits without a capture"
    "gating:second-script       a gated child process is instrumented too"
    "chrome:keys                Chrome framework keys via the anchor locator (separate Chrome instance)"
    "chrome:plaintext           Chrome TCP plaintext: the nonce URL is in the .tap"
    "chrome:quic                Chrome QUICHE STREAM-frame hooks produce QUIC flows"
    "chrome:pages-load          pages load while attached; Chrome survives the detach"
    "chrome:learned-cache       a second attach hooks from the learned-offsets cache"
    "electron:hooks             a running Electron network helper gets keylog/plaintext/QUIC hooks"
)

if [ -f "$RIG_DIR/chromium_checks.sh" ]; then
    # shellcheck source=chromium_checks.sh
    . "$RIG_DIR/chromium_checks.sh"
else
    run_chrome_checks() {
        local c
        for c in keys plaintext quic pages-load learned-cache; do skip "chrome:$c  chromium_checks.sh is missing"; done
    }
    run_electron_checks() { skip "electron:hooks             chromium_checks.sh is missing"; }
fi

print_summary_and_exit() {
    section "summary"
    printf '%d passed, %d failed, %d skipped\n' "$PASS_COUNT" "$FAIL_COUNT" "$SKIP_COUNT"
    if [ "$FAIL_COUNT" -gt 0 ]; then
        printf '\nfailed checks:\n'
        for name in ${FAILED_NAMES+"${FAILED_NAMES[@]}"}; do printf '  - %s\n' "$name"; done
        printf '\nRe-run with --keep to inspect the raw output in the work dir.\n'
        exit 1
    fi
    printf '%sAll applicable checks passed.%s\n' "$C_OK" "$C_OFF"
    exit 0
}

if [ "$LIST_ONLY" = "1" ]; then
    printf 'checks:\n'
    for name in "${CHECK_NAMES[@]}"; do printf '  %s\n' "$name"; done
    exit 0
fi

# ---------------------------------------------------------------------------
# preflight
# ---------------------------------------------------------------------------

section "preflight"

if [ "$(uname -s)" != "Darwin" ]; then
    echo "This rig only works on macOS (it targets /usr/lib/libboringssl.dylib)." >&2
    exit 2
fi
detail "macOS $(sw_vers -productVersion) on $(uname -m)"

for tool in swiftc openssl python; do
    command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 2; }
done

SIP_STATUS=$(csrutil status 2>/dev/null | sed 's/^.*: //')
detail "System Integrity Protection: ${SIP_STATUS:-unknown}"
case "$SIP_STATUS" in
    *disabled*) ;;
    *) printf '%s note%s SIP appears enabled. Frida may be unable to attach; if the\n' \
              "$C_WARN" "$C_OFF"
       printf '      capture checks fail with a permission error, that is why.\n' ;;
esac

FRIDA_VERSION=$(python -c 'import frida; print(frida.__version__)' 2>/dev/null)
detail "frida ${FRIDA_VERSION:-<not importable>}"

WORK=$(mktemp -d /tmp/fritap-verify.XXXXXX)
trap cleanup EXIT
# Timestamp reference for "which debug logs did this run create" (see cleanup).
touch "$WORK/.started"
detail "work dir $WORK"

if [ "$CHROMIUM_ONLY" = "1" ]; then
    run_chrome_checks
    run_electron_checks
    print_summary_and_exit
fi

# ---------------------------------------------------------------------------
section "repo checks"
# ---------------------------------------------------------------------------

if ( cd "$REPO_ROOT" && python -m pytest tests/unit -q >"$WORK/pytest.out" 2>&1 ); then
    pass "repo:unit-tests            $(tail -1 "$WORK/pytest.out" | sed 's/^ *//')"
else
    fail "repo:unit-tests"
    detail "$(tail -3 "$WORK/pytest.out")"
fi

# The bundle is what actually runs in the target; a stale one silently
# exercises old code, and `tsc --noEmit` does NOT catch what frida-compile
# rejects. A failed build also leaves the previous bundle in place, so the
# "done. intercept agent:" and "all requested bundles built." lines are the
# only trustworthy signal.
if ( cd "$REPO_ROOT" && ./dev/compile_agent.sh >"$WORK/build1.out" 2>&1 ) \
   && grep -q "done. intercept agent:" "$WORK/build1.out" \
   && grep -q "all requested bundles built." "$WORK/build1.out"; then
    HASH1=$(md5 -q "$REPO_ROOT/friTap/fritap_agent.js")
    ( cd "$REPO_ROOT" && ./dev/compile_agent.sh >"$WORK/build2.out" 2>&1 )
    HASH2=$(md5 -q "$REPO_ROOT/friTap/fritap_agent.js")
    if [ "$HASH1" = "$HASH2" ]; then
        pass "repo:agent-build           deterministic ($(grep -o 'intercept agent: *[0-9]*' "$WORK/build1.out" | tr -s ' ') bytes)"
    else
        fail "repo:agent-build           two builds differ ($HASH1 vs $HASH2)"
    fi
else
    fail "repo:agent-build           compile_agent.sh did not report success"
    detail "$(tail -3 "$WORK/build1.out")"
fi

# ---------------------------------------------------------------------------
section "building the rig"
# ---------------------------------------------------------------------------

cd "$WORK" || exit 2
# SAN as well as CN: the rig's client trusts the cert unconditionally, so this
# is not strictly needed today, but a cert without a subjectAltName is rejected
# outright by anything doing real validation — cheap insurance if the client is
# ever pointed at a stricter stack.
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 7 -nodes \
        -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1 \
    || { echo "cert generation failed" >&2; exit 2; }
cp "$RIG_DIR/tls_server.py" "$WORK/tls_server.py"
swiftc -O "$RIG_DIR/tls_client.swift" -o "$WORK/tls_client" 2>"$WORK/swiftc.out" \
    || { echo "swiftc failed:"; cat "$WORK/swiftc.out"; exit 2; }
if [ -f "$RIG_DIR/tls_fork.swift" ]; then
    swiftc -O "$RIG_DIR/tls_fork.swift" -o "$WORK/tls_fork" 2>>"$WORK/swiftc.out" \
        || detail "tls_fork.swift failed to build; the gating check will be skipped"
fi
detail "cert, server and targets built"

python3 "$WORK/tls_server.py" >"$WORK/server.out" 2>&1 &
SERVER_PID=$!
# disown so the shell does not print a "Killed: 9" job notice after the
# summary when the EXIT trap tears these down — it reads as an error.
disown "$SERVER_PID" 2>/dev/null
STARTED_PIDS+=("$SERVER_PID")
sleep 2
alive "$SERVER_PID" || { echo "TLS server failed to start:"; cat "$WORK/server.out"; exit 2; }
detail "HTTPS server up on 127.0.0.1:8443 (pid $SERVER_PID)"

"$WORK/tls_client" >"$WORK/client.out" 2>&1 &
CLIENT_PID=$!
disown "$CLIENT_PID" 2>/dev/null
STARTED_PIDS+=("$CLIENT_PID")
sleep 5
if ! grep -q "status=200" "$WORK/client.out"; then
    echo "TLS client never completed a request:"; cat "$WORK/client.out"; exit 2
fi
detail "client doing TLS rounds (pid $CLIENT_PID)"

# ---------------------------------------------------------------------------
section "capture checks"
# ---------------------------------------------------------------------------

# --- attach mode -----------------------------------------------------------
run_fritap 35 "$WORK/attach.out" -k "$WORK/keys_attach.log" -v -do "$CLIENT_PID"
KEYS=$(count_keys "$WORK/keys_attach.log")
BAD=$(count_malformed "$WORK/keys_attach.log")
if [ "$KEYS" -gt 0 ] && [ "$BAD" -eq 0 ] && alive "$CLIENT_PID"; then
    pass "capture:attach             $KEYS keys, $BAD malformed, target alive"
else
    fail "capture:attach             $KEYS keys, $BAD malformed, target alive=$(alive "$CLIENT_PID" && echo yes || echo NO)"
    detail "$(tail -5 "$WORK/attach.out")"
fi

# --- spawn mode ------------------------------------------------------------
# This is the path that used to kill Apple targets outright: platform
# detection messaged NSProcessInfo, which kills a suspended spawned process.
run_fritap 35 "$WORK/spawn.out" -s -k "$WORK/keys_spawn.log" -v -do "$WORK/tls_client"
KEYS=$(count_keys "$WORK/keys_spawn.log")
BAD=$(count_malformed "$WORK/keys_spawn.log")
if [ "$KEYS" -gt 0 ] && [ "$BAD" -eq 0 ]; then
    pass "capture:spawn              $KEYS keys, $BAD malformed"
else
    fail "capture:spawn              $KEYS keys, $BAD malformed"
    detail "$(tail -5 "$WORK/spawn.out")"
fi

# --- the startup handshake completed --------------------------------------
# The agent blocks in recv().wait() twice during script.load(); if the host
# fails to answer either request, load() never returns. Seeing both stages is
# the only direct evidence the handshake round-trips.
CFG=$(grep -c "stage: config-handshake" "$WORK/spawn.out" || true)
ANTI=$(grep -c "stage: anti-handshake" "$WORK/spawn.out" || true)
if [ "$CFG" -ge 1 ] && [ "$ANTI" -ge 1 ]; then
    pass "capture:handshake          config-handshake x$CFG, anti-handshake x$ANTI"
else
    fail "capture:handshake          config-handshake x$CFG, anti-handshake x$ANTI (expected >=1 each)"
fi

# ---------------------------------------------------------------------------
section "script-load timeout"
# ---------------------------------------------------------------------------

# A deliberately unreachable bound must abort with an actionable message
# instead of hanging, and must leave the target running.
#
# 0.001s, not something like 0.05s: a warm macOS host loads the whole 2.3 MB
# agent bundle in well under 50 ms, so a bound anywhere near the real load time
# makes this check a coin flip (measured: 0.05s fired on 1 of 2 attempts, while
# 0.001s fired on 3 of 3). The bound only has to be unreachable, not realistic.
run_fritap 45 "$WORK/timeout.out" --script-load-timeout 0.001 -k "$WORK/keys_to.log" "$CLIENT_PID"
if grep -q "did not finish loading" "$WORK/timeout.out" \
   && grep -q "compile_agent.sh" "$WORK/timeout.out" \
   && grep -q "script-load-timeout" "$WORK/timeout.out" \
   && alive "$CLIENT_PID"; then
    pass "timeout:fires              aborted with hints, target survived"
    detail "$(grep 'did not finish loading' "$WORK/timeout.out" | head -1)"
else
    fail "timeout:fires"
    detail "$(tail -6 "$WORK/timeout.out")"
fi

run_fritap 30 "$WORK/nobound.out" --script-load-timeout 0 -k "$WORK/keys_off.log" "$CLIENT_PID"
KEYS=$(count_keys "$WORK/keys_off.log")
BAD=$(count_malformed "$WORK/keys_off.log")
if [ "$KEYS" -gt 0 ] && [ "$BAD" -eq 0 ] \
   && ! grep -q "did not finish loading" "$WORK/nobound.out"; then
    pass "timeout:disabled           $KEYS keys with the bound switched off"
else
    fail "timeout:disabled           $KEYS keys, $BAD malformed"
    detail "$(tail -5 "$WORK/nobound.out")"
fi

# ---------------------------------------------------------------------------
section "probe mode"
# ---------------------------------------------------------------------------

if ! ( cd "$REPO_ROOT" && python -m friTap.friTap --help 2>&1 ) | grep -q -- "--probe"; then
    skip "probe:reports              this friTap build has no --probe flag"
else
    run_fritap 30 "$WORK/probe.out" --probe "$CLIENT_PID"
    # Probe must report the platform and must NOT install hooks: the giveaway
    # for an install is a keylog_callback / hooking line in the output.
    if grep -qi "platform report" "$WORK/probe.out" && alive "$CLIENT_PID"; then
        if grep -qi "will be hooked\|invoking keylog_callback" "$WORK/probe.out"; then
            fail "probe:reports              reported, but hooks were installed anyway"
            detail "$(grep -i 'will be hooked\|invoking keylog_callback' "$WORK/probe.out" | head -2)"
        else
            pass "probe:reports              $(grep -i 'platform report' "$WORK/probe.out" | head -1 | sed 's/^.*platform report/platform report/I')"
        fi
    else
        fail "probe:reports              no platform report in the output"
        detail "$(tail -6 "$WORK/probe.out")"
    fi
fi

# ---------------------------------------------------------------------------
section "genuine OpenSSL (non-system libssl)"
# ---------------------------------------------------------------------------

# The bug: a versioned libssl.<n>.dylib outside /usr/lib matched NO registry
# entry on macOS. The LibreSSL entry required /usr/lib, the "Python OpenSSL"
# entry required "python" in the path (a Homebrew path has no such component),
# and the generic entry excluded the versioned name outright. friTap attached,
# installed nothing, and logged nothing — silently.
#
# CPython's ssl module is the easiest way to load such a library: on a Homebrew
# or pyenv interpreter it links /opt/homebrew/opt/openssl@3/lib/libssl.3.dylib.
# If this interpreter's _ssl links Apple's own libssl instead, there is nothing
# to prove here and the check skips rather than passing vacuously.
PY_SSL_LIB=$(otool -L "$(python -c 'import _ssl; print(_ssl.__file__)' 2>/dev/null)" 2>/dev/null \
             | awk '/libssl/ {print $1; exit}')
if [ -z "$PY_SSL_LIB" ]; then
    skip "capture:openssl-python     could not determine this python's libssl"
elif [ "${PY_SSL_LIB#/usr/lib/}" != "$PY_SSL_LIB" ]; then
    skip "capture:openssl-python     this python links the system libssl ($PY_SSL_LIB)"
else
    cp "$RIG_DIR/tls_client_openssl.py" "$WORK/tls_client_openssl.py"
    python "$WORK/tls_client_openssl.py" >"$WORK/py_client.out" 2>&1 &
    PY_CLIENT_PID=$!
    disown "$PY_CLIENT_PID" 2>/dev/null
    STARTED_PIDS+=("$PY_CLIENT_PID")
    sleep 4
    if ! grep -q "status=True" "$WORK/py_client.out"; then
        skip "capture:openssl-python     python TLS client never completed a round"
        detail "$(tail -3 "$WORK/py_client.out")"
    else
        run_fritap 35 "$WORK/py_openssl.out" \
            -k "$WORK/keys_openssl.log" -v -do "$PY_CLIENT_PID"
        PY_KEYS=$(count_keys "$WORK/keys_openssl.log")
        PY_BAD=$(count_malformed "$WORK/keys_openssl.log")
        # Assert on the SPECIFIC module, not just "some libssl". A CPython
        # process loads Apple's /usr/lib/libssl.48.dylib as well, and that one
        # was already hooked before this fix — so a grep for a bare "libssl.*
        # hooked" passes whether or not the library under test was routed.
        # Matching the basename from otool is what makes this check honest.
        PY_SSL_NAME=$(basename "$PY_SSL_LIB")
        PY_HOOKED=$(grep -c "$PY_SSL_NAME found & will be hooked" "$WORK/py_openssl.out" || true)
        # Exactly one, never two: the three libssl entries are a partition, and a
        # second hook on the same module would mean two executors installed.
        # Keys must also be attributable to THIS module, not to the system one.
        PY_KEYLOG=$(grep -c "keylog_callback.*($PY_SSL_NAME)" "$WORK/py_openssl.out" || true)
        if [ "$PY_KEYS" -gt 0 ] && [ "$PY_BAD" -eq 0 ] \
           && [ "$PY_HOOKED" -eq 1 ] && [ "$PY_KEYLOG" -ge 1 ]; then
            pass "capture:openssl-python     $PY_KEYS keys, $PY_BAD malformed, $PY_SSL_NAME hooked once and yielding keys"
            detail "$PY_SSL_LIB"
            detail "$(grep -m1 "$PY_SSL_NAME found & will be hooked" "$WORK/py_openssl.out" | sed 's/^ *//')"
        else
            fail "capture:openssl-python     $PY_KEYS keys, $PY_BAD malformed, $PY_SSL_NAME hooked ${PY_HOOKED}x (need exactly 1), keylog lines=$PY_KEYLOG (need >=1)"
            detail "$(grep -i "libssl\|will be hooked\|registry: skipping" "$WORK/py_openssl.out" | tail -8)"
        fi
    fi
fi

# ---------------------------------------------------------------------------
section "library listing (-ll must not start a capture)"
# ---------------------------------------------------------------------------

# `-ll` documents that it "will not start the logging process, but only list the
# libraries and exit". It used to print the listing and then fall through into a
# full capture session, blocking in wait_for_completion() until the user gave up
# and hit Ctrl+C. The unit tests cannot reproduce that: the fall-through only
# hangs once a real attach succeeds, which is exactly what this check does.
#
# The bound used to be 240s because tlsLibHunter's scan was itself pathologically
# slow on macOS: it re-scanned the 587 MB shared dyld-cache range once per module
# per pattern, so six modules took ~113s. With that fixed (tlsLibHunter's
# moduleScanRegions filters the shared range) a full -ll is ~1-2s, so 60s is
# ample and still leaves room for a busier target. The discriminator here remains
# the capture-session banner plus a clean exit, not wall-clock alone.
if ! ( cd "$REPO_ROOT" && python -c 'import tlslibhunter' >/dev/null 2>&1 ); then
    skip "list:exits                 tlsLibHunter not importable in this env"
else
    LL_T0=$SECONDS
    run_fritap 60 "$WORK/listlibs.out" -ll "$CLIENT_PID"
    LL_RC=$?
    LL_SECS=$((SECONDS - LL_T0))
    LL_DETECT=$(grep -c "TLS/SSL Library Detection" "$WORK/listlibs.out" || true)
    # The fall-through's fingerprint. A run that prints these started a capture
    # session it promised not to start.
    LL_SESSION=$(grep -c "Start logging\|Press Ctrl+C to stop logging" "$WORK/listlibs.out" || true)
    if [ "$LL_RC" -eq 0 ] && [ "$LL_SECS" -lt 60 ] \
       && [ "$LL_DETECT" -ge 1 ] && [ "$LL_SESSION" -eq 0 ]; then
        pass "list:exits                 exited 0 after ${LL_SECS}s, listing printed, no capture session"
        detail "$(grep -m1 'Libraries found' "$WORK/listlibs.out" | sed 's/^ *//')"
    else
        fail "list:exits                 rc=$LL_RC after ${LL_SECS}s (bound 60s), detection blocks=$LL_DETECT (need >=1), capture-session lines=$LL_SESSION (need 0)"
        detail "$(tail -6 "$WORK/listlibs.out")"
    fi
fi

# ---------------------------------------------------------------------------
section "child gating (second instrumented script)"
# ---------------------------------------------------------------------------

# The bug: with more than one instrumented process in a session, the second
# script.load() used to hang forever waiting for a handshake reply the host
# only ever sent once. Two config-handshake breadcrumbs == two scripts loaded.
if [ ! -x "$WORK/tls_fork" ]; then
    skip "gating:second-script       no tls_fork binary in this rig"
else
    run_fritap 45 "$WORK/gating.out" -s --enable_child_gating \
        -k "$WORK/keys_gate.log" -v -do "$WORK/tls_fork"
    CFG=$(grep -c "stage: config-handshake" "$WORK/gating.out" || true)
    ANTI=$(grep -c "stage: anti-handshake" "$WORK/gating.out" || true)
    CHILD=$(grep -c "Attached to child process" "$WORK/gating.out" || true)
    KEYS=$(count_keys "$WORK/keys_gate.log")
    BAD=$(count_malformed "$WORK/keys_gate.log")
    # The single-process spawn check above pins the handshake count at 1, which
    # is what makes a second pair here attributable to the gated child rather
    # than to a retry.
    if [ "$CFG" -ge 2 ] && [ "$ANTI" -ge 2 ] && [ "$CHILD" -ge 1 ] \
       && [ "$KEYS" -gt 0 ] && [ "$BAD" -eq 0 ]; then
        pass "gating:second-script       $CFG handshake pairs, $CHILD child attached, $KEYS keys, $BAD malformed"
    else
        fail "gating:second-script       $CFG config-handshakes (need >=2), $CHILD children, $KEYS keys, $BAD malformed"
        detail "$(grep -i 'child\|handshake\|Unanswered' "$WORK/gating.out" | tail -5)"
    fi
fi

run_chrome_checks
run_electron_checks

print_summary_and_exit
