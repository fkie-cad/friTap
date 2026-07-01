#!/bin/bash
# End-to-end Wine + friTap test that ACTUALLY produces TLS keys.
#
# What it does:
#   1. Creates a VBS probe script that fires 120 HTTPS requests through
#      Wine's WinHTTP → schannel → gnutls path (rotating hosts so each is a
#      fresh handshake, defeating TLS session resumption).
#   2. Launches cscript.exe under `wine64` via `setsid` so it survives the
#      launching shell exiting.
#   3. Waits until wine has fully loaded (ntdll.dll, kernelbase, gnutls) so
#      the isWine() check inside the agent detects the process correctly.
#   4. Attaches friTap by PID with --experimental.
#   5. Streams progress every 3s until keys land, fritap dies, or timeout.
#
# Requirements:
#   * Wine ≥9 on Linux with libgnutls.so.30 installed (native x86_64 build).
#   * WINEPREFIX (default $HOME/.wine) owned by the current uid — this script
#     refuses to run under sudo (Wine will reject a foreign-owned prefix).
#   * Frida can attach to processes you own; ensure
#     `sysctl kernel.yama.ptrace_scope=0` if you hit ptrace denials.
#
# Why not spawn mode (-s /usr/lib/wine/wine64 …)?
#   Wine 9's preloader execve's itself within milliseconds of spawn+resume;
#   Frida loses the session before the agent finishes loading. See the footer
#   of dev/wine_spawn_vlc_test.sh for the full analysis. Attach-mode after
#   Wine has fully initialised is the only reliable path today.
#
# ARGV[1] (optional): comma-separated URLs to probe. Defaults to a set of
# stable HTTPS endpoints known to work through schannel.

set -eu

# --- Config ---
FRITAP="${FRITAP:-/home/daniel/research/memslicer/env/bin/fritap}"
WINE_BIN="${WINE_BIN:-/usr/lib/wine/wine64}"
CSCRIPT_EXE="${CSCRIPT_EXE:-/home/daniel/.wine/drive_c/windows/system32/cscript.exe}"
KEYS_LOG="${KEYS_LOG:-/tmp/wine_e2e_keys.log}"
WINE_PATH_VBS="C:\\temp\\https_probe.vbs"
HOST_PATH_VBS="${WINEPREFIX:-$HOME/.wine}/drive_c/temp/https_probe.vbs"
DEFAULT_HOSTS='"www.example.com","www.iana.org","www.mozilla.org","www.python.org","www.wikipedia.org","www.debian.org","www.gnu.org","www.rfc-editor.org"'
HOSTS_LITERAL="${1:-$DEFAULT_HOSTS}"

# --- Sanity: don't run as root against a user-owned prefix ---
if [ "$(id -u)" = "0" ]; then
    echo "[-] Refusing to run as root: Wine will reject any user-owned WINEPREFIX." >&2
    exit 1
fi
WPRE="${WINEPREFIX:-$HOME/.wine}"
POWNER="$(stat -c %u "$WPRE" 2>/dev/null || echo -1)"
if [ "$POWNER" != "$(id -u)" ]; then
    echo "[-] WINEPREFIX '$WPRE' owned by uid $POWNER, running as uid $(id -u)." >&2
    exit 1
fi

# --- Precheck binaries ---
[ ! -x "$FRITAP" ]     && { echo "[-] friTap not found at $FRITAP"; exit 1; }
[ ! -x "$WINE_BIN" ]   && { echo "[-] wine64 not at $WINE_BIN"; exit 1; }
[ ! -f "$CSCRIPT_EXE" ] && { echo "[-] cscript.exe not at $CSCRIPT_EXE"; exit 1; }

# --- Write the VBS probe (each iteration is a distinct handshake) ---
mkdir -p "$(dirname "$HOST_PATH_VBS")"
cat > "$HOST_PATH_VBS" <<VBS
hosts = Array($HOSTS_LITERAL)
n = UBound(hosts) + 1
For i = 1 To 120
    On Error Resume Next
    Set http = CreateObject("WinHttp.WinHttpRequest.5.1")
    h = hosts(i Mod n)
    http.Open "GET", "https://" & h & "/?p=" & i, False
    http.Send
    WScript.Echo "probe " & i & " " & h & " status=" & http.Status
    Set http = Nothing
    Err.Clear
    WScript.Sleep 1500
Next
VBS

# --- Launch cscript (setsid so it survives shell exit) ---
LOG_VBS="$(mktemp -t wine_e2e_vbs.XXXXXX.log)"
LOG_FRITAP="$(mktemp -t wine_e2e_fritap.XXXXXX.log)"
rm -f "$KEYS_LOG"
echo "[*] Launching cscript via $WINE_BIN..."
setsid "$WINE_BIN" "$CSCRIPT_EXE" "//nologo" "$WINE_PATH_VBS" > "$LOG_VBS" 2>&1 &
WINE_LP=$!

# --- Wait for the cscript wine process to be visible + settled ---
CS=""
echo "[*] Waiting up to 15s for cscript wine process (with wine indicators mapped)..."
for i in $(seq 1 30); do
    sleep 0.5
    for p in $(ls /proc | grep -E '^[0-9]+$' 2>/dev/null); do
        exe=$(readlink /proc/$p/exe 2>/dev/null) || continue
        case "$exe" in "$WINE_BIN"|/usr/lib/wine/wine|/usr/lib/wine/wine64) ;; *) continue;; esac
        cmd=$(cat /proc/$p/cmdline 2>/dev/null | tr '\0' ' ')
        case "$cmd" in *cscript.exe*) CS=$p; break;; esac
    done
    if [ -n "$CS" ] && grep -q wine64 /proc/$CS/maps 2>/dev/null; then break; fi
done

if [ -z "$CS" ] || ! kill -0 "$CS" 2>/dev/null; then
    echo "[-] cscript did not come up. VBS launcher output:"
    head -20 "$LOG_VBS"
    kill $WINE_LP 2>/dev/null || true
    exit 1
fi
echo "[*] cscript PID: $CS  (exe: $(readlink /proc/$CS/exe))"

# --- Attach friTap ---
echo "[*] Attaching friTap → $CS (writing keys to $KEYS_LOG)..."
"$FRITAP" --experimental -k "$KEYS_LOG" -v -do "$CS" > "$LOG_FRITAP" 2>&1 &
FTPID=$!

# --- Monitor for 90s ---
for i in $(seq 1 30); do
    sleep 3
    K=$(wc -l < "$KEYS_LOG" 2>/dev/null | awk '{print $1}')
    A=$(kill -0 $FTPID 2>/dev/null && echo alive || echo done)
    echo "[t+$((i*3))s] keys=${K:-0} fritap=$A"
    if [ "${K:-0}" -ge 3 ]; then break; fi
    if [ "$A" = "done" ]; then break; fi
done

kill $FTPID 2>/dev/null || true
kill $WINE_LP 2>/dev/null || true
wait 2>/dev/null || true

# --- Report ---
echo
echo "=================================================================="
echo "  RESULT"
echo "=================================================================="
K=$(wc -l < "$KEYS_LOG" 2>/dev/null | awk '{print $1}')
if [ "${K:-0}" -ge 1 ]; then
    echo "  ✓ Captured ${K} keylog line(s) in $KEYS_LOG"
    echo
    echo "  First 3 lines:"
    head -3 "$KEYS_LOG" | sed 's/^/    /'
    echo
    DYN=$(grep -c "gnutls dyn" "$LOG_FRITAP" 2>/dev/null || echo 0)
    if [ "$DYN" -gt 0 ]; then
        echo "  Dynamic pattern discovery:"
        grep "gnutls dyn" "$LOG_FRITAP" | sed 's/^/    /'
    fi
    rc=0
else
    echo "  ✗ No keys captured."
    echo
    echo "  Last friTap diagnostic lines:"
    grep -E "gnutls diag|Wine|libgnutls" "$LOG_FRITAP" 2>/dev/null | tail -15 | sed 's/^/    /'
    echo
    echo "  Last VBS output:"
    grep "probe" "$LOG_VBS" 2>/dev/null | tail -5 | sed 's/^/    /'
    rc=1
fi
echo
echo "  Full logs:"
echo "    friTap: $LOG_FRITAP"
echo "    cscript stdout: $LOG_VBS"
echo "    keys: $KEYS_LOG"
echo "=================================================================="

exit $rc
