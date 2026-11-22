# Chrome / Electron checks for verify.sh (sourced; uses its helpers and $WORK).
#
# Chrome: a separate instance (own profile, NetworkServiceInProcess2 so TLS runs
# in the browser process, DevTools port to drive it) is attached twice with one
# learned-offsets dir: the first attach scans the framework, the second must hook
# from the cache. Each attach is ended with SIGINT so friTap detaches cleanly.
# Electron: attach to an already-running Electron network helper, if any.

CHROME_APP="/Applications/Google Chrome.app"
CHROME_NONCE="n$RANDOM$RANDOM"
# httpbin.org is TCP (HTTP/2): its URL must show up in the .tap's request flows.
CHROME_URLS=("https://httpbin.org/get?n=$CHROME_NONCE" "https://example.com/?n=$CHROME_NONCE"
             "https://cloudflare-quic.com/?n=$CHROME_NONCE" "https://www.google.com/search?q=$CHROME_NONCE")
KEYLOG_LINE_RE='^[A-Z_0-9]+ [0-9a-fA-F]{64} [0-9a-fA-F]{64}([0-9a-fA-F]{32})?$'

# Every DevTools call is bounded: a hung browser must fail a check, not hang the rig.
CURL_DEVTOOLS=(curl -s --connect-timeout 3 --max-time 10)

count_malformed_ci() { count_malformed "$1" "$KEYLOG_LINE_RE"; }

free_port() { python -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }

# wait_for <seconds> <file> <regex>: true once the regex appears in the file.
wait_for() {
    local deadline=$((SECONDS + $1))
    while [ $SECONDS -lt $deadline ]; do
        grep -qE "$3" "$2" 2>/dev/null && return 0
        sleep 1
    done
    return 1
}

# start_fritap <outfile> <target pid> <fritap args...>: background friTap, sets
# FRITAP_PID (the python process: fritap_cmd execs) and registers it for cleanup.
# Stop it with stop_fritap (verify.sh).
start_fritap() {
    local outfile=$1 target=$2
    shift 2
    FRITAP_LEARNED_OFFSETS_DIR="$WORK/learned" fritap_cmd "$@" "$target" >"$outfile" 2>&1 &
    FRITAP_PID=$!
    FRITAP_PIDS+=("$FRITAP_PID")
}

# attach_until_hooked <name> <pid> <settle secs> [cmd...]: attach friTap with
# $WORK/<name>.{out,keylog,tap}, wait for the keylog and QUIC hooks, settle, run
# cmd while still attached, then stop with SIGINT. Sets HOOK_SECS (-1: no hook).
attach_until_hooked() {
    local name=$1 pid=$2 settle=$3 t0=$SECONDS
    shift 3
    start_fritap "$WORK/$name.out" "$pid" -k "$WORK/$name.keylog" --tap "$WORK/$name.tap" -do
    HOOK_SECS=-1
    wait_for 90 "$WORK/$name.out" "keylog hooks installed via anchor-locator" && HOOK_SECS=$((SECONDS - t0))
    # The plaintext and QUIC locators finish a few seconds after the keylog hook.
    wait_for 30 "$WORK/$name.out" "Hooked QuicConnection::OnStreamFrame" || true
    sleep "$settle"
    [ $# -gt 0 ] && "$@"
    stop_fritap "$FRITAP_PID" "$WORK/$name.out"
    detach_note "$WORK/$name.out"
}

# detach_note <outfile>: one detail line explaining an unclean stop.
detach_note() {
    [ "$FRITAP_DETACHED" = 1 ] && return
    detail "friTap did not detach cleanly (rc=$FRITAP_RC; no 'Ctrl+C detected' or needed SIGKILL); tail of $(basename "$1"):"
    detail "$(tail -n 3 "$1" 2>/dev/null)"
}

# Page titles of the nonce tabs, one per line ("" while a page still loads).
chrome_titles() {
    "${CURL_DEVTOOLS[@]}" "http://127.0.0.1:$1/json/list" | python -c '
import json, sys
for t in json.load(sys.stdin):
    if t.get("type") == "page" and sys.argv[1] in t.get("url", ""): print(repr(t.get("title", "")))' "$CHROME_NONCE" 2>/dev/null
}

# chrome_load_pages <port>: open every nonce URL, echo how many got a title.
# A loaded page has a title; an empty one (or no DevTools answer) means the
# network thread or the whole browser is stalled.
chrome_load_pages() {
    local url loaded=0 deadline=$((SECONDS + 20))
    for url in "${CHROME_URLS[@]}"; do
        "${CURL_DEVTOOLS[@]}" -X PUT "http://127.0.0.1:$1/json/new?$url" >/dev/null
        sleep 1
    done
    # A title can arrive before the page's remaining requests.
    sleep 3
    while :; do
        loaded=$(chrome_titles "$1" | grep -vc "^''$" || true)
        [ "$loaded" -ge "${#CHROME_URLS[@]}" ] || [ $SECONDS -ge $deadline ] && break
        sleep 1
    done
    echo "$loaded"
}

# chrome_record_pages <port>: sets CHROME_LOADED.
chrome_record_pages() { CHROME_LOADED=$(chrome_load_pages "$1"); }

# chrome_responsive <pid> <port>: process alive AND DevTools still answers.
chrome_responsive() {
    alive "$1" && "${CURL_DEVTOOLS[@]}" -o /dev/null "http://127.0.0.1:$2/json/version"
}

# tap_summary <tap>: "<flows> <quic flows> <tcp flows with the nonce URL>".
tap_summary() {
    ( cd "$REPO_ROOT" && python -c '
import sys
from friTap.flow.tap_reader import TapReader
with TapReader(sys.argv[1]) as r:
    r.open()
    s = r.read_flow_summaries()
print(len(s), sum(f.transport == "quic" for f in s),
      sum(f.transport == "tls" and sys.argv[2] in (f.url or "") for f in s))' "$1" "$CHROME_NONCE" 2>/dev/null ) || echo "0 0 0"
}

# chrome_session <tag>: one fresh Chrome instance, one attach, URLs loaded, clean detach.
# Leaves $WORK/chrome_<tag>.{out,keylog,tap} and sets CHROME_{ALIVE,LOADED,PAGES,HOOK_SECS,DETACHED}.
# CHROME_ALIVE is only checked after friTap has exited, so it really means "after detach".
chrome_session() {
    local tag=$1 port pid
    port=$(free_port)
    open -na "Google Chrome" --args --user-data-dir="$WORK/chrome_ud" \
        --enable-features=NetworkServiceInProcess2 --no-first-run --no-default-browser-check \
        --remote-debugging-port="$port" about:blank
    pid=""
    for _ in $(seq 1 30); do
        pid=$(pgrep -f "MacOS/Google Chrome --user-data-dir=$WORK/chrome_ud" | head -1)
        [ -n "$pid" ] && "${CURL_DEVTOOLS[@]}" -o /dev/null "http://127.0.0.1:$port/json/version" && break
        sleep 0.5
    done
    CHROME_ALIVE=0; CHROME_LOADED=0; CHROME_PAGES=${#CHROME_URLS[@]}; CHROME_HOOK_SECS=-1; CHROME_DETACHED=0
    [ -n "$pid" ] || { detail "chrome ($tag): browser did not start"; return 1; }
    STARTED_PIDS+=("$pid")
    sleep 3
    attach_until_hooked "chrome_$tag" "$pid" 3 chrome_record_pages "$port"
    CHROME_HOOK_SECS=$HOOK_SECS
    CHROME_DETACHED=$FRITAP_DETACHED
    sleep 2
    chrome_responsive "$pid" "$port" && CHROME_ALIVE=1
    kill -TERM "$pid" 2>/dev/null
    for _ in $(seq 1 10); do alive "$pid" || break; sleep 0.5; done
    alive "$pid" && kill -9 "$pid" 2>/dev/null
    return 0
}

run_chrome_checks() {
    section "Chrome (Google Chrome Framework, arm64)"
    if [ "$(uname -m)" != "arm64" ] || [ ! -d "$CHROME_APP" ]; then
        for c in keys plaintext quic pages-load learned-cache; do skip "chrome:$c  no Google Chrome on an arm64 Mac"; done
        return
    fi
    mkdir -p "$WORK/learned"
    chrome_session cold
    local keys bad tap flows quic nonce
    keys=$(count_keys "$WORK/chrome_cold.keylog")
    bad=$(count_malformed_ci "$WORK/chrome_cold.keylog")
    local traffic; traffic=$(grep -c "^CLIENT_TRAFFIC_SECRET_0 " "$WORK/chrome_cold.keylog" 2>/dev/null || true)
    if [ "$keys" -gt 0 ] && [ "$bad" -eq 0 ] && [ "${traffic:-0}" -gt 0 ]; then
        pass "chrome:keys                $keys lines ($traffic connections), 0 malformed; anchor locator hooked after ${CHROME_HOOK_SECS}s"
    else
        fail "chrome:keys                $keys lines, $bad malformed, ${traffic:-0} CLIENT_TRAFFIC_SECRET_0"
        detail "$(grep -m3 'anchor-locator\]' "$WORK/chrome_cold.out")"
    fi
    read -r flows quic nonce <<<"$(tap_summary "$WORK/chrome_cold.tap")"
    if grep -q "hooked statically linked BoringSSL for TCP TLS plaintext" "$WORK/chrome_cold.out" && [ "$nonce" -ge 1 ]; then
        pass "chrome:plaintext           SSL_write located; $nonce TCP flow(s) with the nonce URL of $flows flows"
    else
        fail "chrome:plaintext           $nonce TCP flows with the nonce URL ($flows flows)"
        detail "$(grep -m2 'BoringSSL plaintext\]' "$WORK/chrome_cold.out")"
    fi
    if grep -q "Hooked QuicConnection::OnStreamFrame" "$WORK/chrome_cold.out" && [ "$quic" -ge 1 ]; then
        pass "chrome:quic                STREAM-frame hooks installed; $quic QUIC flows"
    else
        fail "chrome:quic                $quic QUIC flows"
        detail "$(grep -m2 'Google QUICHE\]' "$WORK/chrome_cold.out")"
    fi
    if [ "$CHROME_LOADED" -eq "$CHROME_PAGES" ] && [ "$CHROME_DETACHED" -eq 1 ] && [ "$CHROME_ALIVE" -eq 1 ]; then
        pass "chrome:pages-load          $CHROME_LOADED/$CHROME_PAGES pages loaded while attached; friTap detached on SIGINT; browser responsive after detach"
    else
        fail "chrome:pages-load          $CHROME_LOADED/$CHROME_PAGES pages loaded, detached=$CHROME_DETACHED, responsive after detach=$CHROME_ALIVE"
    fi
    chrome_session warm
    local hits; hits=$(grep -cE "ssl_log_secret for Google Chrome Framework from learned cache|STREAM-frame API resolved in [0-9]+ ms \(from learned cache\)" "$WORK/chrome_warm.out" || true)
    # Same page-load + detach bar as pages-load: a cache hit that hangs the browser is a failure.
    if [ "${hits:-0}" -ge 2 ] && [ "$(count_keys "$WORK/chrome_warm.keylog")" -gt 0 ] \
       && [ "$CHROME_LOADED" -eq "$CHROME_PAGES" ] && [ "$CHROME_DETACHED" -eq 1 ] && [ "$CHROME_ALIVE" -eq 1 ]; then
        pass "chrome:learned-cache       second attach hooked from the cache ($hits hits) after ${CHROME_HOOK_SECS}s; $(count_keys "$WORK/chrome_warm.keylog") key lines; $CHROME_LOADED/$CHROME_PAGES pages loaded; clean detach"
    else
        fail "chrome:learned-cache       $hits cache hits (need 2), $(count_keys "$WORK/chrome_warm.keylog") keys, $CHROME_LOADED/$CHROME_PAGES pages loaded, detached=$CHROME_DETACHED, responsive=$CHROME_ALIVE"
    fi
}

# A running Electron network-service helper: "<pid>" or empty.
electron_helper_pid() {
    local pid
    for pid in $(pgrep -f 'utility-sub-type=network.mojom.NetworkService'); do
        lsof -p "$pid" 2>/dev/null | grep -q "Electron Framework.framework" && { echo "$pid"; return; }
    done
}

run_electron_checks() {
    section "Electron (Electron Framework, arm64)"
    local pid
    pid=$( [ "$(uname -m)" = "arm64" ] && electron_helper_pid )
    if [ -z "$pid" ]; then
        skip "electron:hooks             no running Electron network helper (start e.g. Obsidian or Slack)"
        return
    fi
    detail "attaching to $(ps -o comm= -p "$pid" | sed 's#.*/##') (pid $pid)"
    attach_until_hooked electron "$pid" 5
    sleep 2
    local k p q bad
    k=$(grep -c "Electron Framework: keylog hooks installed" "$WORK/electron.out" || true)
    p=$(grep -c "Electron Framework: hooked statically linked BoringSSL" "$WORK/electron.out" || true)
    q=$(grep -c "Hooked QuicConnection::OnStreamFrame .* in Electron Framework" "$WORK/electron.out" || true)
    bad=$(count_malformed_ci "$WORK/electron.keylog")
    if [ "$k" -ge 1 ] && [ "$p" -ge 1 ] && [ "$q" -ge 1 ] && [ "$bad" -eq 0 ] && [ "$FRITAP_DETACHED" -eq 1 ] && alive "$pid"; then
        pass "electron:hooks             keylog, plaintext and QUIC hooks installed; helper alive after detach; $(count_keys "$WORK/electron.keylog") key lines (idle app: 0 is fine)"
    else
        fail "electron:hooks             keylog=$k plaintext=$p quic=$q malformed=$bad detached=$FRITAP_DETACHED alive=$(alive "$pid" && echo 1 || echo 0)"
    fi
}
