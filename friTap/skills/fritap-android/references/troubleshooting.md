# friTap on Android: troubleshooting

Sources: `docs/platforms/android.md`, `docs/troubleshooting/common-issues.md`,
`docs/advanced/pairip-safe.md`, `docs/api/cli.md`.

| Symptom | Likely cause | Do this |
|---------|--------------|---------|
| `fritap devices` / `apps` exit 1, "unable to connect" | frida-server not running or not root | `adb shell ps \| grep frida-server`; restart it with `su -c` (below) |
| `frida version mismatch` | device frida-server differs from host `frida` | push the frida-server of exactly `frida --version`; or install the legacy friTap line for an old server (README "Frida compatibility") |
| frida-server starts but cannot inject | SELinux enforcing on the device | `adb shell su -c "setenforce 0"` (docs mention permissive mode for Android kernels); re-run |
| Several devices, wrong one used | `-m` without an id picks the USB device | `fritap devices`, then `-m <id>` |
| Package not found | wrong identifier | `fritap apps -m`, `adb shell pm list packages \| grep <name>` |
| Agent load hangs, then a timeout diagnostic | `script.load()` exceeded `--script-load-timeout` (default 20 s, tripled with `--patterns` / `--library-scan`) | raise it (`--script-load-timeout 60`) or `0` for no bound |
| App dies right after attach/spawn | one hook, anti-tamper, or spawn timing | crash ladder below |
| App refuses to run on a rooted device | root detection | add `-ar` / `--anti_root` |
| App dies with `SIGSEGV`, friTap reports PairIP | PairIP integrity check | `--pairip-safe`, attach mode; see `docs/advanced/pairip-safe.md` |
| Keylog empty, no error | no fresh handshake in the window | drive the app; toggle airplane mode right after `keylog hooks installed` |
| Keylog empty, app clearly did TLS | stripped / statically linked / renamed TLS lib | `-do -v --debug-log`, `--list-libraries`, `--library-scan`, `--patterns`, `--force-scan` (fritap-custom-hooks skill) |
| Keys present, pcap empty or wrong endpoints | socket FD not resolvable | `--enable_default_fd`; or `-f -p` + `-k` and decrypt offline |
| Traffic from WebView / `:service` processes missing | other process | `--enable_spawn_gating`, or target `com.example.app:service` |
| HTTP/3 traffic missing in plaintext | QUIC stack | QUIC keys are in the TLS keylog; `--quic-only` for a target already in QUIC; `--quic-capture-mode app-api` for decoded HTTP/3 headers (Chrome/Cronet QUICHE) |
| HTTP/2 shown as undecoded TLS in Wireshark | port 443 heuristic | "Decode As" HTTP2 on 443 |
| `--full_capture requires -p` | `-f` without `-p` | add `-p <file>` |

## frida-server restart

```bash
adb shell su -c "killall frida-server"
adb shell su -c "/data/local/tmp/frida-server &"
adb shell ps | grep frida-server
adb shell su -c "getenforce"
```

## Crash ladder

Each step removes one suspect (`docs/troubleshooting/common-issues.md`).

```bash
fritap -m --probe com.example.app
frida -U -f com.example.app
fritap -m -k keys.log com.example.app
fritap -m -k keys.log --pairip-safe com.example.app
fritap -m -k keys.log --no-loader-hook com.example.app
fritap -m -k keys.log --quic-only com.example.app
fritap -m -k keys.log --offsets offsets.json com.example.app
fritap -m -v -do --debug-log ./debug.log -k keys.log com.example.app
```

1. `--probe` loads the agent without TLS hooks. Survives: the crash is in
   hook installation. Dies: not a TLS hook.
2. Plain `frida -U -f` with no script. Dies too: Frida injection itself is
   blocked; friTap cannot fix that.
3. Attach instead of spawn (no `-s`). Works: startup timing, not a bad hook.
4. Narrow the hook set: `--pairip-safe`, `--no-loader-hook`, `--quic-only`,
   or a single library via `--offsets`.
5. `--debug-log` collects the tombstone and `logcat -b crash` into the log.

## Confirming there is traffic to catch

```bash
adb shell "su -c 'ss -tunp | grep :443 | grep pid=<pid>'"
adb shell cmd connectivity airplane-mode enable
adb shell cmd connectivity airplane-mode disable
```

No `:443` sockets of the app's PID means it is network-idle; zero keys is then
expected, not a broken hook.
