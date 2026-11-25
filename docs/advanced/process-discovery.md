# Process discovery (Android)

The process that runs an app's TLS is often **not** the process you launched.
Hooking only the launched package then yields no keys, or only some of them.
This page explains why, how [tlsLibHunter](https://github.com/monkeywave/tlsLibHunter)
finds the right processes, and how friTap captures them with a discovery
profile. For the flags in short, see
[Android: Delegate Processes](../platforms/android.md#delegate-processes-discovery-profiles)
and the [CLI reference](../api/cli.md#-profile-profilejson).

## The problem

Common reasons the TLS runs elsewhere:

- **Launcher hand-off.** Gemini (`com.google.android.apps.bard`) is a thin
  launcher: it hands the conversation to the Google app
  (`com.google.android.googlequicksearchbox`, process `:search`), which talks
  QUIC through Cronet in `/apex/com.android.tethering/lib64/libhttpengine.so`.
  Hooking Gemini alone captures nothing of the Gemini backend.
- **Sub-processes.** Apps split work into `:process` siblings (sync, media,
  push) that each open their own connections.
- **Restarts.** A process can be killed and restarted while you use the app;
  an attach-only capture loses it.

## The Android process model

Android has no system TLS daemon like Schannel/LSASS on Windows. **Every
process runs its own TLS stack in-process**:

- Conscrypt (BoringSSL) for the platform `javax.net.ssl` stack.
- HttpEngine (Cronet in the tethering APEX) and GMS Cronet, which Play
  services loads *into the app's process* via dynamite modules.
- WebView: networking runs in the app process (network service in-process);
  renderers are isolated and do no networking.

The one in-app exception is the **SDK Runtime**: ad SDKs can run in
`<pkg>_sdk_sandbox`, a separate process whose traffic is still attributable to
the app.

Apps can still **delegate whole requests** over binder or intents to other
processes that run their own TLS: Google Play services (GMS),
DownloadProvider, Chrome (Custom Tabs), netd/DnsResolver (Private DNS / DoT)
and the Play Store. Those processes serve **many apps**, so their traffic
cannot be attributed to the target. friTap reports them (role
`shared_system`) but **never hooks them**.

## Zygote, copy-on-write and spawn gating

Every app process is forked from zygote and inherits its memory
copy-on-write. Injecting Frida into zygote itself does not work: after
`fork()` only the forking thread survives in the child, so Frida's agent
threads are gone, while the inherited trampolines still point into an agent
that no longer runs, and the child crashes.

The usable vantage point is **spawn gating** at process specialization: Frida
pauses each new process right after zygote turns it into an app, before the
app code runs, so friTap can hook it before its first connection.

Zygote maps Conscrypt's `libssl.so` and the tethering APEX's
`libhttpengine.so` into *every* app process (verified on a Pixel 5, Android
14). Their presence in `/proc/<pid>/maps` is therefore only weak evidence:
tlsLibHunter labels them `tls_lib:conscrypt/libssl.so` /
`tls_lib:tethering/libhttpengine.so` and marks a process `confirmed` only when
such a library comes with an owned TLS socket. Any other TLS library (bundled
Cronet, Flutter, WebView, ...) confirms on its own.

## Evidence layers and roles

tlsLibHunter combines several kinds of evidence per process:

| Layer | What it checks |
|-------|----------------|
| Topology | Same app UID (`uid % 100000`), isolated processes (app id 90000-99999), SDK sandbox (app id 20000-29999), `:process` names |
| Hand-off | The foreground host after launch; `dumpsys activity oom` `adjSource` bindings from the target to other processes |
| Socket ownership | `/proc/net/{tcp,udp}*` joined with `/proc/<pid>/fd` (needs root). netd `fchown`s DNS/DoT sockets to the app UID, so the UID alone does not prove the app opened a socket |
| TLS libraries | Which TLS libraries are mapped in `/proc/<pid>/maps` (root, no Frida) |
| Binder probe (opt-in, `--probe`) | A short Frida probe in the target logs the binder interfaces it calls (`handoff:binder:<descriptor>`) and its TLS-port `connect`/`sendto` calls |

Each process gets a role:

| Role | Meaning | friTap |
|------|---------|--------|
| `target` | The launched package | hooked |
| `sibling` | `:process` of the same package | hooked |
| `delegate` | Another package the target hands work to (e.g. the Google app for Gemini) | hooked, restarted under spawn gating |
| `sdk_sandbox` | `<pkg>_sdk_sandbox` of the target | hooked |
| `shared_system` | GMS, netd, Play Store, ... serving many apps | reported only |

## Workflow: learn, then capture

**1. Learn.** Run discovery while you exercise the app:

```bash
tlslibhunter discover com.google.android.apps.bard --serial <SERIAL> \
    --duration 30 --write-profile gemini.json
```

**2. Capture.** Launch fresh with the profile:

```bash
fritap -m <SERIAL> --profile gemini.json -k keys.log -s com.google.android.apps.bard
```

Add `--probe` to also record which binder services the target calls, or
use `tlslibhunter discover <pkg> --watch` to stream process restarts and new
delegates as JSON lines (`tlslibhunter.watch/1`).

Or do both in one run with `--discover SECONDS` (needs tlsLibHunter
installed). Add packages by hand with `--also-package <package>`
(repeatable).

What friTap does with a profile:

1. Enables spawn gating for all profile packages **before** force-stopping
   the delegates. Delegates such as the Google app respawn in about 0.1 s, so
   the gate must already be armed.
2. Holds each gated process until the agent reports its hooks installed (at
   most 6 s, below Android's 10 s process-start timeout), then resumes it.
3. Keeps capturing while any profile process runs, even after the target
   exits. Stop with Ctrl+C.

**Why not attach late?** Cronet and QUIC pool connections: the handshakes
happen at startup and later requests reuse them. Attaching after the fact
finds the connections already established and gets no keys for them.

Every event carries `process_origin` (`pid`, `process`, `role`), and `.tap`
flows carry `pid` / `process_role` (see
[.tap format](../api/tap-format.md#optional-pid-process_role)).

## Profile format

A profile is JSON with schema `tlslibhunter.profile/1`:

| Field | Content |
|-------|---------|
| `target` | Target process name |
| `target_package` | Target package |
| `gate_packages` | Packages friTap spawn-gates |
| `process_patterns` | Process names to hook |
| `device_fingerprint`, `version_code` | Device and app version the profile was learned on |
| `candidates[]` | `pid`, `process`, `package`, `uid`, `role`, `evidence` per process |

Profiles are **untrusted input**: friTap validates every package and process
name against Android naming rules and rejects a profile with any other value.
Re-learn the profile after app or OS updates.

## Limitations

- Socket ownership needs root; without it discovery relies on the other
  layers.
- Discovery polls `/proc`; very short-lived sockets can be missed.
- Traffic that a target delegates to `shared_system` processes is not
  captured.
- The **USAP pool** pre-forks app processes, which can escape spawn gating.
  friTap warns and prints the command to disable it
  (`setprop persist.device_config.runtime_native.usap_pool_enabled false`).
- The cached-app **freezer** can freeze background processes, so a delegate
  may produce no traffic until it is in use again.
- After a run in which the target was closed and relaunched (so delegates
  were hooked again while the main target was gone), Frida's script unload
  can stall in the delegate processes. friTap still removes every hook
  (graceful detach), but the idle Frida agent stays mapped in those processes
  until they exit. Run `adb shell am force-stop <delegate package>` to clear
  it.
- `--probe` needs the target's own process to run. Pure launchers such as
  Gemini hand off before their process stays up, so there is nothing to
  probe; discovery then still finds the delegates through the other layers.

## Measured example

Gemini on a Pixel 5, Android 14:

| Mode | Result |
|------|--------|
| Late attach to Gemini | 0 keys |
| `--profile` capture | All startup handshakes keyed (10/10); the Gemini backend `robinfrontend-pa.googleapis.com` decrypted over HTTP/3 |

See also [QUIC: Gemini / Google app](../protocols/quic.md#gemini-google-app-gsa).
