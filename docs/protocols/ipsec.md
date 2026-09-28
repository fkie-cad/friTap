# IPsec (strongSwan) capture

friTap has **early, experimental** support for IPsec targets built on
**strongSwan** / **libcharon**. Today this support is limited to **connection
detection** — friTap can recognise that a strongSwan IPsec stack is loaded on
both the default legacy agent path and the explicit `--modern` path. **Key extraction (IKEv2 / ESP) is not
yet functional.**

!!! note "Not yet selectable as `--protocol ipsec`"
    The Python-side `IPSecHandler` is not registered yet (it is commented out in
    `friTap/protocols/registry.py` and `friTap/protocols/__init__.py`), so
    `--protocol ipsec` is **rejected by the CLI** and does not appear in the TUI.
    Today the strongSwan hooks install only when you select **`--protocol all`**
    or **`--protocol auto`**: the agent then hooks every supported protocol,
    including IPsec, on both the legacy and `--modern` paths.

!!! warning "EXPERIMENTAL — detection works, key extraction does not (yet)"
    IPsec support is at the **detection-only stub** stage. With
    `--protocol all`/`auto` the agent installs the strongSwan hook definition and
    detects the connection, but it **does not yet decrypt IKEv2 or ESP traffic**.

    The strongSwan definition is explicitly described in source as a
    *"detection-only stub"* (`agent/ipsec/definitions/strongswan.ts:4`).
    **Partial, non-functional** `derive_ike_keys` and
    `ikev2_derive_child_sa_keys` hooks exist in the legacy executor, but they do
    not currently produce usable Wireshark decryption material. Do not rely on
    IPsec key recovery for real work yet.

## What works today

| Capability | Status |
|---|---|
| Detect a strongSwan / libcharon IPsec stack | **Works** |
| Hook IPsec targets on the legacy (default) and `--modern` agent paths (via `--protocol all`/`auto`) | **Works** |
| Select IPsec alone with `--protocol ipsec` | **Not yet** (handler not registered) |
| Emit synthetic, metadata-only flow records for the connection | **Works** |
| Extract IKEv2 SA keys (`derive_ike_keys`) | **Partial / non-functional** |
| Extract ESP Child SA keys (`ikev2_derive_child_sa_keys`) | **Partial / non-functional** |
| Produce Wireshark IKEv2 + ESP SA decryption tables | **Future work** |

What you can expect right now: friTap will **acknowledge the IPsec connection**
and surface **metadata-only** flow records for it. It will **not** hand you
decrypted IKEv2 or ESP payloads. Treat any IPsec run as a detection and
groundwork exercise, not a decryption workflow.

## How to enable the IPsec hooks

`ipsec` is **not** one of the `--protocol` choices yet: the CLI only accepts
protocols registered in `friTap/protocols/registry.py`, and the IPsec handler
there is still commented out, so `--protocol ipsec` fails with an
"unknown protocol" error. The agent-side strongSwan hooks are installed when
every protocol is hooked, i.e. with `--protocol all` (asks for confirmation;
skip with `-y`) or `--protocol auto`:

```bash
# Detect a strongSwan target (Linux). Key extraction is NOT yet functional.
sudo fritap --protocol auto -p out.pcapng -- /usr/sbin/charon
```

Once the handler is registered, `ipsec` will become a selectable, **exclusive**
protocol (only the IPsec hooks install, not TLS/QUIC/SSH).

!!! info "IPsec does not force the modern agent path"
    The IPsec hooks keep the agent path you choose. On the default legacy
    path the strongSwan libraries are hooked by the legacy IPsec executor
    (`agent/ipsec/platforms/linux/ipsec_linux.ts`, with the partial
    key-derivation hooks); passing `--modern` explicitly selects the
    definition-based strongSwan executor instead.

## Under the hood

The strongSwan `HookDefinition` (`agent/ipsec/definitions/strongswan.ts`)
delegates installation to the legacy `ipsec_detect_execute` path
(`agent/ipsec/platforms/linux/ipsec_linux.ts`), which is the source of truth for
runtime behaviour today. The definition advertises a set of strongSwan symbols
that **future** work will target:

| Symbol | Intended future role |
|---|---|
| `derive_ike_keys` | IKEv2 SA key derivation |
| `ikev2_derive_child_sa_keys` | ESP Child SA key derivation |
| `child_sa_install` | Child SA installation |
| `child_sa_set_spi` | Child SA SPI assignment |
| `keymat_v2_create` | Keying-material construction |

None of these symbols are required to resolve today — they may not be exported,
especially in stripped production builds where vtable-based hooking will
eventually be needed. The generic read/write executors are intentionally not
wired for IPsec; key extraction is meant to live in dedicated key-derivation
hooks once they are completed.

The planned end state is a register-aware reimplementation of those hooks backed
by a Wireshark-compatible IPsec keylog formatter on the Python side, emitting
IKEv2 + ESP SA decryption tables. That work has not landed.

## Limitations

* **No IKEv2/ESP decryption today.** The key-derivation hooks are present but
  non-functional. Captured output is synthetic metadata only.
* **strongSwan / libcharon only.** Other IPsec implementations are out of scope.
* **Not selectable on its own yet.** `--protocol ipsec` is rejected until the
  IPsec handler is registered; use `--protocol all`/`auto`.
* **No agent-path override.** IPsec no longer forces `--modern`; its hooks
  run on the default legacy path unless you pass `--modern` explicitly.
  (The modern path is itself EXPERIMENTAL for IPsec.)

## Next steps

- [CLI reference](../api/cli.md) — `--protocol` choices and `--modern`.
- [Core concepts](../getting-started/concepts.md) — flows, events, and the
  detection-vs-decryption distinction.
