# IPsec (strongSwan) capture

friTap has **early, experimental** support for IPsec targets built on
**strongSwan** / **libcharon**. Today this support is limited to **connection
detection** — friTap can recognise that a strongSwan IPsec stack is loaded and
route it through the modern agent path. **Key extraction (IKEv2 / ESP) is not
yet functional.**

!!! warning "EXPERIMENTAL — detection works, key extraction does not (yet)"
    IPsec support is at the **detection-only stub** stage. Selecting
    `--protocol ipsec` installs the strongSwan hook definition and detects the
    connection, but it **does not yet decrypt IKEv2 or ESP traffic**.

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
| Route IPsec targets through the modern agent path | **Works** |
| Emit synthetic, metadata-only flow records for the connection | **Works** |
| Extract IKEv2 SA keys (`derive_ike_keys`) | **Partial / non-functional** |
| Extract ESP Child SA keys (`ikev2_derive_child_sa_keys`) | **Partial / non-functional** |
| Produce Wireshark IKEv2 + ESP SA decryption tables | **Future work** |

What you can expect right now: friTap will **acknowledge the IPsec connection**
and surface **metadata-only** flow records for it. It will **not** hand you
decrypted IKEv2 or ESP payloads. Treat any IPsec run as a detection and
groundwork exercise, not a decryption workflow.

## How `--protocol ipsec` works

IPsec is selected through the same `--protocol` selector as the other
protocols. Valid choices are `tls`, `ipsec`, `ssh`, `all`, and `auto`
(`friTap/friTap.py`). `ipsec` is **exclusive** — only the IPsec hooks install,
not TLS/QUIC/SSH:

```bash
# Detect a strongSwan target (Linux). Key extraction is NOT yet functional.
sudo fritap --protocol ipsec -p out.pcapng -- /usr/sbin/charon
```

!!! info "`--protocol ipsec` auto-enables the modern agent path"
    The strongSwan executor is registered **only** on the modern agent path.
    To avoid silently falling back to the legacy TLS-only agent (which would
    no-op a strongSwan target), `--protocol ipsec` **automatically forces
    `use_modern=true`** (`friTap/friTap.py`):

    > `[ipsec] --protocol ipsec auto-enables use_modern=true (legacy path has no IPSec support)`

    You do not need to pass `--modern` yourself; selecting IPsec implies it.

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
* **Modern path required.** IPsec is registered only on the modern agent; this
  is auto-enabled when you pass `--protocol ipsec`. (The modern path is itself
  EXPERIMENTAL for IPsec.)

## Next steps

- [CLI reference](../api/cli.md) — `--protocol` choices and `--modern`.
- [Core concepts](../getting-started/concepts.md) — flows, events, and the
  detection-vs-decryption distinction.
