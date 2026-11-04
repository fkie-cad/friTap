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

!!! success "IKEv2 + ESP key extraction works on stock strongSwan"
    friTap extracts IKEv2 SA keys and ESP (CHILD_SA) keys from a **stock,
    stripped** `charon` (the build Debian/Ubuntu ship) and writes the Wireshark
    decryption tables, so a captured IKE_SA + CHILD_SA exchange decrypts in
    Wireshark/tshark. The key routines are not exported in release builds, so
    friTap locates them by the DBG format-string anchors they reference — no
    symbols and no per-version byte patterns required (verified end-to-end on
    strongSwan 5.9.13, AES-CBC-256/HMAC-SHA2-256-128 and AES-GCM-128).

    Limitation: IKE-key capture relies on the `DBG4` key-dump log statements
    being compiled in (`DEBUG_LEVEL >= 4`, the stock default). On a reduced
    compile-time debug build those statements — and their format-string
    anchors — are gone, and IKE-key capture degrades; ESP key extraction (via
    the kernel-netlink `add_sa` struct fields) is independent of the debug level.

## What works today

| Capability | Status |
|---|---|
| Detect a strongSwan / libcharon IPsec stack | **Works** |
| Hook IPsec targets on the legacy (default) and `--modern` agent paths | **Works** |
| Select IPsec alone with `--protocol ipsec` | **Works** |
| Extract IKEv2 SA keys (SPIi/SPIr, SK_ei/er/ai/ar) from stripped `charon` | **Works** |
| Extract ESP Child SA keys (SPI, enc/auth keys) via kernel-netlink `add_sa` | **Works** |
| Produce Wireshark `ikev2_decryption_table` + `esp_sa` tables | **Works** |

With `-k <path>` friTap writes `ikev2_decryption_table` and `esp_sa` next to the
keylog path, in strongSwan's own `save-keys` format. Point Wireshark/tshark at
them (they live in the Wireshark config/profile directory) and enable ESP
decryption (`-o esp.enable_encryption_decode:TRUE`) to read the IKE_AUTH and ESP
payloads.

## How to enable the IPsec hooks

`ipsec` is a first-class `--protocol` choice, and the strongSwan hooks also run
under `--protocol all`/`auto`. Attach to the running `charon` daemon and start
(or re-key) the tunnel so the key derivation runs while friTap is attached:

```bash
# Attach to charon and write the Wireshark decryption tables next to keys.log.
sudo fritap --protocol ipsec -k keys.log <charon-pid>
# then, in another shell: swanctl --initiate --child <name>
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

The strongSwan key routines are not exported in release builds, so friTap does
not rely on symbols. The extractor (`agent/ipsec/libs/strongswan_keys.ts`)
locates them by the unique DBG format-string literals they reference, using the
generic string-anchor locator (`agent/shared/string_anchor_functions.ts`):

| Target (located by anchor) | Role | Capture |
|---|---|---|
| `derive_ike_keys` (libcharon) | IKEv2 SA key derivation | SPIi/SPIr from the `ike_sa_id` arg, enc/integ algorithms from the proposal, and SK_ei/er/ai/ar read at the `charon->bus->log` key-dump calls while live |
| `add_sa` (kernel-netlink plugin) | ESP CHILD_SA installation | SPI, src/dst, enc_alg/enc_key, int_alg/int_key read from the `kernel_ipsec_sa_id_t` / `kernel_ipsec_add_sa_t` structs |

The IKE encryption/integrity keys are `chunk_split` "move" slices into a buffer
that is freed before `derive_ike_keys` returns, so they are captured at their
`DBG4` key-dump call site (via the charon bus logger) rather than at function
return. The ESP path reads plain struct fields, independent of the debug level.

On the Python side, `friTap/protocols/ipsec_handler.py` maps the IANA transform
ids to Wireshark algorithm names (mirroring strongSwan's `save-keys` plugin) and
`friTap/output/ipsec_decryption_tables.py` writes the `ikev2_decryption_table`
and `esp_sa` UAT files.

## Limitations

* **IKE-key capture needs `DEBUG_LEVEL >= 4` at compile time** (the stock
  default). A reduced-debug build omits the `DBG4` key dumps and their anchors,
  so IKE-key capture degrades; ESP extraction (struct-field reads at `add_sa`)
  is unaffected.
* **strongSwan / libcharon only.** Other IPsec implementations are out of scope.
* **Addresses in `esp_sa` default to the `*` wildcard** (Wireshark matches ESP by
  SPI); IPv6 endpoint extraction is not yet implemented.
* **No agent-path override.** IPsec keeps the agent path you choose; its hooks
  run on the default legacy path unless you pass `--modern` explicitly.

## Next steps

- [CLI reference](../api/cli.md) — `--protocol` choices and `--modern`.
- [Core concepts](../getting-started/concepts.md) — flows, events, and the
  detection-vs-decryption distinction.
