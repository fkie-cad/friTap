# OHTTP (Oblivious HTTP) capture

friTap can recover the **plaintext inner HTTP message** of an
[Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9292) (OHTTP) exchange the
moment it is sealed or opened, before it is wrapped in HPKE and shipped to the
relay. The inner message is framed as **Binary HTTP (BHTTP, RFC 9292)** and is
emitted as a dedicated `ohttp_plaintext` event — distinct from the outer TLS or
QUIC connection that carries the encapsulated request to the relay/gateway.

!!! info "Captured inside the TLS family — there is no separate OHTTP flag"
    OHTTP capture is **on by default** and rides along with `--protocol tls`
    (the default protocol). There is **no** `--protocol ohttp` choice and **no**
    `--ohttp` command-line flag. The corresponding config key is
    `HookingConfig.ohttp_enabled`, which defaults to `True`
    (`friTap/config.py`). The `--protocol` help text states it plainly:
    *"'tls' covers the TLS family — TLS, QUIC, and OHTTP."*

## What OHTTP is

Oblivious HTTP separates *who* is making a request from *what* the request
contains. A client encapsulates an HTTP request with **HPKE** (Hybrid Public
Key Encryption) under the gateway's public key, sends the encapsulated blob to
an **Oblivious Relay** over TLS, and the relay forwards it to the **Oblivious
Gateway** without seeing the client's IP. The gateway decapsulates, performs
the real HTTP request, and the response travels back the same HPKE-protected
path.

The inner request/response is not ordinary HTTP/1.1 text — it is **Binary HTTP
(BHTTP)**, RFC 9292's compact binary serialization of an HTTP message. friTap
recognises the **known-length** BHTTP framing indicators (`0x00` = request,
`0x01` = response) to confirm a buffer is a real inner message before emitting
it.

## What friTap captures

friTap hooks the **NSS HPKE** primitives — the same HPKE backend Firefox and
other NSS-based stacks use for OHTTP:

| Hook | Direction | What it yields |
|---|---|---|
| `PK11_HPKE_Seal` | request (egress) | The BHTTP plaintext **before** HPKE encryption, read from the input `SECItem` |
| `PK11_HPKE_Open` | response (ingress) | The BHTTP plaintext **after** HPKE decryption, read from the output `SECItem` on success |

On `PK11_HPKE_Seal`, friTap inspects the plaintext `SECItem` argument, confirms
it looks like known-length BHTTP, and emits an `ohttp_plaintext` event tagged
`direction="request"`. On `PK11_HPKE_Open`, it captures the freshly decrypted
output `SECItem` only when the call returns success, tagging it
`direction="response"`. Capture is gated on PCAP output being enabled.

!!! note "Known-length BHTTP only"
    friTap currently recognises the **known-length** BHTTP framings (`0x00`
    request / `0x01` response). The **indeterminate-length** variants (`0x02` /
    `0x03`) are intentionally excluded because the Python-side parser does not
    yet decode them.

## Platforms

OHTTP capture targets the **NSS HPKE** symbols `PK11_HPKE_Seal` /
`PK11_HPKE_Open`, which require **NSS ≥ 3.58** (where the public HPKE API was
introduced). The hooks are registered across **Linux, macOS, Windows, and
Android** — any target that links a recognisable `*libnss*` module. If the
symbols are absent (older NSS, or a build without HPKE), friTap logs that
`PK11_HPKE_Seal`/`PK11_HPKE_Open` were not found and simply installs no OHTTP
hooks; the rest of TLS capture is unaffected.

## Quick start

Because OHTTP capture is part of the default TLS family, no special flag is
needed — capture TLS as usual and OHTTP plaintext appears automatically when
the target performs an Oblivious HTTP exchange:

```bash
# Default --protocol tls already enables OHTTP capture
fritap -m --protocol tls -p out.pcapng com.example.app
```

To be explicit about the TLS family (functionally identical to the default):

```bash
fritap --protocol tls -p out.pcapng -- /path/to/nss-based-client
```

## Relationship to the outer transport

The encapsulated OHTTP exchange still travels to the relay over an ordinary TLS
or QUIC connection. friTap captures **both** layers independently: the outer
connection appears as normal TLS/QUIC traffic, while the inner Oblivious HTTP
message is surfaced separately as `ohttp_plaintext`. If the outer transport is
QUIC, see [QUIC capture](quic.md) for how the carrier connection is handled.

## Next steps

- [CLI reference](../api/cli.md) — `--protocol` and the TLS-family default.
- [QUIC capture](quic.md) — the transport that often carries OHTTP to the relay.
- [Core concepts](../getting-started/concepts.md) — how protocols, flows, and
  events fit together.
