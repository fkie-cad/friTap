# SSH (OpenSSH) capture

friTap can capture plaintext SSH traffic from **OpenSSH** on **Linux and
Android (Termux)** in the same shape it captures plaintext TLS: synthetic
TCP/22 frames written into a PCAPNG file, plus a side-car keylog file that
Wireshark's SSH dissector can read to decrypt a *paired ciphertext capture*
(produced separately, e.g. via tcpdump).

## Quick start

```bash
# Linux x86_64, client side
fritap --protocol ssh --include-loopback \
    -p out.pcapng \
    -- /usr/bin/ssh user@host 'echo hello'

# Linux server side (sshd) — friTap auto-enables --enable_child_gating
sudo fritap -s --protocol ssh \
    -p sshd-out.pcapng \
    -- /usr/sbin/sshd -D -p 2222

# Android via Termux
fritap -m --protocol ssh -p /sdcard/ssh.pcapng \
    -- /data/data/com.termux/files/usr/bin/ssh user@host 'date'
```

After a run the working directory contains:

| File | Producer | Consumer |
|---|---|---|
| `out.pcapng` | friTap PCAPNG sink | Open in Wireshark — plaintext TCP/22 frames |
| `keys.log` (when `-k` set) | friTap keylog handler | Human-readable per-direction SSH keys |
| `out.ssh-keys.log` (auto-derived from `-p`) | friTap SSH keylog side-car | Wireshark `Edit → Preferences → Protocols → SSH → Key log filename` |

## What the PCAPNG contains

friTap hooks **`ssh_packet_send2_wrapped`** (write path) and
**`ssh_packet_read_poll2`** (read path) inside OpenSSH. These are the points
where the fully-assembled SSH binary packet is in memory in cleartext —
post-compression on the send side, post-decryption + decompression on the
receive side. friTap reads `state->outgoing_packet` / `state->incoming_packet`
via `sshbuf_ptr` + `sshbuf_len`, fabricates an IPv4/IPv6 + TCP frame using
the same 5-tuple lookup TLS uses (`getsockname` / `getpeername` on the
SSH socket fd), and emits an Enhanced Packet Block into the PCAPNG file.

Wireshark's SSH dissector **expects ciphertext + a keylog file**. It will
not auto-decode the plaintext that friTap embeds in this PCAPNG (it sees
non-encrypted bytes where it expects encryption to have happened). To
inspect:

```bash
# Follow the TCP stream — the binary packet protocol is visible
tshark -r out.pcapng -Y "tcp.port == 22" -q -z follow,tcp,raw,0

# Extract TCP payloads as raw bytes
tshark -r out.pcapng -Y "tcp.port == 22" -T fields -e tcp.payload \
    | tr -d '\n' | xxd -r -p > /tmp/payload.bin
```

The bytes form the RFC 4253 §6 SSH binary packet protocol:

```
[u32 packet_length] [u8 padding_length] [payload ...] [padding]
```

The first message in each direction is the SSH version banner; subsequent
messages are KEXINIT, KEXDH_INIT, KEXDH_REPLY, NEWKEYS, USERAUTH_REQUEST,
CHANNEL_DATA, etc.

## The Wireshark side-car keylog

If you *also* have a paired ciphertext PCAP (e.g. you ran `tcpdump -i any
tcp port 22` alongside friTap), Wireshark can use the side-car keylog
friTap auto-generates to decrypt and fully dissect that capture.

```bash
# 1. Capture ciphertext separately
sudo tcpdump -i any -w /tmp/ssh-cipher.pcap "tcp port 22" &

# 2. friTap produces the keylog (and a plaintext PCAPNG we don't need here)
fritap --protocol ssh -p /tmp/dummy.pcapng \
    -- /usr/bin/ssh user@host 'echo decryptme'
# → /tmp/dummy.ssh-keys.log is auto-derived from /tmp/dummy.pcapng

# 3. Open /tmp/ssh-cipher.pcap in Wireshark
# 4. Edit → Preferences → Protocols → SSH → Key log filename
#    → /tmp/dummy.ssh-keys.log
# 5. Reload (Ctrl-R). Encrypted SSH packets are now dissected.
```

Format details:
- One line per (re)keying: `<32-hex-cookie> SHARED_SECRET <K-hex>`.
- `cookie` is the 16-byte random from `SSH_MSG_KEXINIT` (hex-encoded).
- `SHARED_SECRET` is the post-DH shared key K. Wireshark performs the
  RFC 4253 §7.2 KDF internally — friTap does **not** emit pre-derived
  per-direction encryption / IV / MAC keys here.
- Wireshark accepts a match against either side's cookie; friTap writes
  both when it can recover them.

**Requirements**: Wireshark **≥ 4.0** (introduced the SSH keylog file
preference in mid-2023). Earlier Wireshark versions see ciphertext only.

## Cipher coverage

Wireshark's SSH dissector currently decrypts:

| Cipher | Status |
|---|---|
| `chacha20-poly1305@openssh.com` | Supported |
| `aes128-ctr` / `aes192-ctr` / `aes256-ctr` + `hmac-sha2-256` / `hmac-sha2-512` (incl. `-etm`) | Supported |
| `aes128-gcm@openssh.com`, `aes256-gcm@openssh.com` | Supported |
| `aes*-cbc`, `3des-cbc`, deprecated MACs | Not supported |
| `zlib@openssh.com` compression | Partial; may break dissection mid-session |

friTap always emits the keylog and the plaintext PCAPNG regardless of
which cipher is negotiated — even when Wireshark can't decrypt the paired
ciphertext PCAP, the plaintext file from friTap is usable.

## CLI / API integration

```
--protocol ssh        # Install SSH hooks only (excludes TLS/QUIC/OHTTP)
--protocol all        # Install everything; prompts unless -y/--yes
--protocol auto       # Script-friendly alias of --protocol all (no prompt)
--ssh-keylog <path>   # Override the side-car file path
-y, --yes             # Auto-confirm --protocol all
```

When `--protocol ssh -p OUT.pcapng` is set and `--ssh-keylog` is omitted,
friTap auto-derives the side-car path: `OUT.ssh-keys.log`.

Programmatic API mirror:

```python
from friTap.api import FriTap
(
    FriTap("ssh")
    .protocol("ssh")
    .pcap("out.pcapng")
    .keylog("keys.log")
    .ssh_keylog("out.ssh-keys.log")
    .run("ssh user@host 'echo hello'")
)
```

## How keys are extracted

friTap's SSH hook ladder (all symbol-based, no struct offsets in the
primary path):

| Hook | Source | Purpose |
|---|---|---|
| `cipher_init(..., key, keylen, iv, ivlen, do_encrypt)` | `cipher.c` | Per-direction key/IV (direct args). Mapped to C2S/S2C using `/proc/self/comm` process role. |
| `kex_send_kexinit(ssh)` | `kex.c` | Capture **local** SSH_MSG_KEXINIT cookie. |
| `kex_input_kexinit(type, seq, ssh)` | `kex.c` | Capture **peer** SSH_MSG_KEXINIT cookie. |
| `kex_derive_keys(ssh, hash, hashlen, shared_secret)` | `kex.c` | Capture shared secret K (arg 3 is an `sshbuf*`). Correlates with cookies and emits the Wireshark keylog line. |
| `ssh_packet_send2_wrapped(ssh)` | `packet.c` | Plaintext send path. |
| `ssh_packet_read_poll2(ssh, typep)` | `packet.c` | Plaintext recv path. |
| `cipher_crypt(cc, ...)` (fallback) | `cipher.c` | Used when wrapper symbols are stripped — emits plaintext with a synthetic loopback 5-tuple. |

Signatures are stable across **OpenSSH 7.6 → 10.x** (verified against
upstream tags V_7_6_P1 → V_10_0_P1). The legacy `kex_derive_keys_bn`
(BIGNUM-based, older OpenSSH) is supported as an automatic fallback.

## Server-side caveat: sshd privilege separation

`sshd` forks a pre-auth child for KEX, then re-execs into `sshd-session`
post-auth. The plaintext + keylog material is generated in the **first
fork** (KEX completes before authentication). When `--protocol ssh` is set
and the target binary basename matches `sshd` or `sshd-session`, friTap
**auto-enables `--enable_child_gating`** so Frida follows the fork chain.

## Symbol availability

friTap resolves symbols via `Module.findExportByName` and falls back to a
`.symtab` scan (`findNonExportedSymbol`). This covers:

| Build | Status |
|---|---|
| Debian / Ubuntu / Fedora / Arch (default `sshd`/`ssh` packages) | Works out of the box |
| Termux openssh (Android) | Works out of the box |
| Alpine Linux (stripped sshd) | Pattern matching required; v1 ships placeholder entries — see the [pattern file format](../advanced/patterns.md#pattern-file-format) and the [pattern derivation guide](../advanced/patterns.md#automated-pattern-generation-with-boringsecrethunter) |
| Custom statically-stripped builds | Same as Alpine |

When all primary plaintext hooks fail to resolve, friTap falls back to
`cipher_crypt` (always exported) and emits plaintext with a synthetic
loopback 5-tuple — Wireshark's SSH dissector won't dissect it but tshark's
hex view still shows the cleartext.

## Limitations

* **Wireshark dissection of the friTap PCAPNG itself**: the friTap PCAPNG
  is plaintext-where-Wireshark-expects-ciphertext. The SSH dissector won't
  engage on it directly. Use the side-car keylog against an *independent*
  ciphertext capture.
* **No PCAPNG DSB block for SSH**: the pcapng spec has not assigned an SSH
  Decryption Secrets Block type. The side-car file is the only delivery
  channel for now.
* **Dropbear** (LineageOS, OpenWrt) is *not* covered. Different codebase,
  different struct layouts. Out of scope for v1.
* **libssh / libssh2** library hooks are detection stubs only; plaintext
  capture in these libraries is a planned extension.
* **iOS** is not supported (no native OpenSSH on iOS).
