# `fritap --from-pcap` flags

Full list: `fritap --from-pcap <file> --help`. The offline pipeline has its own
parser; capture flags do not apply here.

| Flag | Purpose |
|------|---------|
| `--from-pcap FILE` | Required. pcap or pcapng (encrypted or plaintext). |
| `--keylog FILE` | NSS `SSLKEYLOGFILE` for TLS/QUIC, decrypted by tshark. Omit for plaintext or a DSB pcapng. |
| `--tap FILE` | Output `.tap` (default `<pcap stem>.tap`). |
| `--scan` | Run the analyzers over the new `.tap` and report a finding count. |
| `--show-layers` | Print each decrypted flow's protocol layer stack. |
| `--tls-port N` / `--quic-port N` | Extra Decode-As ports (repeatable; UDP 443 always on for QUIC). |
| `--decode-as RULE` | Raw tshark `-d` rule (repeatable). |
| `--tls-heuristic` | tshark TLS-over-TCP heuristic for unknown ports. |
| `--tshark-path PATH` | tshark binary (also `$FRITAP_TSHARK`). |
| `--repair-keylog` | Fix a keylog by trial decryption: re-pair wrong or `???` client randoms and correct swapped TLS 1.3 HANDSHAKE/TRAFFIC labels. Writes `<stem>.relabeled.keylog` next to the keylog and decrypts with it; otherwise keeps the original keylog. |
| `--tls-midstream-secrets FILE` | `*.tls_midstream.secrets.jsonl` from a memory scan; decrypts TLS 1.3 flows with no ClientHello in the pcap. |
| `--schannel-unpaired FILE` | Schannel memory-scan `.schannel.unpaired` sidecar; pairs secrets to connections by trial decryption. |
| `--mtproto-keylog FILE` | Telegram MTProto keys; friTap's own decryptor, not tshark. |
| `--telegram-keylog FILE` | Combined Telegram cloud + secret-chat keys. |
| `--rc4-keylog FILE` | RC4 keys; with `--keylog` for RC4 inside TLS. |
| `--resync-search-depth N` | Search depth when re-aligning a mid-stream flow to a memory-recovered key. |

```bash
fritap --from-pcap capture.pcapng --keylog keys.log --tap out.tap --scan
fritap --from-pcap cleartext.pcap --tap out.tap
fritap --from-pcap win.pcapng --schannel-unpaired capture.schannel.unpaired --tap win.tap
fritap --from-pcap traffic.pcap --keylog keys.log --tap out.tap --show-layers
```

## Manifest sidecar

`<pcap>.fritap.json` next to the pcap fills in `keylog`, `tls_ports`,
`quic_ports` you did not pass. Precedence: CLI flag > manifest > default.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Application data written |
| `1` | Other failure (e.g. tshark exited non-zero) |
| `2` | pcap not found |
| `3` | tshark not found |
| `4` | Ran, but no application data (wrong keys or ports, or encrypted keyless capture) |
| `5` | `--keylog` given but missing, and no DSB (`NoDecryptionKeysError`) |

## Environment

| Variable | Effect |
|----------|--------|
| `FRITAP_TSHARK` | tshark path (after `--tshark-path`, before `PATH`) |
| `FRITAP_SCHANNEL_ORACLE=0` | Send every Schannel/repair trial to tshark |
| `FRITAP_PCAP_PARSER=scapy` | Old scapy parser for the raw-TCP decryptors |

## Python

```python
from friTap import pcap_to_tap   # not from friTap.offline
result = pcap_to_tap("traffic.pcap", keylog_path="keys.log", tap_path="out.tap")
print(result.to_dict())          # flow_count, decrypted_packet_count, ...
```
