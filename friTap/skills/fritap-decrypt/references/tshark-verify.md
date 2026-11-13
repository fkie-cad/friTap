# Verifying decryption with tshark

A decryption claim needs evidence: the same display filter must match **more**
packets with the keylog than without it. Never print the keylog itself; count
labels instead.

## Inspect the keylog (labels only)

```bash
cut -d' ' -f1 keys.log | sort | uniq -c
```

| TLS version | Labels needed per connection |
|-------------|------------------------------|
| TLS 1.2 and older | `CLIENT_RANDOM` |
| TLS 1.3 (also QUIC) | `CLIENT_HANDSHAKE_TRAFFIC_SECRET`, `SERVER_HANDSHAKE_TRAFFIC_SECRET`, `CLIENT_TRAFFIC_SECRET_0`, `SERVER_TRAFFIC_SECRET_0` |
| optional | `EXPORTER_SECRET`, `CLIENT_EARLY_TRAFFIC_SECRET`, `RESUMPTION_MASTER_SECRET` |

`EXPORTER_SECRET` protects no records; its absence does not stop decryption.
The second column is the client random; it must match a ClientHello in the
pcap.

## Count with and without keys

```bash
# TLS 1.3: decrypted records show inner content type 23 under outer type 23
tshark -r cap.pcap -Y "tls.record.opaque_type==23 && tls.record.content_type==23" | wc -l
tshark -r cap.pcap -o tls.keylog_file:keys.log \
  -Y "tls.record.opaque_type==23 && tls.record.content_type==23" | wc -l

# Application protocols (TLS 1.2 or 1.3)
tshark -r cap.pcap -o tls.keylog_file:keys.log -Y "http || http2" | wc -l

# QUIC / HTTP/3
tshark -r cap.pcap -o tls.keylog_file:keys.log -Y http3 | wc -l

# Treat MAC failures as errors instead of hiding them
tshark -r cap.pcap -o tls.keylog_file:keys.log \
  -o tls.ignore_ssl_mac_failed:FALSE -Y "http || http2"
```

- `tls.record.content_type==23` alone also matches TLS 1.2 application data,
  even without keys; it proves nothing.
- Repo sample: `demo/tst.pcap` with `demo/keys.log` (TLS 1.3 on port 8443)
  gives 0 without and 3 with the keylog for the TLS 1.3 filter.
- Errors from third-party Wireshark Lua plugins on stderr do not affect the
  count; pipe only stdout into `wc -l`.

## Non-standard ports

```bash
tshark -r cap.pcap -o tls.keylog_file:keys.log -d tcp.port==8443,tls -Y "http || http2"
```

The friTap equivalents are `--tls-port 8443`, `--quic-port 8443`,
`--decode-as` and `--tls-heuristic` on `fritap --from-pcap`.

## friTap's own check

`fritap --from-pcap` runs the same comparison for you. On success it prints
`decrypted packets: N`; when some handshakes are uncovered it prints a note,
and on zero decrypted packets (exit `4`) it explains why:

| Message | Meaning |
|---------|---------|
| `TLS keylog covers N/N TLS handshakes in the capture.` | All good |
| `TLS keylog matches M of N TLS handshakes ...; not covered: ...` | Some connections lack keys |
| `TLS keylog matches 0 of N TLS handshakes ...` | Keylog and pcap are from different runs |
| `... connections started before the capture and can't be decrypted.` | No ClientHello in the pcap |
| `The keylog was last written ... after the capture ended ...` | Keys belong to later sessions |
| `The capture contains no TLS traffic over TCP (QUIC handshakes are not checked) ...` | QUIC-only or plaintext capture; check is not applicable |

## Embedded keys (DSB)

A friTap pcapng (`-p out.pcapng` or `--pcap-format pcapng`) carries its keys
in a Decryption Secrets Block. Wireshark and `fritap --from-pcap` use it
without `--keylog`. Sharing that pcapng shares the keys.
