import pyshark

import argparse
import pprint
import sys


def _get_sessions_dec(dec_pcap):
    sessions_dec = list()
    try:
        i = 0
        while True:
            with pyshark.FileCapture(
                    dec_pcap, display_filter=f"tcp.stream eq {i}") as dec:
                pkt = dec[0]
                if hasattr(pkt, "ip"):
                    sessions_dec.append({
                        "src_addr": pkt.ip.src,
                        "dst_addr": pkt.ip.dst,
                        "src_port": pkt.tcp.srcport,
                        "dst_port": pkt.tcp.dstport
                    })
                else:
                    sessions_dec.append({
                        "src_addr": pkt.ipv6.src,
                        "dst_addr": pkt.ipv6.dst,
                        "src_port": pkt.tcp.srcport,
                        "dst_port": pkt.tcp.dstport
                    })
                i += 1
    except Exception as e:
        return sessions_dec


def _get_sessions_enc(enc_pcap):
    # Read sessions in the encrypted pcap
    sessions_enc = list()

    with pyshark.FileCapture(enc_pcap, display_filter="tls") as enc:
        for pkt in enc:
            if "handshake_type" in pkt.tls.field_names and pkt.tls.handshake_type == "1":
                if hasattr(pkt, "ip"):
                    sessions_enc.append({
                        "src_addr": pkt.ip.src,
                        "dst_addr": pkt.ip.dst,
                        "src_port": pkt.tcp.srcport,
                        "dst_port": pkt.tcp.dstport
                    })
                else:
                    sessions_enc.append({
                        "src_addr": pkt.ipv6.src,
                        "dst_addr": pkt.ipv6.dst,
                        "src_port": pkt.tcp.srcport,
                        "dst_port": pkt.tcp.dstport
                    })
    return sessions_enc


def compare(enc_pcap, dec_pcap):
    """
    compare a encrypted and a decrypted pcap and return number of connections, and number of connections of 
    theese which have been found decrypted 
    """

    # Read sessions in the decrypted pcap
    sessions_dec = _get_sessions_dec(dec_pcap)
    # Read sessions in the encrypted pcap
    sessions_enc = _get_sessions_enc(enc_pcap)

    total_sessions = len(sessions_enc)
    decrypted_sessions = 0
    for sess in sessions_dec:
        try:
            sessions_enc.remove(sess)
            decrypted_sessions += 1
        except ValueError as e:
            print("Found session in decrypted pcap which is not present in encrypted pcap - aborting...", file=sys.stderr)
            sys.exit(1)

    return total_sessions, decrypted_sessions


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Compare encrypted and decrypted pcaps for completeness")
    parser.add_argument("-e", metavar="<encrypted pcap>")
    parser.add_argument("-d", metavar="<decrypted pcap>")
    args = parser.parse_args()
    total, total_dec = compare(args.e, args.d)
    quota = float(total_dec)/float(total)
    print(f"Total: {total}, decrypted: {total_dec}, Quota: {quota:.0%}")
