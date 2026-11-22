#!/usr/bin/env python3
"""Minimal HTTPS server offering only TLS 1.3 TLS_AES_256_GCM_SHA384.

Ground-truth target for the Flutter fixture (FRITAP_LOCAL_TLS_URL). Use this
instead of `openssl s_server -www`, which deadlocks with dart:io HttpClient.
"""
import argparse
import os
import sys
import tempfile

# Python's ssl cannot restrict TLS 1.3 suites, so OpenSSL must read this config
# before ssl is first imported.
_OPENSSL_CONF = """\
openssl_conf = openssl_init
[openssl_init]
ssl_conf = ssl_sect
[ssl_sect]
system_default = system_default_sect
[system_default_sect]
MinProtocol = TLSv1.3
Ciphersuites = TLS_AES_256_GCM_SHA384
"""
TLS13_SUITE = "TLS_AES_256_GCM_SHA384"


def install_openssl_conf():
    if "ssl" in sys.modules:
        sys.exit("ssl was imported before the OpenSSL config could be applied")
    fd, path = tempfile.mkstemp(prefix="https_sha384_", suffix=".cnf")
    with os.fdopen(fd, "w") as conf:
        conf.write(_OPENSSL_CONF)
    os.environ["OPENSSL_CONF"] = path
    return path


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cert", required=True, help="PEM certificate")
    parser.add_argument("--key", required=True, help="PEM private key")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--keylog", help="write NSS key log here")
    return parser.parse_args()


def build_context(ssl, args):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(args.cert, args.key)
    if args.keylog:
        ctx.keylog_filename = args.keylog
    tls13 = {c["name"] for c in ctx.get_ciphers() if c["protocol"] == "TLSv1.3"}
    if tls13 != {TLS13_SUITE}:
        sys.exit("OpenSSL config not applied, TLS 1.3 suites: %s" % sorted(tls13))
    return ctx


def main():
    args = parse_args()
    conf_path = install_openssl_conf()
    import http.server
    import ssl

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            cipher = self.connection.cipher()[0]
            body = ("ok %s cipher=%s\n" % (self.path, cipher)).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            # Explicit close: dart:io waits for TCP close, not close_notify.
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

    ctx = build_context(ssl, args)
    os.unlink(conf_path)
    server = http.server.ThreadingHTTPServer((args.host, args.port), Handler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    print("listening on https://%s:%d/" % (args.host, args.port), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
