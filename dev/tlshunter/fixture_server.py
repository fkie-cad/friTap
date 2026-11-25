"""Loopback HTTPS server for the owned Android emulator fixture."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import re
import ssl
import time


class FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if not re.fullmatch(r"/[A-Za-z0-9_-]{1,64}", self.path):
            self.send_error(404)
            return
        print(json.dumps({"id": self.path[1:], "event": "server_received",
                          "host_ns": time.monotonic_ns()}), flush=True)
        self.send_response(204)
        self.send_header("Connection", "close")
        self.end_headers()

    def log_message(self, format, *args):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    args = parser.parse_args()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    with ThreadingHTTPServer(("127.0.0.1", 8443), FixtureHandler) as server:
        server.socket = context.wrap_socket(server.socket, server_side=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
