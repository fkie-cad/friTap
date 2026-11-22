"""Canonical set of SSLKEYLOGFILE-style TLS keylog labels (dependency-free leaf, cheap to import)."""

TLS_KEYLOG_LABELS = frozenset({
    "CLIENT_RANDOM",
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_TRAFFIC_SECRET_0",
    "SERVER_TRAFFIC_SECRET_0",
    "EXPORTER_SECRET",
    "RESUMPTION_MASTER_SECRET",
    "CLIENT_EARLY_TRAFFIC_SECRET",
    "EARLY_EXPORTER_SECRET",  # 0-RTT; NSS and the Fizz hooks
    "ECH_SECRET",  # NSS >= 3.115, same <label> <client_random> <hex> shape
    "ECH_CONFIG",
})
