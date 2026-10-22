"""Protocol-neutral pcap/TCP helpers shared by the offline decryptors.

Nothing here knows about a specific protocol (MTProto, Signal, RC4, TLS):
protocol packages import from this package, never the other way round.
"""
