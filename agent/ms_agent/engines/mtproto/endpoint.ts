/* ---------------------------------------------------------------------------
 * ConnectionSocket peer-address decoding for Tier E (MTPROTO_OBF_KEY endpoints).
 *
 * The offsets are relative to the Connection object base — the same
 * this[0]==(moduleBase + vtable_ptr_rva) anchor Tier E already scans for.
 * ConnectionSocket is the primary base, so there is NO multiple-inheritance
 * delta to add. The sockaddr is PREFERRED over the socket fd because it survives
 * socket_fd==-1 (an idle/torn-down socket). MEASURED + on-device VALIDATED for
 * libtmessages.49 / Telegram 12.10.x arm64 — see research/re_tier_e/.
 *
 * Split out of scanner.ts as a single-responsibility module so the decode logic
 * can be unit-tested with synthetic buffers (endpoint.test.ts), and kept pure:
 * it takes a NativePointer-like base and reads through it, holding no state.
 *
 * Frida-17-safe: Frida 17 removed the Memory.read* free functions, so every read
 * goes through the NativePointer's own guarded methods. A faulting/short read or
 * an unknown family yields NO_ENDPOINT ('-') and NEVER throws — a bad endpoint
 * must not drop the recovered obfuscation key.
 * ------------------------------------------------------------------------- */

export const AF_INET = 2;        // sockaddr_in.sin_family  (host byte order)
export const AF_INET6 = 10;      // sockaddr_in6.sin6_family (Linux/Android, host order)
export const NO_ENDPOINT = '-';

/* The family field is a host-order uint16, so NativePointer.readU16 (host-endian)
 * reads it directly. Guarded: a candidate base is a guessed address and a fault
 * is the normal case, not the exceptional one. */
function guardedReadU16(p: any): number | null {
    try { return p.readU16(); } catch (e: any) { return null; }
}

/* The address and port bytes are read raw (a byte array) because the port is in
 * NETWORK byte order (big-endian), independent of the host, and the address is a
 * fixed-width byte string either way. */
function guardedReadBytes(p: any, len: number): Uint8Array | null {
    try {
        var b = p.readByteArray(len);
        return b === null ? null : new Uint8Array(b);
    } catch (e: any) { return null; }
}

/* Two big-endian (network-order) bytes -> a port number. */
function bePort(b: Uint8Array): number {
    return ((b[0] << 8) | b[1]) & 0xffff;
}

export function formatIPv4(addr: Uint8Array): string {
    return addr[0] + '.' + addr[1] + '.' + addr[2] + '.' + addr[3];
}

/* Colon-hex, all eight groups, no zero compression: compact enough for the
 * space-separated keylog line, unambiguous, and trivial to parse offline. */
export function formatIPv6(addr: Uint8Array): string {
    var parts: string[] = [], i;
    for (i = 0; i < 16; i += 2) {
        parts.push((((addr[i] << 8) | addr[i + 1]) & 0xffff).toString(16));
    }
    return parts.join(':');
}

/* Decode the peer "ip:port" from a Connection object base, or NO_ENDPOINT.
 *
 * Read the IPv4 family at endpoint_sockaddr_in first: if it is AF_INET the peer
 * is IPv4 (addr @+4, port BE @+2). Otherwise read the IPv6 family at
 * endpoint_sockaddr_in6: if it is AF_INET6 the peer is IPv6 (addr @+8, port BE
 * @+2). Anything else — a missing offset, a faulting read, or an unknown family
 * — falls back to NO_ENDPOINT. Never throws. */
export function readConnectionEndpoint(objBase: any, off: any): string {
    try {
        var v4 = off && off.endpoint_sockaddr_in;
        if (typeof v4 === 'number' && guardedReadU16(objBase.add(v4)) === AF_INET) {
            var port4 = guardedReadBytes(objBase.add(v4 + 2), 2);
            var addr4 = guardedReadBytes(objBase.add(v4 + 4), 4);
            if (port4 !== null && addr4 !== null) {
                return formatIPv4(addr4) + ':' + bePort(port4);
            }
        }
        var v6 = off && off.endpoint_sockaddr_in6;
        if (typeof v6 === 'number' && guardedReadU16(objBase.add(v6)) === AF_INET6) {
            var port6 = guardedReadBytes(objBase.add(v6 + 2), 2);
            var addr6 = guardedReadBytes(objBase.add(v6 + 8), 16);
            if (port6 !== null && addr6 !== null) {
                return '[' + formatIPv6(addr6) + ']:' + bePort(port6);
            }
        }
    } catch (e: any) { /* fall through to NO_ENDPOINT — a bad endpoint never drops the key */ }
    return NO_ENDPOINT;
}
