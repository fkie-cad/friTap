// Pure sockaddr / PRNetAddr decoders, factored out of shared_functions.ts so
// they can be unit-tested under Node without the heavy Frida import graph
// (shared_functions.ts runs native pointer arithmetic at load). This module
// depends only on the AF_* constants and Process.platform.
//
// See sockaddr.test.ts for the darwin (BSD sockaddr) coverage.

import { AF_INET, AF_INET6 } from "./shared_structures.js";

/** Decoded sockaddr/PRNetAddr tuple in the pcap-writer address encoding. */
export interface DecodedSockaddr {
    family: "AF_INET" | "AF_INET6";
    port: number;            // host-order
    addr: number | string;   // AF_INET -> host-order int; AF_INET6 -> 32-char uppercase hex
}

/** libc byte-order conversion functions, used only when the native path is requested. */
export interface ByteOrderFns {
    ntohs: NativeFunction<number, [number]>;
    ntohl: NativeFunction<number, [number]>;
}

/**
 * Read the address family from `sa`, normalized to the Linux/NSPR AF_* values
 * this module compares against (AF_INET=2, AF_INET6=10).
 *
 * Linux/Android sockaddr AND NSPR PRNetAddr both store a 2-byte family at
 * offset 0. A BSD/Darwin sockaddr instead has a 1-byte `sa_len` at offset 0 with
 * the family in the single byte at offset 1, and uses AF_INET6=30. Pass
 * `bsdSockaddr=true` ONLY for a real BSD sockaddr (e.g. a connect() argument) so
 * the leading-length convention is honored on macOS/iOS — NEVER for a PRNetAddr
 * (its 2-byte family@0 layout is platform-independent, so the NSS callers must
 * leave this false). The port/address field offsets (port@2, v4@4, v6@8) are
 * identical across both layouts, so only the family read needs platform care.
 */
export function readSockaddrFamily(sa: NativePointer, bsdSockaddr: boolean = false): number {
    if (bsdSockaddr && Process.platform === "darwin") {
        const fam = sa.add(1).readU8();        // sa_len@0, sa_family@1
        return fam === 30 ? AF_INET6 : fam;    // Darwin AF_INET6 (30) -> Linux value (10)
    }
    const fam = sa.readU16();
    // NSPR PRNetAddr keeps a 2-byte family@0 on all platforms, but on macOS it
    // stores the OS AF_INET6 value (30). Normalize so the AF_INET6 (==10) branch
    // matches. Linux/Windows never report 30 here, so this is a no-op there.
    return (fam === 30 && Process.platform === "darwin") ? AF_INET6 : fam;
}

/**
 * Decode a sockaddr (or NSS PRNetAddr, which shares the field layout) at `sa`
 * into { family, port, addr }. Layout: family@0, port@2, IPv4@4, IPv6@8.
 * Folds IPv4-mapped IPv6 (::ffff:a.b.c.d) down to AF_INET. Returns null for
 * unsupported families. Does NOT filter loopback / port 0 — callers decide.
 *
 * By default uses platform-independent manual byte math, which is numerically
 * identical to libc ntohs/ntohl on both little- and big-endian hosts and needs
 * no native functions. Set `useNativeByteOrder = true` (and pass `fns`) to route
 * port/address conversion through libc ntohs/ntohl instead.
 *
 * @param sa Pointer to the sockaddr structure.
 * @param useNativeByteOrder When true, use `fns.ntohs`/`fns.ntohl` instead of byte math.
 * @param fns The ntohs/ntohl wrappers (required when `useNativeByteOrder` is true).
 * @param bsdSockaddr See readSockaddrFamily — true only for real BSD sockaddrs.
 */
export function decodeSockaddr(sa: NativePointer, useNativeByteOrder?: false, fns?: ByteOrderFns, bsdSockaddr?: boolean): DecodedSockaddr | null;
export function decodeSockaddr(sa: NativePointer, useNativeByteOrder: true, fns: ByteOrderFns, bsdSockaddr?: boolean): DecodedSockaddr | null;
export function decodeSockaddr(
    sa: NativePointer,
    useNativeByteOrder: boolean = false,
    fns?: ByteOrderFns,
    bsdSockaddr: boolean = false,
): DecodedSockaddr | null {
    if (sa.isNull()) return null;
    const family = readSockaddrFamily(sa, bsdSockaddr);

    const readPort = (): number =>
        (useNativeByteOrder && fns)
            ? (fns.ntohs(sa.add(2).readU16()) as number)
            : (((sa.add(2).readU8() << 8) | sa.add(3).readU8()) >>> 0);

    const readV4 = (p: NativePointer): number =>
        (useNativeByteOrder && fns)
            ? (fns.ntohl(p.readU32()) as number)
            : (((p.readU8() << 24) | (p.add(1).readU8() << 16) |
                (p.add(2).readU8() << 8) | p.add(3).readU8()) >>> 0);

    if (family === AF_INET) {
        return { family: "AF_INET", port: readPort(), addr: readV4(sa.add(4)) };
    }
    if (family === AF_INET6) {
        const base = sa.add(8); // sin6_addr
        let hex = "";
        for (let i = 0; i < 16; i++) {
            hex += ("0" + base.add(i).readU8().toString(16).toUpperCase()).slice(-2);
        }
        if (hex.indexOf("00000000000000000000FFFF") === 0) { // v4-mapped -> AF_INET
            return { family: "AF_INET", port: readPort(), addr: readV4(base.add(12)) };
        }
        return { family: "AF_INET6", port: readPort(), addr: hex };
    }
    return null;
}
