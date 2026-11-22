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

/** Windows (and NSPR-on-Windows PR_AF_INET6) AF_INET6 value. */
const WINDOWS_AF_INET6 = 23;

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
 *
 * Windows' AF_INET6 (23) is mapped to 10 on every non-Darwin platform, not only
 * on "windows": a PE NSPR / Winsock under Wine reports Process.platform "linux"
 * but still stores 23. On Linux/Android 23 is the obsolete AF_IRDA, which is
 * never a TCP/UDP peer, so the mapping cannot misclassify a real native address.
 */
export function readSockaddrFamily(sa: NativePointer, bsdSockaddr: boolean = false): number {
    if (bsdSockaddr && Process.platform === "darwin") {
        const fam = sa.add(1).readU8();        // sa_len@0, sa_family@1
        return fam === 30 ? AF_INET6 : fam;    // Darwin AF_INET6 (30) -> Linux value (10)
    }
    const fam = sa.readU16();
    // NSPR PRNetAddr keeps a 2-byte family@0 on all platforms, but PR_AF_INET6
    // is defined per platform as the OS AF_INET6 (NSPR prcpucfg: Linux 10,
    // macOS 30, Windows 23), and a native sockaddr uses the same OS value.
    // Normalize so the AF_INET6 (==10) branch matches.
    return fam === nativeAfInet6() ? AF_INET6 : fam;
}

/** The OS AF_INET6 value that differs from Linux's 10: Darwin's 30, else Windows' 23 (see above). */
function nativeAfInet6(): number {
    return Process.platform === "darwin" ? 30 : WINDOWS_AF_INET6;
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
