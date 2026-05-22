/* In this file we store global variables and structures */

import { keylog_enabled } from "../fritap_agent.js";

export type ModuleHookingType = (moduleName: string, is_base_hook: boolean) => void;

export type Platform = "linux" | "darwin" | "windows" | "wine";

export type LibraryType =
    | "openssl" | "boringssl" | "libressl" | "gnutls" | "wolfssl"
    | "nss" | "mbedtls" | "s2ntls" | "rustls"
    | "gotls" | "matrixssl" | "sspi" | "lsass" | "nss_hpke"
    | "quiche" | "msquic" | "google_quiche" | "neqo"
    | "ssh_openssh" | "ssh_libssh"
    | "ipsec_strongswan";
export const PLATFORM_LINUX: Platform = "linux";
export const PLATFORM_DARWIN: Platform = "darwin";
export const PLATFORM_WINDOWS: Platform = "windows";
export const PLATFORM_WINE: Platform = "wine";

export const unwantedFDs = new Set<number>(); // this helps us to track if we alredy encountered this fd

export const AF_INET = 2;
export const AF_INET6 = 10;
export const AF_UNIX = 1;
export const pointerSize = Process.pointerSize;

export const AddressFamilyMapping: { [key: number]: string } = {
    2: "AF_INET", // IPv4
    10: "AF_INET6", // IPv6
    1: "AF_UNIX", // Unix domain sockets
    17: "AF_PACKET", // Raw packets
    // Add other address families as needed
};

// Module-level protocol cache — avoids require() on every TLS packet
let _selectedProtocol: string = "tls";

/**
 * Set the active protocol used by sendWithProtocol.
 * Called once from fritap_agent.ts after the recv handshake completes.
 *
 * @param protocol  The protocol string (e.g., "tls", "ssh", "ipsec")
 */
export function setSelectedProtocol(protocol: string): void {
    _selectedProtocol = protocol;
}

/**
 * Send a message to the Python side with the active protocol stamped in.
 *
 * @param message  The payload object (will be mutated with `protocol` field)
 * @param data     Optional binary data to attach
 */
export function sendWithProtocol(message: { [key: string]: any }, data?: ArrayBuffer | number[] | null): void {
    message["protocol"] = _selectedProtocol;
    if (data !== undefined && data !== null) {
        send(message, data);
    } else {
        send(message);
    }
}

export function sendKeylog(keylogLine: string): void {
    // Defensive choke point: even if a hook site forgot to honor the
    // keylog_enabled gate at install time, no KeylogEvent leaves the agent
    // when the user requested plaintext-only mode.
    if (!keylog_enabled) return;
    sendWithProtocol({ contentType: "keylog", keylog: keylogLine });
}

/**
 * Gated emitter for protocol key material that does NOT flow through
 * sendKeylog() — i.e. keys sent under custom contentTypes such as ssh_key,
 * ssh_keylog, ipsec_child_sa_keys and ipsec_ike_keys (and any future protocol).
 *
 * This mirrors the keylog_enabled choke point in sendKeylog() so that no key
 * material leaves the agent in plaintext-only mode (-p without -k), regardless
 * of which protocol emits it. Without this, every sendWithProtocol() key
 * emission would have to remember to gate itself by hand — exactly the trap
 * that let IPSec keys leak. Route all direct key emissions through here.
 */
export function sendKeyMaterial(message: { [key: string]: any }, data?: ArrayBuffer | number[] | null): void {
    if (!keylog_enabled) return;
    sendWithProtocol(message, data);
}

export function sendDatalog(message: { [key: string]: any }, data: ArrayBuffer | number[] | null): void {
    message["contentType"] = "datalog";
    sendWithProtocol(message, data);
}

export function sendConnectionLifecycle(
    event: string,
    message: { [key: string]: any },
): void {
    message["contentType"] = "connection_lifecycle";
    message["event"] = event;
    sendWithProtocol(message);
}

/**
 * Send a QUIC keylog line with BOTH the standard TLS 1.3 label
 * AND a QUIC_ prefixed duplicate.
 *
 * Only used by QUIC library hooks (quiche, Google QUICHE, msquic).
 * Regular TLS hooks should continue using sendKeylog() directly.
 */
export function sendQuicKeylog(keylogLine: string): void {
    // Emit standard label (Wireshark compatibility)
    sendKeylog(keylogLine);
    // Emit QUIC_ prefixed duplicate (other tools)
    const spaceIdx = keylogLine.indexOf(" ");
    if (spaceIdx > 0) {
        const label = keylogLine.substring(0, spaceIdx);
        const rest = keylogLine.substring(spaceIdx);
        sendKeylog("QUIC_" + label + rest);
    }
}

/**
 * Send a QUIC datalog message with stream_id and optional connection IDs.
 *
 * @param message  The payload (will be mutated with contentType, stream_id, quic_scid, quic_dcid)
 * @param data     Binary plaintext data
 * @param streamId QUIC stream ID (-1 for datagrams)
 * @param scid     Source Connection ID hex (optional)
 * @param dcid     Destination Connection ID hex (optional)
 * @param transport Transport for pcap framing — QUIC is always "udp" (default)
 * @param http3Headers Decoded HTTP/3 header list [[name, value], ...] (optional).
 *                     Used by the app-API capture path (OnHeadersDecoded). When
 *                     present and non-empty it is attached as message["http3_headers"];
 *                     header-only sends pass data = null.
 */
export function sendQuicDatalog(
    message: { [key: string]: any },
    data: ArrayBuffer | number[] | null,
    streamId: number,
    scid?: string,
    dcid?: string,
    transport: "udp" | "tcp" = "udp",
    http3Headers?: [string, string][],
): void {
    message["stream_id"] = streamId;
    if (scid) message["quic_scid"] = scid;
    if (dcid) message["quic_dcid"] = dcid;
    message["transport"] = transport;
    if (http3Headers && http3Headers.length > 0) message["http3_headers"] = http3Headers;
    sendDatalog(message, data);
}