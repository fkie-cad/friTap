/* In this file we store global variables and structures, including the process-
 * wide runtime state shared across ALL protocol hooks (TLS and any messenger
 * protocol). This module is side-effect-free: importing it never installs hooks.
 *
 * fritap_agent.ts SETS these via the setters during the config handshake and
 * re-exports them, so the many modules that read them from `fritap_agent` keep
 * working unchanged — while optional protocol units (e.g. agent/signal/) read
 * them from HERE without importing the agent entry (importing the entry would
 * run its top-level install, which must happen AFTER such units register).
 *
 * General rule when adding a new protocol: keep protocol-specific state inside
 * that protocol's own module; put anything reusable by other protocols here.
 */

// --- Shared runtime state (live ESM bindings; set once at config-handshake) ---
// Reads are live, taken at hook-INSTALL time (well after config parse), so the
// defaults below are only ever observed transiently during module import.

// `offsets` may transiently hold the un-replaced "{OFFSETS}" placeholder string
// (legacy string-replace build), a raw JSON string (--offsets handshake), or a
// parsed offsets object keyed by library name; callers treat it structurally.
export let offsets: any = "{OFFSETS}";
export let pcap_enabled: boolean = false;
export let keylog_enabled: boolean = true;   // default ON; friTap.py sets it explicitly
export let _isShuttingDown: boolean = false; // set true at gracefulDetach start
export let ohttp_enabled: boolean = true;
// Generic, protocol-agnostic passthrough bag from the host (config_batch.extensions).
// Carries opt-in feature config such as { scan_region: "<module|base,size|heap>" }
// for the public memory-scan engine (agent/shared/scan/). A private protocol unit
// reads its own sub-keys from here; the public core never names a private key.
export let config_extensions: Record<string, any> = {};

export function setOffsets(value: any): void { offsets = value; }
export function setPcapEnabled(value: boolean): void { pcap_enabled = value; }
export function setKeylogEnabled(value: boolean): void { keylog_enabled = value; }
export function setIsShuttingDown(value: boolean): void { _isShuttingDown = value; }
export function setOhttpEnabled(value: boolean): void { ohttp_enabled = value; }
export function setConfigExtensions(value: Record<string, any>): void { config_extensions = value ?? {}; }

export type ModuleHookingType = (moduleName: string, is_base_hook: boolean) => void;

export type Platform = "linux" | "darwin" | "windows" | "wine";

export type LibraryType =
    | "openssl" | "boringssl" | "libressl" | "gnutls" | "wolfssl"
    | "nss" | "mbedtls" | "s2ntls" | "rustls"
    | "gotls" | "matrixssl" | "sspi" | "lsass" | "nss_hpke"
    | "quiche" | "msquic" | "google_quiche" | "neqo"
    | "ssh_openssh" | "ssh_libssh"
    | "ipsec_strongswan"
    | "mtproto_tgnet"
    | "signal_libsignal"
    | "telegram_e2e";
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

// Active protocol selected on the CLI — shared across all protocol hooks (read
// by sendWithProtocol for message tagging and by the per-platform hook loaders
// for hook filtering). Avoids require() on every TLS packet.
export let selected_protocol: string = "tls";

/**
 * Set the active protocol used by sendWithProtocol and hook filtering.
 * Called once from fritap_agent.ts after the recv handshake completes.
 *
 * @param protocol  The protocol string (e.g., "tls", "ssh", "ipsec")
 */
export function setSelectedProtocol(protocol: string): void {
    selected_protocol = protocol;
}

/**
 * Send a message to the Python side with the active protocol stamped in.
 *
 * @param message  The payload object (will be mutated with `protocol` field)
 * @param data     Optional binary data to attach
 */
export function sendWithProtocol(message: { [key: string]: any }, data?: ArrayBuffer | number[] | null): void {
    message["protocol"] = selected_protocol;
    if (data !== undefined && data !== null) {
        send(message, data);
    } else {
        send(message);
    }
}

/**
 * Like sendWithProtocol, but stamps an explicit protocol tag instead of the
 * active `selected_protocol`. Used for key material that is definitionally
 * bound to one protocol regardless of which protocol the user selected on the
 * CLI (e.g. NSS keylog lines are always TLS, even under `--protocol signal`,
 * which IMPLIES tls and runs the TLS hooks alongside the Signal hooks).
 */
function sendWithProtocolTag(message: { [key: string]: any }, protocol: string, data?: ArrayBuffer | number[] | null): void {
    message["protocol"] = protocol;
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
    // NSS keylog lines (CLIENT_RANDOM / EXPORTER_SECRET / TLS 1.3 secrets, and
    // their QUIC_ duplicates) are always TLS key material. They are emitted by
    // the TLS/QUIC hooks, which run whenever a composite protocol implies "tls"
    // (e.g. signal → [signal, tls]). Tag them "tls" explicitly so they route to
    // the TLS keylog formatter/file rather than being mis-tagged with the
    // active protocol (which would drop them — the Signal formatter can't parse
    // raw NSS lines, and the TLS handler never sees a "tls" event otherwise).
    sendWithProtocolTag({ contentType: "keylog", keylog: keylogLine }, "tls");
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
    // Shutdown-time short-circuit. Once gracefulDetach has fired, this is the
    // single chokepoint for ALL plaintext IPC (datalog from QUIC, TLS, SSH,
    // IPSec — every protocol). Skipping send() here lets pending Interceptor
    // callbacks already queued on the JS message loop drain in microseconds
    // (just the gate check) instead of seconds (full message serialization +
    // post to Python). Without this, script.unload() blocks until the queue
    // drains, which under heavy Chrome HTTP/3 traffic blows past any
    // reasonable detach timeout.
    if (_isShuttingDown) return;
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