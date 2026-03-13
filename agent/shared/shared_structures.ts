/* In this file we store global variables and structures */

export type ModuleHookingType = (moduleName: string, is_base_hook: boolean) => void;

export type Platform = "linux" | "darwin" | "windows" | "wine";

export type LibraryType =
    | "openssl" | "boringssl" | "gnutls" | "wolfssl"
    | "nss" | "mbedtls" | "s2ntls" | "rustls"
    | "gotls" | "matrixssl" | "sspi";
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
    sendWithProtocol({ contentType: "keylog", keylog: keylogLine });
}

export function sendDatalog(message: { [key: string]: any }, data: ArrayBuffer | number[] | null): void {
    message["contentType"] = "datalog";
    sendWithProtocol(message, data);
}