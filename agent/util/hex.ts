/**
 * hex.ts — PUBLIC, side-effect-free hex helpers.
 *
 * Lives in agent/util/ (the genuinely pure layer: no install-time side effects,
 * no frida-java-bridge / registry / library_scanner imports). Safe to import
 * from anywhere — the public scan engine, the private signal binding, legacy TLS
 * libs — without dragging in the agent's top-level install. Imports NOTHING.
 */

// Pre-built lookup table: byte value -> two-char lowercase hex string (built
// once at module load). Moved here from shared_functions.ts so the byte->hex
// impl has a single home; shared_functions re-exports toHexString for its many
// existing callers.
const byteToHex: string[] = [];
for (let n = 0; n <= 0xff; ++n) {
    byteToHex.push(n.toString(16).padStart(2, "0"));
}

/**
 * Byte sequence -> continuous lowercase hex string ("0a1bff", no separator).
 * Accepts number[], Uint8Array, ArrayBuffer, or any value Uint8Array can wrap
 * (legacy callers pass `any`). Each element is coerced to a 0..255 byte, so this
 * exactly reproduces both the old scan_engine.toHex(number[]) and the old
 * shared_functions.toHexString(any).
 */
export function toHexString(byteArray: any): string {
    return Array.prototype.map.call(
        new Uint8Array(byteArray),
        (n: number) => byteToHex[n]
    ).join("");
}

/**
 * ASCII string -> space-separated Frida Memory.scan pattern ("43 4c 49 ..."),
 * each char's code as two-char lowercase hex. Reproduces the former
 * memory_scan_strategy._stringToHexPattern and signal_libsignal._asciiToHexPattern
 * byte-for-byte (empty string -> "").
 */
export function toHexPattern(str: string): string {
    let out = "";
    for (let i = 0; i < str.length; i++) {
        if (i > 0) out += " ";
        out += str.charCodeAt(i).toString(16).padStart(2, "0");
    }
    return out;
}
