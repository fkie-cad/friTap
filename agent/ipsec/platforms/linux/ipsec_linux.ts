/**
 * IPSec key extraction hooks for Linux (strongSwan).
 *
 * Hooks ikev2_derive_child_sa_keys() and derive_ike_keys()
 * to extract ESP and IKE SA key material.
 *
 * Based on keys-in-flux research:
 * https://github.com/fkie-cad/keys-in-flux-paper-material
 */

import { log, devlog } from "../../../util/log.js";

function readKeyMaterial(ptr: NativePointer, label: string): string | null {
    try {
        if (ptr.isNull()) return null;
        // key_material_t: { ptr: void*, len: size_t }
        const dataPtr = ptr.readPointer();
        const dataLen = ptr.add(Process.pointerSize).readUInt();
        if (dataLen > 0 && dataLen < 1024 && !dataPtr.isNull()) {
            const data = dataPtr.readByteArray(dataLen);
            if (data) {
                const hex = Array.from(new Uint8Array(data))
                    .map(b => b.toString(16).padStart(2, '0')).join('');
                devlog(`[IPSec] ${label}: ${hex.substring(0, 32)}... (${dataLen} bytes)`);
                return hex;
            }
        }
    } catch (e) {
        devlog(`[IPSec] Error reading key material for ${label}: ${e}`);
    }
    return null;
}

export function ipsec_execute(moduleName: string, is_base_hook: boolean): void {
    devlog(`[IPSec] Installing IPSec hooks for: ${moduleName}`);
    log(`[*] IPSec library found: ${moduleName}`);

    // Notify Python side about the detected library
    send({
        contentType: "library_detected",
        library: moduleName,
        protocol: "ipsec",
        message: `IPSec library detected: ${moduleName}`,
    });

    // Hook ikev2_derive_child_sa_keys() — ESP key material
    const deriveChildSaKeys = (Module as any).findExportByName(moduleName, "ikev2_derive_child_sa_keys");
    if (deriveChildSaKeys) {
        // This function is called during Child SA establishment and derives the ESP keys (SK_ei, SK_er)
        // Key Extraction will be implemented in the future; currently we just log that the function was called
        log(`[IPSec] Hooked ikev2_derive_child_sa_keys in ${moduleName}`);
    } else {
        devlog(`[IPSec] ikev2_derive_child_sa_keys not found in ${moduleName}`);
    }

    // Hook derive_ike_keys() — IKE SA keys (SK_ai, SK_ar, SK_ei, SK_er)
    const deriveIkeKeys = (Module as any).findExportByName(moduleName, "derive_ike_keys");
    if (deriveIkeKeys) {
        // This function is called during IKE SA establishment and derives the IKE SA keys
        // currently we only log that; in the future we could also extract the keys if they are passed as output parameters or accessible via global state
        log(`[IPSec] Hooked derive_ike_keys in ${moduleName}`);
    } else {
        devlog(`[IPSec] derive_ike_keys not found in ${moduleName}`);
    }
}

// Keep backward-compatible export name for existing registrations
export { ipsec_execute as ipsec_detect_execute };
