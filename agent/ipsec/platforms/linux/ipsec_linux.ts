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
import { sendWithProtocol } from "../../../shared/shared_structures.js";
import { toHexString } from "../../../shared/shared_functions.js";

function readKeyMaterial(ptr: NativePointer, label: string): string | null {
    try {
        if (ptr.isNull()) return null;
        // key_material_t: { ptr: void*, len: size_t }
        const dataPtr = ptr.readPointer();
        const dataLen = ptr.add(Process.pointerSize).readUInt();
        if (dataLen > 0 && dataLen < 1024 && !dataPtr.isNull()) {
            const data = dataPtr.readByteArray(dataLen);
            if (data) {
                const hex = toHexString(data);
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
    sendWithProtocol({
        contentType: "library_detected",
        library: moduleName,
        message: `IPSec library detected: ${moduleName}`,
    });

    // Hook ikev2_derive_child_sa_keys() — ESP key material
    const deriveChildSaKeys = (Module as any).findExportByName(moduleName, "ikev2_derive_child_sa_keys");
    if (deriveChildSaKeys) {
        Interceptor.attach(deriveChildSaKeys, {
            onEnter: function (args) {
                // Arguments vary by strongSwan version
                // Typically: proposal, dh_secret, nonce_i, nonce_r, encr_i, encr_r, integ_i, integ_r
                this.args = [];
                for (let i = 0; i < 8; i++) {
                    this.args.push(args[i]);
                }
            },
            onLeave: function (retval) {
                try {
                    // Output args are typically at indices 4-7:
                    // encr_i (initiator encryption), encr_r (responder encryption)
                    // integ_i (initiator integrity), integ_r (responder integrity)
                    const labels = ["encr_i", "encr_r", "integ_i", "integ_r"];
                    const keys: { [key: string]: string } = {};

                    for (let i = 4; i < 8 && i < this.args.length; i++) {
                        const keyData = readKeyMaterial(this.args[i], labels[i - 4]);
                        if (keyData) {
                            keys[labels[i - 4]] = keyData;
                        }
                    }

                    if (Object.keys(keys).length > 0) {
                        sendWithProtocol({
                            contentType: "ipsec_child_sa_keys",
                            keys: keys,
                            message: "ESP Child SA keys extracted",
                        });
                        log(`[IPSec] Child SA keys extracted (${Object.keys(keys).length} keys)`);
                    }
                } catch (e) {
                    devlog(`[IPSec] Error in ikev2_derive_child_sa_keys onLeave: ${e}`);
                }
            }
        });
        log(`[IPSec] Hooked ikev2_derive_child_sa_keys in ${moduleName}`);
    } else {
        devlog(`[IPSec] ikev2_derive_child_sa_keys not found in ${moduleName}`);
    }

    // Hook derive_ike_keys() — IKE SA keys (SK_ai, SK_ar, SK_ei, SK_er)
    const deriveIkeKeys = (Module as any).findExportByName(moduleName, "derive_ike_keys");
    if (deriveIkeKeys) {
        Interceptor.attach(deriveIkeKeys, {
            onEnter: function (args) {
                this.args = [];
                for (let i = 0; i < 6; i++) {
                    this.args.push(args[i]);
                }
            },
            onLeave: function (retval) {
                try {
                    // IKE SA key outputs: SK_ai, SK_ar, SK_ei, SK_er, SK_pi, SK_pr
                    const labels = ["SK_ai", "SK_ar", "SK_ei", "SK_er", "SK_pi", "SK_pr"];
                    const keys: { [key: string]: string } = {};

                    for (let i = 0; i < this.args.length; i++) {
                        const keyData = readKeyMaterial(this.args[i], labels[i] || `arg${i}`);
                        if (keyData) {
                            keys[labels[i] || `arg${i}`] = keyData;
                        }
                    }

                    if (Object.keys(keys).length > 0) {
                        sendWithProtocol({
                            contentType: "ipsec_ike_keys",
                            keys: keys,
                            message: "IKE SA keys extracted",
                        });
                        log(`[IPSec] IKE SA keys extracted (${Object.keys(keys).length} keys)`);
                    }
                } catch (e) {
                    devlog(`[IPSec] Error in derive_ike_keys onLeave: ${e}`);
                }
            }
        });
        log(`[IPSec] Hooked derive_ike_keys in ${moduleName}`);
    } else {
        devlog(`[IPSec] derive_ike_keys not found in ${moduleName}`);
    }
}

// Keep backward-compatible export name for existing registrations
export { ipsec_execute as ipsec_detect_execute };
