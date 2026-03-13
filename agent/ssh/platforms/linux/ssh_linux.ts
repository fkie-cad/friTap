/**
 * SSH key extraction hooks for Linux (OpenSSH).
 *
 * Hooks kex_derive_keys() and ssh_set_newkeys() to extract
 * encryption keys and IVs from the sshenc struct.
 *
 * Based on keys-in-flux research:
 * https://github.com/fkie-cad/keys-in-flux-paper-material
 */

import { log, devlog } from "../../../util/log.js";
import { sendWithProtocol } from "../../../shared/shared_structures.js";
import { toHexString } from "../../../shared/shared_functions.js";

// sshenc struct offsets (OpenSSH 9.x/10.x)
// These match the struct layout: cipher_name(+0), key_len(+20), iv_len(+24), key_ptr(+32), iv_ptr(+32+ptrSize)
const SSHENC_CIPHER_NAME_OFFSET = 0;
const SSHENC_KEY_LEN_OFFSET = 20;
const SSHENC_IV_LEN_OFFSET = 24;
const SSHENC_KEY_PTR_OFFSET = 32;

function readSshEncKeys(sshencPtr: NativePointer, direction: string): void {
    try {
        const cipherNamePtr = sshencPtr.add(SSHENC_CIPHER_NAME_OFFSET).readPointer();
        const cipherName = cipherNamePtr.readCString() || "unknown";
        const keyLen = sshencPtr.add(SSHENC_KEY_LEN_OFFSET).readU32();
        const ivLen = sshencPtr.add(SSHENC_IV_LEN_OFFSET).readU32();
        const ptrSize = Process.pointerSize;
        const keyPtr = sshencPtr.add(SSHENC_KEY_PTR_OFFSET).readPointer();
        const ivPtr = sshencPtr.add(SSHENC_KEY_PTR_OFFSET + ptrSize).readPointer();

        if (keyLen > 0 && keyLen < 256 && !keyPtr.isNull()) {
            const keyData = keyPtr.readByteArray(keyLen);
            if (keyData) {
                const keyHex = toHexString(keyData);

                sendWithProtocol({
                    contentType: "ssh_key",
                    direction: direction,
                    key_type: `SSH_ENC_KEY_${direction.toUpperCase()}`,
                    cipher: cipherName,
                    key_len: keyLen,
                    key_data: keyHex,
                });

                log(`[SSH] ${direction} key extracted: cipher=${cipherName}, len=${keyLen}`);
            }
        }

        if (ivLen > 0 && ivLen < 256 && !ivPtr.isNull()) {
            const ivData = ivPtr.readByteArray(ivLen);
            if (ivData) {
                const ivHex = toHexString(ivData);

                sendWithProtocol({
                    contentType: "ssh_key",
                    direction: direction,
                    key_type: `SSH_IV_${direction.toUpperCase()}`,
                    cipher: cipherName,
                    iv_len: ivLen,
                    key_data: ivHex,
                });

                log(`[SSH] ${direction} IV extracted: cipher=${cipherName}, len=${ivLen}`);
            }
        }
    } catch (e) {
        devlog(`[SSH] Error reading sshenc struct for ${direction}: ${e}`);
    }
}

export function ssh_execute(moduleName: string, is_base_hook: boolean): void {
    devlog(`[SSH] Installing SSH hooks for: ${moduleName}`);
    log(`[*] SSH library found: ${moduleName}`);

    // Notify Python side about the detected library
    sendWithProtocol({
        contentType: "library_detected",
        library: moduleName,
        message: `SSH library detected: ${moduleName}`,
    });

    // Hook kex_derive_keys() — called after key exchange completes
    const kexDeriveKeys = (Module as any).findExportByName(moduleName, "kex_derive_keys");
    if (kexDeriveKeys) {
        Interceptor.attach(kexDeriveKeys, {
            onEnter: function (args) {
                // arg0 = struct ssh *
                this.sshPtr = args[0];
            },
            onLeave: function (retval) {
                if (this.sshPtr.isNull()) return;
                try {
                    // Navigate: ssh->state->newkeys[MODE_IN]->enc
                    // ssh->state is at offset depending on version
                    // For OpenSSH 9.x: ssh->state is first pointer field
                    const statePtr = this.sshPtr.readPointer();
                    if (statePtr.isNull()) return;

                    const ptrSize = Process.pointerSize;
                    // newkeys[MODE_IN=0] and newkeys[MODE_OUT=1]
                    // state->newkeys is an array of 2 pointers
                    for (let mode = 0; mode < 2; mode++) {
                        const direction = mode === 0 ? "client" : "server";
                        try {
                            const newkeysPtr = statePtr.add(mode * ptrSize).readPointer();
                            if (!newkeysPtr.isNull()) {
                                // newkeys->enc is the sshenc struct (first field)
                                const encPtr = newkeysPtr;
                                readSshEncKeys(encPtr, direction);
                            }
                        } catch (e) {
                            devlog(`[SSH] Error reading newkeys[${mode}]: ${e}`);
                        }
                    }
                } catch (e) {
                    devlog(`[SSH] Error in kex_derive_keys onLeave: ${e}`);
                }
            }
        });
        log(`[SSH] Hooked kex_derive_keys in ${moduleName}`);
    } else {
        devlog(`[SSH] kex_derive_keys not found in ${moduleName}`);
    }

    // Hook ssh_set_newkeys() — called when new keys are activated
    const sshSetNewkeys = (Module as any).findExportByName(moduleName, "ssh_set_newkeys");
    if (sshSetNewkeys) {
        Interceptor.attach(sshSetNewkeys, {
            onEnter: function (args) {
                this.sshPtr = args[0];
                this.mode = args[1].toInt32(); // MODE_IN=0, MODE_OUT=1
            },
            onLeave: function (retval) {
                const direction = this.mode === 0 ? "client" : "server";
                log(`[SSH] New keys activated for ${direction} direction`);
                sendWithProtocol({
                    contentType: "ssh_newkeys",
                    direction: direction,
                    message: `SSH new keys activated: ${direction}`,
                });
            }
        });
        log(`[SSH] Hooked ssh_set_newkeys in ${moduleName}`);
    } else {
        devlog(`[SSH] ssh_set_newkeys not found in ${moduleName}`);
    }
}

// Keep backward-compatible export name for existing registrations
export { ssh_execute as ssh_detect_execute };
