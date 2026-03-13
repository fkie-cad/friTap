/**
 * OpenSSH hook class for SSH key extraction.
 *
 * Follows the same pattern as openssl_boringssl.ts for consistency.
 * Uses symbol-based lookup with pattern infrastructure wired in.
 */

import { log, devlog } from "../../util/log.js";
import { sendWithProtocol } from "../../shared/shared_structures.js";

export class SSH_OpenSSH {
    module_name: string;
    addresses: { [functionName: string]: NativePointer };

    constructor(moduleName: string) {
        this.module_name = moduleName;
        this.addresses = {};
    }

    /**
     * Resolve addresses for SSH key derivation functions.
     * Uses symbol-based lookup; pattern infrastructure wired but empty.
     */
    resolveAddresses(): boolean {
        const targetFunctions = [
            "kex_derive_keys",
            "ssh_set_newkeys",
            "kex_derive_keys_bn",
        ];

        let resolved = 0;
        for (const fn of targetFunctions) {
            const addr = (Module as any).findExportByName(this.module_name, fn);
            if (addr) {
                this.addresses[fn] = addr;
                resolved++;
                devlog(`[SSH_OpenSSH] Resolved ${fn} at ${addr}`);
            }
        }

        log(`[SSH_OpenSSH] Resolved ${resolved}/${targetFunctions.length} functions in ${this.module_name}`);
        return resolved > 0;
    }

    /**
     * Install hooks on resolved addresses.
     */
    installHooks(): void {
        if (this.addresses["kex_derive_keys"]) {
            this._hookKexDeriveKeys();
        }
        if (this.addresses["ssh_set_newkeys"]) {
            this._hookSshSetNewkeys();
        }
    }

    private _hookKexDeriveKeys(): void {
        const addr = this.addresses["kex_derive_keys"];
        Interceptor.attach(addr, {
            onEnter: function (args) {
                this.sshPtr = args[0];
            },
            onLeave: function (retval) {
                devlog("[SSH_OpenSSH] kex_derive_keys returned");
                // Key extraction deferred to ssh_execute() in ssh_linux.ts
                // which handles the full struct navigation
            }
        });
        devlog(`[SSH_OpenSSH] Hooked kex_derive_keys`);
    }

    private _hookSshSetNewkeys(): void {
        const addr = this.addresses["ssh_set_newkeys"];
        Interceptor.attach(addr, {
            onEnter: function (args) {
                this.sshPtr = args[0];
                this.mode = args[1].toInt32();
            },
            onLeave: function (retval) {
                const direction = this.mode === 0 ? "client" : "server";
                sendWithProtocol({
                    contentType: "ssh_newkeys",
                    direction: direction,
                    message: `SSH new keys activated: ${direction}`,
                });
            }
        });
        devlog(`[SSH_OpenSSH] Hooked ssh_set_newkeys`);
    }
}
