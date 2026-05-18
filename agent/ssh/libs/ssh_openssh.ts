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
     * Resolve addresses for SSH hooks.
     *
     * Covers:
     *  - Key extraction:   cipher_init (preferred, version-stable args),
     *                      kex_derive_keys / kex_derive_keys_bn (shared secret),
     *                      kex_send_kexinit / kex_input_kexinit (cookies),
     *                      ssh_set_newkeys (status).
     *  - Plaintext hooks:  ssh_packet_send2_wrapped / ssh_packet_read_poll2,
     *                      cipher_crypt (fallback when wrappers are stripped).
     *  - Accessors:        sshbuf_ptr / sshbuf_len (buffer reads),
     *                      ssh_packet_get_connection_in / _out (fd discovery).
     *
     * Returns true when at least one key-extraction or plaintext entry point
     * resolved — callers can still install partial hooks.
     */
    resolveAddresses(): boolean {
        const targetFunctions = [
            // key extraction
            "kex_derive_keys",
            "kex_derive_keys_bn",
            "kex_send_kexinit",
            "kex_input_kexinit",
            "ssh_set_newkeys",
            "cipher_init",
            // plaintext
            "ssh_packet_send2_wrapped",
            "ssh_packet_read_poll2",
            "cipher_crypt",
            // helpers
            "sshbuf_ptr",
            "sshbuf_len",
            "ssh_packet_get_connection_in",
            "ssh_packet_get_connection_out",
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
                // mode is MODE_IN(0) / MODE_OUT(1) — a direction relative to
                // the local process, not an endpoint role. The active hook
                // path in ssh_linux.ts resolves this to C2S/S2C using the
                // process role; here we only have packet-layer direction.
                const direction = this.mode === 0 ? "in" : "out";
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
