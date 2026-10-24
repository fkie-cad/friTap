// agent/legacy/tls/platforms/macos/libressl_macos.ts
//
// Legacy (class-based) LibreSSL executor for macOS.
// LibreSSL ships as /usr/lib/libssl.48.dylib on macOS.
// Unlike BoringSSL, LibreSSL's SSL_get_fd works correctly, so read/write hooks are enabled.

import { OpenSSL_BoringSSL } from "../../../../tls/libs/openssl_boringssl.js";
import { socket_library } from "../../../../platforms/macos.js";
import { devlog, devlog_error, log } from "../../../../util/log.js";
import { patterns, isPatternReplaced, experimental, getParsedPatterns } from "../../../../fritap_agent.js";
import { sendKeylog } from "../../../../shared/shared_structures.js";
import { findLibreSslKdfAddresses, attachLibreSslPrfHook } from "../../../../shared/libressl_kdf.js";
import { installLibreSslClientRandomViaSend, resolveLibreSslClientRandom, attachHandshakeTracker, currentHandshakeSsl } from "../../../../shared/libressl_client_random.js";
import { readHexFromPointer } from "../../../../tls/decoders/hex_utils.js";
import { executeSSLLibrary } from "../../../shared/shared_functions_legacy.js";
import { TLS13_LABEL_MAP } from "../../../../tls/definitions/shared_constants.js";
import { createKeylogCallbackTracker } from "../../../../shared/keylog_callback_tracker.js";

// Pre-allocated buffer reused across hook invocations
const _masterKeyBuf = Memory.alloc(48);


export class LibreSSL_MacOS extends OpenSSL_BoringSSL {

    private SSL_get_client_random_fn: NativeFunction<number, [NativePointer, NativePointer, number]> | null = null;
    private SSL_SESSION_get_master_key_fn: NativeFunction<number, [NativePointer, NativePointer, number]> | null = null;

    constructor(public moduleName: string, public socket_library: String, is_base_hook: boolean) {
        var library_method_mapping: { [key: string]: Array<string> } = {};
        library_method_mapping[`*${moduleName}*`] = [
            "SSL_read", "SSL_write", "SSL_get_fd",
            "SSL_get_session", "SSL_SESSION_get_id",
            "SSL_new", "SSL_CTX_set_keylog_callback",
            "SSL_get_client_random", "SSL_SESSION_get_master_key",
            "SSL_do_handshake", "SSL_connect", "SSL_accept",
        ];
        library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"];

        super(moduleName, socket_library, is_base_hook, library_method_mapping);

        // Force read/write hooks ON (LibreSSL's SSL_get_fd works on macOS, unlike BoringSSL)
        this.do_read_write_hooks = true;
        try {
            this.SSL_SESSION_get_id = new NativeFunction(this.addresses[this.moduleName]["SSL_SESSION_get_id"], "pointer", ["pointer", "pointer"]);
            this.SSL_get_fd = new NativeFunction(this.addresses[this.moduleName]["SSL_get_fd"], "int", ["pointer"]);
            this.SSL_get_session = new NativeFunction(this.addresses[this.moduleName]["SSL_get_session"], "pointer", ["pointer"]);
        } catch (e) {
            devlog_error(`[LibreSSL] Error creating NativeFunction wrappers: ${e}`);
            this.do_read_write_hooks = false;
        }

        const crAddr = this.addresses[this.moduleName]["SSL_get_client_random"];
        if (crAddr && !crAddr.isNull()) {
            this.SSL_get_client_random_fn = new NativeFunction(crAddr, "int", ["pointer", "pointer", "int"]);
        }

        const mkAddr = this.addresses[this.moduleName]["SSL_SESSION_get_master_key"];
        if (mkAddr && !mkAddr.isNull()) {
            this.SSL_SESSION_get_master_key_fn = new NativeFunction(mkAddr, "int", ["pointer", "pointer", "int"]);
        }
    }

    install_tls_keys_callback_hook() {

        // ── Tier 1: SSL_CTX_set_keylog_callback (LibreSSL 3.5+) ──
        const setKeylogAddr = this.addresses[this.moduleName]["SSL_CTX_set_keylog_callback"];
        if (setKeylogAddr && !setKeylogAddr.isNull()) {
            try {
                this.SSL_CTX_set_keylog_callback = new NativeFunction(setKeylogAddr, "void", ["pointer", "pointer"]);
                const instance = this;

                const sslNewAddr = this.addresses[this.moduleName]["SSL_new"];
                if (sslNewAddr && !sslNewAddr.isNull()) {
                    // Records every SSL_CTX we point at our script-owned keylog callback so
                    // releaseAgentHooks can undo it (see shared/keylog_callback_tracker.ts).
                    // SSL_CTX_up_ref / SSL_CTX_get_keylog_callback are optional: the
                    // tracker degrades safely when this LibreSSL build lacks them.
                    const tracker = createKeylogCallbackTracker(this.moduleName, setKeylogAddr, instance.keylog_callback, true);
                    Interceptor.attach(sslNewAddr, {
                        onEnter: function (args: any) {
                            try {
                                tracker.install(args[0]);
                            } catch (e) {
                                devlog_error(`[LibreSSL] Error in SSL_new keylog hook: ${e}`);
                            }
                        },
                    });
                    log("[LibreSSL] Keylog via SSL_CTX_set_keylog_callback installed");
                }
            } catch (e) {
                devlog(`[LibreSSL] SSL_CTX_set_keylog_callback setup failed: ${e}`);
            }
        }

        // ── Tier 2: Hook non-exported KDF functions ──
        // Always: LibreSSL exports SSL_CTX_set_keylog_callback (3.5+) but never
        // invokes the callback, so Tier 1 alone yields no keys.
        this.installKdfHooks();
    }

    private installKdfHooks(): void {
        this.installHandshakeTracker();

        // Resolve the KDF functions: symbol table first (dynamic/symbol-bearing
        // builds), byte-pattern fallback for stripped static hosts. Shared with
        // the modern definition via agent/shared/libressl_kdf.ts.
        const kdf = findLibreSslKdfAddresses(this.moduleName, getParsedPatterns());

        // Stripped-static path: no SSL_get_client_random, and client_random is
        // not reachable from any KDF frame — capture it from the ClientHello
        // send() (getThreadClientRandom falls back to it).
        if (!this.SSL_get_client_random_fn && (kdf.hkdf || kdf.hkdfWithLen || kdf.prf)) {
            installLibreSslClientRandomViaSend();
        }

        // ── TLS 1.3: tls13_hkdf_expand_label ──
        const hkdfAddr = kdf.hkdf;
        if (hkdfAddr) {
            log("[LibreSSL] Hooking tls13_hkdf_expand_label for TLS 1.3 key extraction");
            this.attachHkdfHook(hkdfAddr, "tls13_hkdf_expand_label");
        }

        const hkdfWithLenAddr = kdf.hkdfWithLen;
        if (hkdfWithLenAddr) {
            log("[LibreSSL] Hooking tls13_hkdf_expand_label_with_length");
            this.attachHkdfHook(hkdfWithLenAddr, "tls13_hkdf_expand_label_with_length");
        }

        // ── TLS 1.2: tls1_PRF ──
        const prfAddr = kdf.prf;
        if (prfAddr) {
            log("[LibreSSL] Hooking tls1_PRF for TLS 1.2 key extraction");
            attachLibreSslPrfHook(prfAddr, this.SSL_get_client_random_fn, (ssl) => this.extractMasterKey(ssl));
        }
    }

    /**
     * Shared HKDF hook installer for tls13_hkdf_expand_label variants.
     * Both variants have the same argument layout: args[0]=out, args[3]=label.
     */
    private attachHkdfHook(addr: NativePointer, funcName: string): void {
        const instance = this;
        Interceptor.attach(addr, {
            onEnter: function (args: any) {
                this.outSecret = args[0];
                this.labelPtr = args[3];
            },
            onLeave: function (_retval: any) {
                try {
                    const label = this.labelPtr.readCString();
                    const sslkeylogLabel = TLS13_LABEL_MAP[label];
                    if (!sslkeylogLabel) return;

                    const dataPtr = this.outSecret.readPointer();
                    const dataLen = this.outSecret.add(Process.pointerSize).readULong();
                    if (dataPtr.isNull() || dataLen === 0) return;

                    const secretHex = readHexFromPointer(dataPtr, dataLen as number);
                    const clientRandom = instance.getThreadClientRandom();
                    if (!clientRandom) return;

                    sendKeylog(`${sslkeylogLabel} ${clientRandom} ${secretHex}`);
                } catch (e) {
                    devlog_error(`[LibreSSL] ${funcName} onLeave error: ${e}`);
                }
            },
        });
    }

    private installHandshakeTracker(): void {
        // Hook every handshake entry point: LibreSSL's SSL_connect/SSL_accept
        // call the method's handshake directly, NOT through SSL_do_handshake.
        for (const sym of ["SSL_do_handshake", "SSL_connect", "SSL_accept"]) {
            const addr = this.addresses[this.moduleName][sym];
            if (addr && !addr.isNull()) {
                attachHandshakeTracker(addr);
                devlog(`[LibreSSL] Handshake tracker installed on ${sym}`);
            }
        }
    }

    private getThreadClientRandom(): string | null {
        return resolveLibreSslClientRandom(this.SSL_get_client_random_fn, currentHandshakeSsl());
    }

    private extractMasterKey(ssl: NativePointer): string | null {
        if (!this.SSL_get_session || !this.SSL_SESSION_get_master_key_fn) return null;
        const session = this.SSL_get_session(ssl) as NativePointer;
        if (session.isNull()) return null;
        const mkLen = this.SSL_SESSION_get_master_key_fn(session, _masterKeyBuf, 48);
        if (mkLen > 0) {
            return readHexFromPointer(_masterKeyBuf, mkLen);
        }
        return null;
    }

    async execute_hooks() {
        OpenSSL_BoringSSL.initializePipeline(
            isPatternReplaced() ? patterns : undefined,
            experimental,
        );
        await this.resolveWithPipelineAsync([
            "SSL_read", "SSL_write", "SSL_get_fd",
            "SSL_get_session", "SSL_SESSION_get_id",
            "SSL_new", "SSL_CTX_set_keylog_callback",
            "SSL_get_client_random", "SSL_SESSION_get_master_key",
            "SSL_do_handshake", "SSL_connect", "SSL_accept",
        ]);

        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        this.install_tls_keys_callback_hook();
    }
}

export function libressl_execute(moduleName: string, is_base_hook: boolean) {
    executeSSLLibrary(LibreSSL_MacOS, moduleName, socket_library, is_base_hook);
}
