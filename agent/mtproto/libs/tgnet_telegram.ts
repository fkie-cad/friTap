/**
 * Telegram tgnet (MTProto) hook class for Android.
 *
 * Mirrors the shape of agent/ssh/libs/ssh_openssh.ts: a small class that owns
 * a module name + resolved-address map and exposes install_hooks().
 *
 * STATUS: cloud-chat auth-key keylog hook is live (ABI verified on
 * org.telegram.messenger 12.8.1 / libtmessages.49.so). It resolves
 * Datacenter::getAuthKey by symbol, dumps (auth_key_id, auth_key, dc_id,
 * key_type), and degrades gracefully when nothing resolves. The plaintext hook
 * remains a documented Phase-0 placeholder. Neither path may crash the target.
 *
 * Targets `libtmessages.tmessages.so` (Telegram's native tgnet stack).
 *
 * Python side (friTap/message_router.py):
 *   - auth keys  -> contentType "mtproto_key"  (fields: auth_key_id, auth_key, dc_id, key_type)
 *   - plaintext  -> contentType "datalog"      (sendDatalog sets contentType itself)
 */

import { log, devlog } from "../../util/log.js";
import { sendKeyMaterial, sendDatalog } from "../../shared/shared_structures.js";
import { toHexString } from "../../shared/shared_functions.js";
import { pcap_enabled } from "../../fritap_agent.js";
import {
    SYM_DATACENTER_GET_AUTH_KEY_CANDIDATES,
    SYM_DATACENTER_GET_DATACENTER_ID,
    SYM_DATACENTER_DECRYPT_SERVER_RESPONSE_CANDIDATES,
    SYM_DATACENTER_AES_IGE_ENCRYPTION_CANDIDATES,
    GET_AUTH_KEY_NAME_FRAGMENTS,
    DECRYPT_SERVER_RESPONSE_NAME_FRAGMENTS,
    AES_IGE_ENCRYPTION_NAME_FRAGMENTS,
    MTPROTO_AUTH_KEY_LEN,
    MTPROTO_AUTH_KEY_ID_LEN,
    BYTEARRAY_BYTES_OFFSET,
    BYTEARRAY_LENGTH_OFFSET,
    getTgnetPatternsForArch,
} from "../definitions/tgnet.js";

/** Cap a single emitted plaintext record (defensive against bogus lengths). */
const MTPROTO_MAX_PLAINTEXT_BYTES = 1 << 20; // 1 MiB

export class TGNET_Telegram {
    module_name: string;
    addresses: { [functionName: string]: NativePointer };

    /**
     * Cached NativeFunction wrapper for Datacenter::getDatacenterId, resolved
     * lazily on first onLeave. `undefined` = not resolved yet, `null` = resolved
     * to "unavailable" (symbol missing) so we stop retrying.
     */
    private _getDatacenterIdFn: NativeFunction<number, [NativePointer]> | null | undefined = undefined;

    /**
     * Dedup set keyed by `auth_key_hex|key_type` (the key BYTES are the stable
     * identity). getAuthKey is called very frequently; keying on the bytes emits
     * each distinct key exactly once, independent of whether the id OUT-param was
     * populated on a given call.
     */
    private _emittedKeys: Set<string> = new Set<string>();

    constructor(moduleName: string) {
        this.module_name = moduleName;
        this.addresses = {};
    }

    /**
     * Entry point: install both the key-extraction and plaintext hooks.
     * Each installer is independently guarded so a failure in one never
     * blocks the other.
     */
    install_hooks(): void {
        log(`[TGNET_Telegram] Installing MTProto hooks on ${this.module_name}`);
        const keylog_ok = this.install_keylog_hook();
        const plaintext_ok = this.install_plaintext_hook();
        if (!keylog_ok && !plaintext_ok) {
            log(`[TGNET_Telegram] No MTProto hooks installed — Phase 0 reverse engineering required for ${this.module_name}`);
        }
    }

    /**
     * Resolve + hook Datacenter::getAuthKey() to dump (auth_key_id, auth_key, dc_id).
     *
     * Resolution order:
     *   1. Module.findExportByName for each known mangled candidate.
     *   2. enumerateExports scan matching /datacenter/i AND /getauthkey/i.
     *   3. (still null) -> warn that a Phase-0 byte-pattern scan is required.
     *
     * Returns true only when a function was resolved AND a hook attached.
     */
    install_keylog_hook(): boolean {
        try {
            const target = this._resolveGetAuthKey();
            if (target === null) {
                // Phase-0 byte patterns live in definitions/tgnet.ts; the field
                // is currently empty for every arch, so we cannot scan yet.
                const patterns = getTgnetPatternsForArch();
                if (patterns.getAuthKey && patterns.getAuthKey.length > 0) {
                    // TODO(Phase 0): when a pattern exists, scan r-x ranges of the
                    // module here (Memory.scanSync over executable ranges only —
                    // whole-module scanSync access-violates on large libs) and
                    // attach to the match. Left unimplemented until a real pattern
                    // is committed.
                    devlog(`[TGNET_Telegram] getAuthKey byte-pattern present but pattern-scan path not yet implemented (Phase 0)`);
                }
                console.warn(
                    `[TGNET_Telegram] Could not resolve Datacenter::getAuthKey in ${this.module_name}. ` +
                    `Phase 0 byte-pattern scan needed — fill TGNET_PATTERNS_<arch>.getAuthKey in agent/mtproto/definitions/tgnet.ts.`
                );
                log(`[TGNET_Telegram] keylog hook NOT installed (Phase 0 byte-pattern needed)`);
                return false;
            }

            this.addresses["Datacenter::getAuthKey"] = target;
            this._attachGetAuthKey(target);
            log(`[TGNET_Telegram] Hooked Datacenter::getAuthKey at ${target}`);
            return true;
        } catch (e) {
            devlog(`[TGNET_Telegram] install_keylog_hook error: ${e}`);
            return false;
        }
    }

    /**
     * Resolve Datacenter::getAuthKey via exports (mangled candidates first,
     * then a fuzzy enumerateExports scan). Returns null if unresolved.
     */
    private _resolveGetAuthKey(): NativePointer | null {
        // Frida >=17 removed the static Module.findExportByName/enumerateExports;
        // resolve against the live module instance instead (matches the rest of
        // the agent, e.g. agent/util/go_runtime_parser.ts).
        const mod = Process.findModuleByName(this.module_name);
        if (mod === null) {
            devlog(`[TGNET_Telegram] module ${this.module_name} not found for export resolution`);
            return null;
        }

        // 1. Known mangled names.
        for (const sym of SYM_DATACENTER_GET_AUTH_KEY_CANDIDATES) {
            const addr = mod.findExportByName(sym);
            if (addr) {
                devlog(`[TGNET_Telegram] Resolved getAuthKey via export ${sym} at ${addr}`);
                return addr;
            }
        }

        // 2. Fuzzy scan of exports for a datacenter/getauthkey symbol.
        try {
            const exports = mod.enumerateExports() as Array<{ name: string; address: NativePointer }>;
            for (const exp of exports) {
                if (GET_AUTH_KEY_NAME_FRAGMENTS.class.test(exp.name) &&
                    GET_AUTH_KEY_NAME_FRAGMENTS.method.test(exp.name)) {
                    devlog(`[TGNET_Telegram] Resolved getAuthKey via export scan: ${exp.name} at ${exp.address}`);
                    return exp.address;
                }
            }
        } catch (e) {
            devlog(`[TGNET_Telegram] enumerateExports failed: ${e}`);
        }

        return null;
    }

    /**
     * Attach to a resolved getAuthKey using the ABI verified on 12.8.1:
     *
     *   ByteArray* Datacenter::getAuthKey(ConnectionType connectionType,
     *                                     bool perm,
     *                                     int64_t* authKeyId,
     *                                     int allowPendingKey)
     *
     * As a non-static C++ method the hooked args are:
     *   args[0] = this (Datacenter*)
     *   args[1] = ConnectionType (enum, by value)
     *   args[2] = bool perm        (true -> "perm", false -> "temp")
     *   args[3] = int64_t* authKeyId (OUT param, filled by the call)
     *   args[4] = int allowPendingKey
     *
     * The return value is a `ByteArray*` { uint8_t* bytes@0; uint32_t length@8 }.
     * The 256-byte auth_key is at `*(retval + BYTEARRAY_BYTES_OFFSET)`.
     *
     * Fully guarded with try/catch + devlog — this must never crash the target.
     */
    private _attachGetAuthKey(addr: NativePointer): void {
        const self = this;
        Interceptor.attach(addr, {
            onEnter: function (args) {
                // args[0] = Datacenter* (this) — used to resolve dc_id on leave.
                this.datacenterPtr = args[0];
                // args[3] = int64_t* auth_key_id OUT param (populated by the call).
                this.authKeyIdOutPtr = args[3];
                // args[2] = bool perm. true -> permanent key, false -> temp (PFS).
                this.perm = !args[2].isNull() && args[2].toInt32() !== 0;
            },
            onLeave: function (retval) {
                try {
                    // retval is a ByteArray*; bail out cleanly on null.
                    if (retval.isNull()) {
                        return;
                    }

                    const bytesPtr = retval.add(BYTEARRAY_BYTES_OFFSET).readPointer();
                    const len = retval.add(BYTEARRAY_LENGTH_OFFSET).readU32();
                    if (bytesPtr.isNull() || len < MTPROTO_AUTH_KEY_LEN) {
                        return;
                    }

                    const authKeyBytes = bytesPtr.readByteArray(MTPROTO_AUTH_KEY_LEN);
                    if (authKeyBytes === null) {
                        return;
                    }
                    const authKeyHex = toHexString(authKeyBytes);

                    // auth_key_id is the low 64 bits of SHA1(auth_key). The OUT
                    // param is the cheapest source, but Datacenter::getAuthKey is
                    // frequently called with a null id pointer, so fall back to
                    // computing it here (sha1(auth_key)[-8:]) — keeping the keylog
                    // self-contained instead of relying on a Python-side derive.
                    let authKeyIdHex = "";
                    try {
                        if (this.authKeyIdOutPtr && !this.authKeyIdOutPtr.isNull()) {
                            const idBytes = this.authKeyIdOutPtr.readByteArray(MTPROTO_AUTH_KEY_ID_LEN);
                            if (idBytes !== null) {
                                authKeyIdHex = toHexString(idBytes);
                            }
                        }
                    } catch (_e) {
                        // out-param not populated — fall through to the sha1 derive.
                    }
                    if (authKeyIdHex.length !== MTPROTO_AUTH_KEY_ID_LEN * 2) {
                        authKeyIdHex = self._computeAuthKeyId(authKeyBytes);
                    }

                    const keyType = this.perm ? "perm" : "temp";

                    // dc_id via the verified Datacenter::getDatacenterId getter.
                    let dcId = 0;
                    try {
                        const getDcId = self._resolveGetDatacenterId();
                        if (getDcId !== null && this.datacenterPtr && !this.datacenterPtr.isNull()) {
                            dcId = getDcId(this.datacenterPtr) as number;
                        }
                    } catch (_e) {
                        dcId = 0;
                    }

                    // Dedup: getAuthKey is called very frequently. Key on the key
                    // BYTES (the true identity) + type so a key is emitted exactly
                    // once, regardless of whether the id OUT-param was populated on
                    // this particular call (prevents an empty-id then with-id
                    // double-emit of the same key).
                    const dedupKey = authKeyHex + "|" + keyType;
                    if (self._emittedKeys.has(dedupKey)) {
                        return;
                    }
                    self._emittedKeys.add(dedupKey);

                    sendKeyMaterial({
                        contentType: "mtproto_key",
                        auth_key_id: authKeyIdHex,   // hex (16 chars when known)
                        auth_key: authKeyHex,         // hex (512 chars)
                        dc_id: dcId,
                        key_type: keyType,
                    });
                    devlog(`[TGNET_Telegram] Emitted mtproto_key (dc_id=${dcId}, id=${authKeyIdHex}, type=${keyType})`);
                } catch (e) {
                    devlog(`[TGNET_Telegram] getAuthKey onLeave error: ${e}`);
                }
            },
        });
    }

    /**
     * Compute the MTProto auth_key_id = low 64 bits of SHA1(auth_key), i.e. the
     * LAST 8 bytes of the SHA1 digest, as 16 lowercase hex chars. Used when
     * Datacenter::getAuthKey leaves the id OUT-param null. Uses frida-gum's
     * Checksum (no native symbol needed). Returns "" on any failure so the
     * Python router's identical sha1 derive remains the safety net.
     */
    private _computeAuthKeyId(authKeyBytes: ArrayBuffer): string {
        try {
            const ck = new Checksum("sha1");
            ck.update(authKeyBytes);
            const digestHex = ck.getString();   // 40 lowercase hex chars
            return digestHex.slice(-MTPROTO_AUTH_KEY_ID_LEN * 2);
        } catch (_e) {
            return "";
        }
    }

    /**
     * Lazily resolve + cache `Datacenter::getDatacenterId` as a NativeFunction
     * callable on a Datacenter* `this`. Returns null (and caches null) when the
     * symbol is unresolved, so dc_id falls back to 0.
     */
    private _resolveGetDatacenterId(): NativeFunction<number, [NativePointer]> | null {
        if (this._getDatacenterIdFn !== undefined) {
            return this._getDatacenterIdFn;
        }
        try {
            const mod = Process.findModuleByName(this.module_name);
            const addr = mod ? mod.findExportByName(SYM_DATACENTER_GET_DATACENTER_ID) : null;
            if (addr) {
                this._getDatacenterIdFn = new NativeFunction(addr, "int", ["pointer"]);
                devlog(`[TGNET_Telegram] Resolved Datacenter::getDatacenterId at ${addr}`);
            } else {
                this._getDatacenterIdFn = null;
                devlog(`[TGNET_Telegram] Datacenter::getDatacenterId not found — dc_id stays 0`);
            }
        } catch (e) {
            this._getDatacenterIdFn = null;
            devlog(`[TGNET_Telegram] _resolveGetDatacenterId error: ${e}`);
        }
        return this._getDatacenterIdFn;
    }

    /**
     * Hook the tgnet plaintext buffers:
     *   - inbound: the buffer right AFTER AES-IGE decrypt of an incoming MTProto
     *     message (function name "mtproto_decrypt", direction "read").
     *   - outbound: the buffer right BEFORE AES-IGE encrypt of an outgoing
     *     message (function name "mtproto_decrypt", direction "write").
     *
     * Both emit via sendDatalog(..., plaintextBytes) so the Python datalog
     * pipeline records decrypted MTProto bytes.
     *
     * STRUCTURED STUB: the exact functions/offsets are unknown. This logs a
     * clear Phase-0 TODO and returns false. The intended call shape is kept
     * below in comments so the Phase-0 implementer only fills the offsets.
     */
    install_plaintext_hook(): boolean {
        // Under full-capture (-f) the raw pcap is taken by the external tcpdump
        // and the in-agent plaintext datalog is discarded downstream, so
        // pcap_enabled is false. Skip the install entirely rather than attaching
        // inert callbacks to the HOT AES-IGE encrypt/decrypt paths (one call per
        // record) — and don't print a misleading "installed" line. The
        // key-extraction hook is independent and still installs.
        if (!pcap_enabled) {
            log(`[TGNET_Telegram] plaintext hooks skipped (full-capture/key-only mode — offline-decrypt the pcap with the keylog)`);
            return false;
        }
        // Both MTProto directions funnel through Datacenter:
        //   - inbound:  Datacenter::decryptServerResponse decrypts the message
        //               body IN PLACE -> read `data` onLeave (direction "read").
        //   - outbound: Datacenter::aesIgeEncryption(..., encrypt=true, ...) is
        //               the in-place AES-IGE primitive -> read `src` onEnter
        //               while it still holds plaintext (direction "write").
        // Emission is gated on pcap_enabled inside each callback (key-only mode
        // ships no plaintext) and on the per-call shutdown gate in sendDatalog.
        let inbound_ok = false;
        let outbound_ok = false;

        try {
            const inAddr = this._resolveExport(
                SYM_DATACENTER_DECRYPT_SERVER_RESPONSE_CANDIDATES,
                DECRYPT_SERVER_RESPONSE_NAME_FRAGMENTS,
                "Datacenter::decryptServerResponse",
            );
            if (inAddr !== null) {
                this.addresses["Datacenter::decryptServerResponse"] = inAddr;
                this._attachDecryptServerResponse(inAddr);
                log(`[TGNET_Telegram] Hooked Datacenter::decryptServerResponse (inbound plaintext) at ${inAddr}`);
                inbound_ok = true;
            }
        } catch (e) {
            devlog(`[TGNET_Telegram] inbound plaintext hook error: ${e}`);
        }

        try {
            const outAddr = this._resolveExport(
                SYM_DATACENTER_AES_IGE_ENCRYPTION_CANDIDATES,
                AES_IGE_ENCRYPTION_NAME_FRAGMENTS,
                "Datacenter::aesIgeEncryption",
            );
            if (outAddr !== null) {
                this.addresses["Datacenter::aesIgeEncryption"] = outAddr;
                this._attachAesIgeEncryption(outAddr);
                log(`[TGNET_Telegram] Hooked Datacenter::aesIgeEncryption (outbound plaintext) at ${outAddr}`);
                outbound_ok = true;
            }
        } catch (e) {
            devlog(`[TGNET_Telegram] outbound plaintext hook error: ${e}`);
        }

        if (!inbound_ok && !outbound_ok) {
            // Symbol resolution failed (e.g. a stripped build). The per-arch
            // byte-pattern fallback in definitions/tgnet.ts is still empty.
            const patterns = getTgnetPatternsForArch();
            if (!patterns.decryptInbound && !patterns.encryptOutbound) {
                console.warn(
                    `[TGNET_Telegram] MTProto plaintext hook could not resolve the ` +
                    `decrypt/encrypt boundary in ${this.module_name} by symbol, and no ` +
                    `byte-pattern fallback is committed. Fill ` +
                    `TGNET_PATTERNS_<arch>.decryptInbound / .encryptOutbound in ` +
                    `agent/mtproto/definitions/tgnet.ts for stripped builds.`
                );
            }
            log(`[TGNET_Telegram] plaintext hook NOT installed (decrypt/encrypt boundary unresolved)`);
            return false;
        }

        log(`[TGNET_Telegram] plaintext hook installed (inbound=${inbound_ok}, outbound=${outbound_ok})`);
        return true;
    }

    /**
     * Generic export resolver: try each mangled candidate via the live module's
     * findExportByName, then fall back to a fuzzy enumerateExports scan matching
     * both name fragments. Mirrors _resolveGetAuthKey. Returns null if nothing
     * resolves (caller logs / falls back).
     */
    private _resolveExport(
        candidates: string[],
        fragments: { class: RegExp; method: RegExp },
        label: string,
    ): NativePointer | null {
        const mod = Process.findModuleByName(this.module_name);
        if (mod === null) {
            devlog(`[TGNET_Telegram] module ${this.module_name} not found resolving ${label}`);
            return null;
        }
        for (const sym of candidates) {
            const addr = mod.findExportByName(sym);
            if (addr) {
                devlog(`[TGNET_Telegram] Resolved ${label} via export ${sym} at ${addr}`);
                return addr;
            }
        }
        try {
            const exports = mod.enumerateExports() as Array<{ name: string; address: NativePointer }>;
            for (const exp of exports) {
                if (fragments.class.test(exp.name) && fragments.method.test(exp.name)) {
                    devlog(`[TGNET_Telegram] Resolved ${label} via export scan: ${exp.name} at ${exp.address}`);
                    return exp.address;
                }
            }
        } catch (e) {
            devlog(`[TGNET_Telegram] enumerateExports failed resolving ${label}: ${e}`);
        }
        devlog(`[TGNET_Telegram] could not resolve ${label} in ${this.module_name}`);
        return null;
    }

    /**
     * Hook Datacenter::decryptServerResponse — the inbound (server->client)
     * boundary. `data` (args[3]) is AES-IGE decrypted in place, so onLeave it
     * holds the decrypted MTProto message. Only emit on a successful (truthy)
     * return. Fully guarded; must never crash the target.
     */
    private _attachDecryptServerResponse(addr: NativePointer): void {
        const self = this;
        Interceptor.attach(addr, {
            onEnter: function (args) {
                this.dataPtr = args[3];
                this.dataLen = args[4].toInt32();
            },
            onLeave: function (retval) {
                try {
                    if (!pcap_enabled) return;
                    // bool return: false => decrypt failed, buffer is unreliable.
                    if (retval.isNull() || retval.toInt32() === 0) return;
                    self._emitPlaintext(this.dataPtr, this.dataLen, "mtproto_decrypt", "read");
                } catch (e) {
                    devlog(`[TGNET_Telegram] decryptServerResponse onLeave error: ${e}`);
                }
            },
        });
    }

    /**
     * Hook Datacenter::aesIgeEncryption — the shared in-place AES-IGE primitive.
     * This is a STATIC method (no implicit `this`), RE-confirmed at runtime:
     *
     *   static void aesIgeEncryption(uint8_t* buffer, uint8_t* key, uint8_t* iv,
     *                                bool encrypt, bool changeIv, uint32_t length)
     *
     * so the hooked args are:
     *   args[0]=buffer, args[1]=key, args[2]=iv,
     *   args[3]=encrypt, args[4]=changeIv, args[5]=length.
     *
     * When `encrypt` is true the call is encrypting an outgoing message, so
     * `buffer` still holds plaintext at onEnter. The decrypt direction
     * (encrypt=false) is ignored here; inbound is captured by the dedicated
     * decryptServerResponse hook. Fully guarded.
     */
    private _attachAesIgeEncryption(addr: NativePointer): void {
        const self = this;
        Interceptor.attach(addr, {
            onEnter: function (args) {
                try {
                    if (!pcap_enabled) return;
                    const encrypt = !args[3].isNull() && args[3].toInt32() !== 0;
                    if (!encrypt) return; // decrypt path handled elsewhere
                    self._emitPlaintext(args[0], args[5].toInt32(), "mtproto_encrypt", "write");
                } catch (e) {
                    devlog(`[TGNET_Telegram] aesIgeEncryption onEnter error: ${e}`);
                }
            },
        });
    }

    /**
     * Read `len` plaintext bytes from `buf` and ship them via sendDatalog so the
     * Python datalog->pcap pipeline records the decrypted MTProto message. The
     * socket 5-tuple is not available at this boundary, so addresses are left as
     * placeholders (pcap.py normalizes them to 0.0.0.0:0); the offline tcpdump
     * path supplies real 5-tuples when needed. `function` drives the read/write
     * direction on the Python side (membership in constants.SSL_READ).
     */
    private _emitPlaintext(
        buf: NativePointer,
        len: number,
        fn: string,
        direction: "read" | "write",
    ): void {
        if (buf === null || buf.isNull()) return;
        if (!Number.isFinite(len) || len <= 0 || len > MTPROTO_MAX_PLAINTEXT_BYTES) return;
        const bytes = buf.readByteArray(len);
        if (bytes === null) return;
        sendDatalog(
            { contentType: "datalog", function: fn, direction: direction },
            bytes,
        );
        devlog(`[TGNET_Telegram] emitted ${fn} plaintext (${len} bytes, ${direction})`);
    }
}
