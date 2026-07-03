import { readAddresses, getPortsAndAddresses, resolveOffsets } from "../../shared/shared_functions.js";
import { sendKeylog, sendDatalog } from "../../shared/shared_structures.js";
import { log, devlog, devlog_error } from "../../util/log.js";
import { toHexString, toSpacedHexUpper } from "../../util/hex.js";
import { normalizeArchKey } from "../../util/process_infos.js";
import { isFunctionPrologueWord } from "../../shared/arm64.js";
import { enable_default_fd, pcap_enabled } from "../../fritap_agent.js";
import { resolveWithPipelineAsync } from "../../shared/pipeline_utils.js";

export class GnuTLS {

    // global variables
    library_method_mapping: { [key: string]: Array<string> } = {};
    addresses: { [libraryName: string]: { [functionName: string]: NativePointer } };
    module_name: string;
    
    static gnutls_transport_get_int : any;
    static gnutls_session_get_id: any;
    static gnutls_session_get_random: any;
    static gnutls_session_set_keylog_function: any;

    
   

    constructor(public moduleName:string, public socket_library:String,public passed_library_method_mapping?: { [key: string]: Array<string> }){
        if(typeof passed_library_method_mapping !== 'undefined'){
            this.library_method_mapping = passed_library_method_mapping;
        }else{
            this.library_method_mapping[`*${moduleName}*`] = ["gnutls_record_recv", "gnutls_record_send", "gnutls_session_set_keylog_function", "gnutls_transport_get_int", "gnutls_session_get_id", "gnutls_init", "gnutls_handshake", "gnutls_session_get_keylog_function", "gnutls_session_get_random"]
            this.library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"]
        }
        
        this.addresses = readAddresses(moduleName,this.library_method_mapping);
        this.module_name = moduleName;


        resolveOffsets(this.addresses, this.moduleName, socket_library, "gnutls");

        resolveWithPipelineAsync(this.addresses, this.moduleName, "gnutls", [
            "gnutls_record_recv", "gnutls_record_send",
            "gnutls_session_set_keylog_function", "gnutls_transport_get_int",
            "gnutls_session_get_id", "gnutls_init", "gnutls_handshake",
            "gnutls_session_get_random"
        ]).catch(() => {}); // best-effort pattern gap-fill (these libs ship no byte patterns)

        GnuTLS.gnutls_transport_get_int = new NativeFunction(this.addresses[this.moduleName]["gnutls_transport_get_int"], "int", ["pointer"])
        GnuTLS.gnutls_session_get_id = new NativeFunction(this.addresses[this.moduleName]["gnutls_session_get_id"], "int", ["pointer", "pointer", "pointer"])
        GnuTLS.gnutls_session_set_keylog_function = new NativeFunction(this.addresses[this.moduleName]["gnutls_session_set_keylog_function"], "void", ["pointer", "pointer"])
        GnuTLS.gnutls_session_get_random = new NativeFunction(this.addresses[this.moduleName]["gnutls_session_get_random"], "pointer", ["pointer", "pointer", "pointer"])

    }

    // Dynamic pattern-discovery bookkeeping. First time our keylog_callback
    // fires, an Interceptor.attach on the callback's own address (see
    // attachDynamicDiscovery below) uses the caller's returnAddress to locate
    // `_gnutls_call_keylog_func` — no hardcoded byte pattern per gnutls build.
    //
    // The address is logged and emitted as a `--patterns` JSON override for
    // reuse (persist across runs, share between machines running the same
    // libgnutls). We deliberately do NOT install a second Interceptor at the
    // discovered address: gnutls always dispatches through our injected
    // callback for every session it created via gnutls_init, so a direct
    // hook there would double-emit every key. The pattern remains valuable
    // for `wine_keylog_pattern_hook.ts` (offline reuse / attach-after-init
    // scenarios that skipped the gnutls_init hook).
    static _gnutls_call_keylog_func_addr: NativePointer | null = null;
    static _pattern_hook_installed: boolean = false;
    static _discovery_listener: InvocationListener | null = null;

    // Scratch buffers reused across every keylog_callback firing. Allocated
    // once at class load (gnutls_session_get_random writes an in/out
    // gnutls_datum_t: { pointer, uint }). Keeping them static avoids two
    // Memory.alloc calls per emitted TLS secret.
    static _cr_datum = Memory.alloc(Process.pointerSize + 4);
    static _sr_datum = Memory.alloc(Process.pointerSize + 4);

    // NativeCallback for gnutls_session_set_keylog_function.
    // Receives (session, label, gnutls_datum_t* secret) — gnutls_datum_t is
    // { pointer data, uint size }. NativeCallbacks don't get a usable
    // this.context; attachDynamicDiscovery() wraps this address in an
    // Interceptor to get real InvocationContext for backtrace.
    static keylog_callback = new NativeCallback(function (session: NativePointer, label: NativePointer, secret: NativePointer) {
        const secret_len = secret.add(Process.pointerSize).readUInt();
        const secretBytes = secret.readPointer().readByteArray(secret_len);
        const secret_str = secretBytes ? toHexString(secretBytes).toUpperCase() : "";

        try {
            GnuTLS.gnutls_session_get_random(session, GnuTLS._cr_datum, GnuTLS._sr_datum);
        } catch (e) {
            devlog_error(`[gnutls] session_get_random failed: ${e}`);
        }
        const crBytes = GnuTLS._cr_datum.readPointer().readByteArray(32);
        const client_random_str = crBytes ? toHexString(crBytes).toUpperCase() : "";

        sendKeylog(label.readCString() + " " + client_random_str + " " + secret_str);
        return 0;
    }, "int", ["pointer", "pointer", "pointer"])

    /**
     * Walk backward from a return address INSIDE `_gnutls_call_keylog_func`
     * to that function's entry, using architecture-specific prologue
     * heuristics. Returns null if no plausible prologue is found within a
     * 512-byte / 128-instruction window.
     *
     * AArch64 uses the shared prologue predicate `isFunctionPrologueWord`
     * from `agent/shared/arm64.ts` — the canonical superset of every
     * hand-rolled AArch64 prologue matcher across the codebase.
     */
    static _findGnutlsFuncStart(retAddr: NativePointer): NativePointer | null {
        const arch = Process.arch;
        if (arch === "x64" || arch === "ia32") return GnuTLS._findX86FuncStart(retAddr);
        if (arch === "arm64") return GnuTLS._findArm64FuncStart(retAddr);
        if (arch === "arm") return GnuTLS._findArmFuncStart(retAddr);
        devlog(`[gnutls dyn] no prologue heuristic for arch=${arch}`);
        return null;
    }

    /**
     * Match `endbr64` (Intel CET, 0xF3 0F 1E FA) at addr. Returns true on
     * clean read + match. Used to prefer the CET landing pad over a later
     * `push rbp ; mov rsp, rbp` when both appear back-to-back (Ubuntu Noble
     * libgnutls).
     */
    static _isEndbr64(addr: NativePointer): boolean {
        try {
            return addr.readU8() === 0xF3
                && addr.add(1).readU8() === 0x0F
                && addr.add(2).readU8() === 0x1E
                && addr.add(3).readU8() === 0xFA;
        } catch (_e) { return false; }
    }

    /**
     * x86-64 / x86 prologue detection. Byte-granular backward walk because
     * x86 is variable-length. Handles `endbr64` and the standard
     * `push rbp ; mov rsp, rbp` (0x55 48 89 E5); if the frame-pointer save
     * is preceded by `endbr64`, backs up 4 bytes so the captured pattern
     * matches the on-disk binary byte-for-byte.
     */
    static _findX86FuncStart(retAddr: NativePointer): NativePointer | null {
        for (let off = 0; off <= 512; off++) {
            const probe = retAddr.sub(off);
            if (GnuTLS._isEndbr64(probe)) return probe;
            let b0: number, b1: number, b2: number, b3: number;
            try {
                b0 = probe.readU8();
                b1 = probe.add(1).readU8();
                b2 = probe.add(2).readU8();
                b3 = probe.add(3).readU8();
            } catch (_e) { return null; }
            // push rbp ; mov rsp, rbp — prefer a preceding endbr64 if present.
            if (b0 === 0x55 && b1 === 0x48 && b2 === 0x89 && b3 === 0xE5) {
                const p2 = probe.sub(4);
                return GnuTLS._isEndbr64(p2) ? p2 : probe;
            }
        }
        return null;
    }

    /**
     * AArch64 prologue detection. 4-byte-aligned backward walk over 128
     * instructions; delegates to `isFunctionPrologueWord()` in
     * `agent/shared/arm64.ts`, which is the canonical union of every
     * prologue encoding used in this codebase (paciasp/pacibsp, bti c|j|jc,
     * STP x29,x30 with signed offset, STP-pre-index broad form for any
     * callee-saved pair, SUB sp,sp,#imm).
     *
     * ARMv8.3+ pointer-auth codes on the return address are stripped via
     * Frida's `NativePointer.strip()`. On a runtime without .strip(), a
     * defensive 48-bit VA mask is applied.
     */
    static _findArm64FuncStart(retAddrRaw: NativePointer): NativePointer | null {
        // Strip PAC; fall back to a 48-bit VA mask on runtimes without strip().
        let retAddr: NativePointer;
        try {
            retAddr = (retAddrRaw as any).strip ? (retAddrRaw as any).strip() : retAddrRaw;
        } catch (_e) {
            try { retAddr = retAddrRaw.and(ptr("0x0000FFFFFFFFFFFF")); }
            catch (_e2) { retAddr = retAddrRaw; }
        }
        // Align down to a 4-byte boundary (defensive).
        retAddr = retAddr.and(ptr("0xFFFFFFFFFFFFFFFC"));

        for (let step = 0; step <= 128; step++) {
            const probe = retAddr.sub(step * 4);
            let insn: number;
            try { insn = probe.readU32(); }
            catch (_e) { return null; }
            if (isFunctionPrologueWord(insn)) return probe;
        }
        return null;
    }

    /**
     * AArch32 (ARM/Thumb) prologue detection — best-effort.
     * Matches `push {..., lr}` in ARM state (opcode E92D...) and
     * `push.w {..., lr}` in Thumb-2, both checking the lr register-list bit.
     */
    static _findArmFuncStart(retAddr: NativePointer): NativePointer | null {
        for (let step = 0; step <= 256; step++) {
            const probe = retAddr.sub(step * 2);
            let b0: number, b1: number, b2: number, b3: number;
            try {
                b0 = probe.readU8();
                b1 = probe.add(1).readU8();
                b2 = probe.add(2).readU8();
                b3 = probe.add(3).readU8();
            } catch (_e) { return null; }
            // ARM state: ?? ?? 2D E9 with reg-list bit 14 (lr) set.
            if (b2 === 0x2D && b3 === 0xE9 && (b1 & 0x40) !== 0) return probe;
            // Thumb-2 push.w: 2D E9 ?? ?? with lr bit set.
            if (b0 === 0x2D && b1 === 0xE9 && (b3 & 0x40) !== 0) return probe;
        }
        return null;
    }

    /**
     * Install a one-shot Interceptor.attach on the keylog_callback address
     * to run dynamic pattern discovery on the first firing.
     *
     * A bare `NativeCallback` body has no usable `this.context`. Wrapping
     * the callback address with `Interceptor.attach` gives us a real
     * InvocationContext with valid `returnAddress` — that address points
     * INSIDE `_gnutls_call_keylog_func` right after the indirect call to
     * our callback. Walk backward from there with arch-specific prologue
     * heuristics to find the function entry, then detach the wrapper so
     * subsequent callback firings pay zero extra overhead.
     */
    static attachDynamicDiscovery() {
        if (GnuTLS._pattern_hook_installed) return;
        GnuTLS._pattern_hook_installed = true;
        try {
            GnuTLS._discovery_listener = Interceptor.attach(GnuTLS.keylog_callback as NativePointer, {
                onEnter(this: any) {
                    if (GnuTLS._gnutls_call_keylog_func_addr !== null) return;
                    const retAddr: NativePointer | undefined = this.returnAddress;
                    if (!retAddr) return;
                    try {
                        const funcStart = GnuTLS._findGnutlsFuncStart(retAddr);
                        GnuTLS._recordDiscovery(funcStart ?? retAddr, funcStart != null, retAddr);
                        // Detach ourselves — the discovery is a one-shot task
                        // and every subsequent secret should not pay the
                        // Interceptor context-capture cost.
                        if (GnuTLS._discovery_listener) {
                            try { GnuTLS._discovery_listener.detach(); } catch (_e) { /* ignore */ }
                            GnuTLS._discovery_listener = null;
                        }
                    } catch (e) {
                        devlog(`[gnutls dyn] discovery onEnter threw: ${e}`);
                    }
                },
            });
        } catch (e) {
            devlog(`[gnutls dyn] attach(keylog_callback) failed: ${e}`);
        }
    }

    /**
     * Emit the discovered address, byte pattern and a copy-paste-ready
     * `--patterns` JSON override. Kept out of the hot Interceptor onEnter
     * so the callback code path stays simple.
     */
    static _recordDiscovery(funcStart: NativePointer, prologueFound: boolean, retAddr: NativePointer) {
        GnuTLS._gnutls_call_keylog_func_addr = funcStart;
        if (!prologueFound) {
            devlog(`[gnutls dyn] returnAddress=${retAddr} — no prologue in scan window; recording raw address anyway`);
            return;
        }
        const sample = funcStart.readByteArray(32);
        const hex = sample ? toSpacedHexUpper(sample) : "";
        const archKey = normalizeArchKey(Process.arch);
        const sigId = archKey === "x64" ? "gnutls_keylog_sysv"
            : archKey === "arm64" ? "gnutls_keylog_aarch64"
            : `gnutls_keylog_${archKey}`;
        log(`[gnutls dyn] resolved _gnutls_call_keylog_func @ ${funcStart}`);
        log(`[gnutls dyn] version-specific pattern (32 bytes): ${hex}`);
        log(`[gnutls dyn] --patterns override:  { "modules": { "gnutls": { "wine": { "${archKey}": { "${sigId}": { "primary": "${hex}" } } } } } }`);
        devlog(`[gnutls dyn] callback returnAddress inside func = ${retAddr}, distance from prologue = ${retAddr.sub(funcStart).toString()}`);
    }

    /**
       * Get the session_id of SSL object and return it as a hex string.
       * @param {!NativePointer} ssl A pointer to an SSL object.
       * @return {dict} A string representing the session_id of the SSL object's
       *     SSL_SESSION. For example,
       *     "59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76336".
       */
     static getSslSessionId(session: NativePointer) {
        var len_pointer = Memory.alloc(4)
        var err = GnuTLS.gnutls_session_get_id(session, NULL, len_pointer)
        if (err != 0) {
            if(enable_default_fd){
                log("using dummy SessionID: 59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76337")
                return "59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76337"
            }
            return ""
        }
        var len = len_pointer.readU32()
        var p = Memory.alloc(len)
        err = GnuTLS.gnutls_session_get_id(session, p, len_pointer)
        if (err != 0) {
            if(enable_default_fd){
                log("using dummy SessionID: 59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76337")
                return "59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76337"
            }
            return ""
        }
        var session_id = ""
        for (var i = 0; i < len; i++) {
            // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
            // it to session_id.

            session_id +=
                ("0" + p.add(i).readU8().toString(16).toUpperCase()).substr(-2)
        }
        return session_id
    }

    install_plaintext_read_hook(){
        if (!pcap_enabled) return;
        var current_module_name = this.module_name;
        var lib_addesses = this.addresses;
        Interceptor.attach(this.addresses[this.moduleName]["gnutls_record_recv"],
    {
        onEnter: function (args: any) {
            var message = getPortsAndAddresses(GnuTLS.gnutls_transport_get_int(args[0]) as number, true, lib_addesses[current_module_name], enable_default_fd)
            message["ssl_session_id"] = GnuTLS.getSslSessionId(args[0])
            message["function"] = "SSL_read"
            this.message = message
            this.buf = args[1]
        },
        onLeave: function (retval: any) {
            retval |= 0 // Cast retval to 32-bit integer.
            if (retval <= 0) {
                return
            }
            sendDatalog(this.message, this.buf.readByteArray(retval))
        }
    })

    }
    
    install_plaintext_write_hook(){
        if (!pcap_enabled) return;
        var current_module_name = this.module_name;
        var lib_addesses = this.addresses;
        Interceptor.attach(this.addresses[this.moduleName]["gnutls_record_send"],
    {
        onEnter: function (args: any) {
            var message = getPortsAndAddresses(GnuTLS.gnutls_transport_get_int(args[0]) as number, false, lib_addesses[current_module_name], enable_default_fd)
            message["ssl_session_id"] = GnuTLS.getSslSessionId(args[0])
            message["function"] = "SSL_write"
            sendDatalog(message, args[1].readByteArray(parseInt(args[2])))
        },
        onLeave: function (retval: any) {
        }
    })

    }
    
    install_tls_keys_callback_hook(){
        
    }



}