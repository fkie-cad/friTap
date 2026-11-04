
// The legacy GoTLS hooker (honours keylog_enabled), as on Android — not the tls/libs copy.
import {GoTLS, symbol_writeKeyLog, GoTlsLogger } from "../../libs/gotls.js";
import { socket_library } from "../../../../platforms/linux.js";
import { keylog_enabled } from "../../../../fritap_agent.js"
import { installGoKeylogByPattern, GO_WRITE_KEYLOG_PATTERNS } from "../../../../tls/shared/go_keylog_hook.js";
import { installBoringSSLSymbolHook, makeBoringSslDumpKeys } from "../../../../shared/boringssl_symbol_hook.js";
import { devlog, devlog_error } from "../../../../util/log.js";
import { legacyGoPlaintext } from "../../libs/gotls_native.js";


export class GoTLS_Linux extends GoTLS {
    private default_pattern: { [arch: string]: { primary: string; fallback: string, second_fallback?: string; } };

    constructor(public moduleName:string, public socket_library:String, is_base_hook: boolean){
        super(moduleName,socket_library,is_base_hook);

        /*
         * Default patterns for GoTLS hooking.
         * These patterns are used to hook the writeKeyLog function in GoTLS (its function entry). x64/arm64 Go pass the arguments in registers (go_abi.ts);
         * x86/arm32 Go pass them on the stack (ABI0), which go_abi.ts decodes from sp+4 at entry.
         * NOTE: the x86/arm patterns below are C-style prologues (push/PIC thunk), not Go
         * stack-checked entries; unverified against Go binaries.
         */

        this.default_pattern = {
            ...GO_WRITE_KEYLOG_PATTERNS, // x64 + arm64 (go_keylog_hook.ts)
            "x86": {
                primary: "55 53 57 56 83 EC 4C E8 00 00 00 00 5B 81 C3 A9 CB 13 00 8B 44 24 60", // x86 pattern
                fallback: "" // TODO: additional x86 patterns needed
            },

            "arm": {
                primary: "2D E9 F0 41 86 B0 04 46 40 6B D0 F8 30 01 00 28 53 D0", // ARM32 pattern
                fallback: "" // TODO: additional ARM32 patterns needed
            }
        };
    }

    getSoName(modulePath: string): string {
        // Match the last segment ending in ".so"
        const m = modulePath.match(/([^\/\\]+\.so)$/);
        return m ? m[1] : modulePath;
      }



    install_key_extraction_hook(){
        // Same gate as the base class (overridden here): no key hooks unless keys were requested.
        if (!keylog_enabled) return;
        var instance = this;
        let goTLSModule = Process.findModuleByName(this.module_name);
        let soName = this.module_name;
        if(goTLSModule === null){
            soName   = this.getSoName(this.module_name);
            goTLSModule = Process.findModuleByName(soName);
            if(goTLSModule === null){
                devlog("[-] GoTLS Error: Unable to find module: " + this.module_name);
                return;
            }
        }
        if (this.addresses[this.module_name][symbol_writeKeyLog] === undefined || this.addresses[this.module_name][symbol_writeKeyLog] === null )  {
            // Stripped binary: the shared Go pattern path (go_keylog_hook.ts) locates writeKeyLog's
            // entry and installs the register-based Go keylog hook (Go's ABIInternal passes the
            // arguments in registers, not in Frida's C args[]).
            const hooker = installGoKeylogByPattern(this.module_name, this.default_pattern,
                { soName, module: goTLSModule });
            return hooker;
        }else{
            devlog("[GoTLS] writeKeyLog symbol available");
            var result = instance.install_tls_keys_callback_hook();
            let hooker = new GoTlsLogger(goTLSModule,true,result);
            return hooker;

        }

    }

    /**
     * Last resort when the writeKeyLog pattern scan found nothing. No Go function is named
     * "ssl_log": the only such symbols are C BoringSSL's (bssl::ssl_log_secret, linked into the
     * module via cgo), so this hooks that C function through the shared BoringSSL symbol hook —
     * C ABI (ssl, label, secret, len) and client_random from the SSL struct. (It used to take
     * the first symbol containing "ssl_log" and read Go-style args[2..8] off a C call.)
     */
    execute_symbol_based_hooking(hooker){
        if(hooker === undefined || hooker === null){
            devlog("[-] Error: Hooker is undefined.");
            return;
        }
        if(!hooker.no_hooking_success) return;
        installBoringSSLSymbolHook(this.module_name, makeBoringSslDumpKeys(this.module_name));
    }

    execute_hooks(){
        // hooking writeKeyLog() from GoTLS
        let hooker_instance = this.install_key_extraction_hook();

        return hooker_instance;
    }

}


export function gotls_execute(moduleName:string, is_base_hook: boolean){
    let gotls = new GoTLS_Linux(moduleName,socket_library,is_base_hook);
    try {
        let hooker = gotls.execute_hooks();
        // wait 1 sec before we continue
        setTimeout(function() {
            try{
                gotls.execute_symbol_based_hooking(hooker);
            }catch(e){
                devlog("[-] Error in gotls.execute_symbol_based_hooking: "+ e);
            }

        }, 1500);
    }catch(error_msg){
        devlog(`gotls_execute error: ${error_msg}`)
    }
    // Plaintext (-p, with -ed): the shared onEnter-only Go probes (no-op without -p).
    legacyGoPlaintext(moduleName);

    if (is_base_hook) {
        try {
            const init_addresses = gotls.addresses[moduleName];
            // ensure that we only add it to global when we are not
            if (Object.keys(init_addresses).length > 0) {
                (globalThis as any).init_addresses[moduleName] = init_addresses;
            }
        }catch(error_msg){
            devlog(`gotls_execute base-hook error: ${error_msg}`)
        }
    }

}
