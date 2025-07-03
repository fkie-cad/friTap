import { readAddresses, checkNumberOfExports, getBaseAddress } from "../shared/shared_functions.js";
import { devlog, log } from "../util/log.js";


export class GoTLS {
    module_name: string;
    library_method_mapping: { [key: string]: string[] } = {};
    addresses: { [lib: string]: { [fn: string]: NativePointer } } = {};
    is_base_hook: boolean;

    constructor(moduleName: string, socket_library: string, is_base_hook: boolean) {
            this.module_name = moduleName;
            this.is_base_hook = is_base_hook;

            // Only hook standard GoTLS functions
            this.library_method_mapping[`*${moduleName}*`] = [
            "crypto/tls.(*Conn).Read", 
            "crypto/tls.(*Conn).Write", 
            "crypto/tls.(*Conn).Handshake",
            ];

            this.addresses = readAddresses(moduleName, this.library_method_mapping);
    }

    install_plaintext_write_hook(): void {
        const symbol = "crypto/tls.(*Conn).writeRecordLocked";
        try {
            const address = Module.getGlobalExportByName( symbol);
            if (!address) throw new Error(`${symbol} not found`);
            Interceptor.attach(address, {
                onEnter(args) {
                    const recordType = args[2].toInt32();
                    if (recordType !== 23) return;

                    const dataPtr = args[3];
                    const len = args[4].toInt32();
                    if (len > 0) {
                        const buf = dataPtr.readByteArray(len);
                        devlog(`[GoTLS] write plaintext (${len} bytes): ${buf ? buf.toString() : "[unreadable]"}`);
                    }
                }
            });
        } catch (err) {
            devlog(`[GoTLS] Failed to hook writeRecordLocked: ${err}`);
        }
    }

    install_plaintext_read_hook(): void {
        const symbol = "crypto/tls.(*Conn).Read";
        try {
            const address = Module.getGlobalExportByName(symbol);
            if (!address) throw new Error(`${symbol} not found`);
            Interceptor.attach(address, {
                onEnter(args) {
                    this.x0 = args[0]; // Go slice pointer
                },
                onLeave(retval) {
                    const len = retval.toInt32();
                    if (len <= 0) return;
                    //const buf = this.context.x0.readByteArray(len); // x0 = first arg (Go slice ptr)
                    const buf = this.x0.readByteArray(len); // x0 = first arg (Go slice ptr)
                    devlog(`[GoTLS] read plaintext (${len} bytes): ${buf ? buf.toString() : "[unreadable]"}`);
                }
            });
        } catch (err) {
            devlog(`[GoTLS] Failed to hook Read: ${err}`);
        }
    }

    install_tls_keys_callback_hook(): void {
        const symbol = "crypto/tls.(*Config).writeKeyLog";
        try {
            const address = Module.getGlobalExportByName(symbol);
            if (!address) throw new Error(`${symbol} not found`);
            Interceptor.attach(address, {
                onEnter(args) {
                    try {
                        const labelPtr = args[2];
                        const labelLen = args[3].toInt32();
                        const crPtr = args[4];
                        const crLen = args[5].toInt32();
                        const secretPtr = args[7];
                        const secretLen = args[8].toInt32();

                        const label = labelPtr.readUtf8String(labelLen);
                        const clientRandom = crPtr.readByteArray(crLen);
                        const secret = secretPtr.readByteArray(secretLen);

                        const hex = (buf: ArrayBuffer | null) =>
                            buf
                                ? Array.from(new Uint8Array(buf))
                                      .map(b => b.toString(16).padStart(2, "0"))
                                      .join("")
                                : "";

                        devlog(`[GoTLS] keylog: ${label} ${hex(clientRandom)} ${hex(secret)}`);
                        send({
                            contentType: "keylog",
                            keylog: `${label} ${hex(clientRandom)} ${hex(secret)}`
                        });
                    } catch (e) {
                        devlog(`[GoTLS] Error reading keylog callback args: ${e}`);
                    }
                }
            });
        } catch (err) {
            devlog(`[GoTLS] Failed to hook writeKeyLog: ${err}`);
        }
    }

    install_hooks(): void {
        this.install_plaintext_write_hook();
        this.install_plaintext_read_hook();
        this.install_tls_keys_callback_hook();
    }



  execute() {
    this.install_hooks();
  }
}

export function gotls_execute(moduleName: string, is_base_hook: boolean) {
  const inst = new GoTLS(moduleName, null as any, is_base_hook);
  try { inst.execute(); }
  catch (e) { devlog(`[GoTLS] Execution failed: ${e}`); }
}
