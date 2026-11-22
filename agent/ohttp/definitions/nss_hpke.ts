import { looksLikeBhttp, sendOhttpPlaintext } from "./bhttp.js";
import { devlog } from "../../util/log.js";
import type { HookDefinition } from "../../core/hook_definition.js";
import { pcap_enabled } from "../../fritap_agent.js";
import { NSS_HPKE_SYMBOLS } from "../../tls/libs/nss_windows_libraries.js";
import { readSecItemView } from "../../shared/sec_item.js";

function installNssHpkeOhttp(
    addresses: { [key: string]: { [fn: string]: NativePointer } },
    moduleName: string,
): void {
    if (!pcap_enabled) return;
    const addrs = addresses[moduleName] ?? {};

    const sealAddr = addrs["PK11_HPKE_Seal"];
    if (sealAddr && !sealAddr.isNull()) {
        Interceptor.attach(sealAddr, {
            onEnter(args) {
                const ptItem = readSecItemView(args[2]);
                if (!ptItem || !looksLikeBhttp(ptItem.data, ptItem.len)) return;
                devlog(`[*] OHTTP: PK11_HPKE_Seal fired — ${ptItem.len} bytes bhttp request`);
                sendOhttpPlaintext("request", "PK11_HPKE_Seal",
                    ptItem.data.readByteArray(ptItem.len));
            },
        });
        devlog("[*] OHTTP: PK11_HPKE_Seal hooked (NSS)");
    } else {
        devlog("[!] OHTTP: PK11_HPKE_Seal not found — NSS >= 3.58 required");
    }

    const openAddr = addrs["PK11_HPKE_Open"];
    if (openAddr && !openAddr.isNull()) {
        Interceptor.attach(openAddr, {
            onEnter(args) {
                this.outPtPtr = args[3];
            },
            onLeave(retval) {
                if (retval.toInt32() !== 0) return;
                if (!this.outPtPtr || this.outPtPtr.isNull()) return;
                const outPt = this.outPtPtr.readPointer();
                if (outPt.isNull()) return;
                const ptItem = readSecItemView(outPt);
                if (!ptItem || !looksLikeBhttp(ptItem.data, ptItem.len)) return;
                devlog(`[*] OHTTP: PK11_HPKE_Open fired — ${ptItem.len} bytes bhttp response`);
                sendOhttpPlaintext("response", "PK11_HPKE_Open",
                    ptItem.data.readByteArray(ptItem.len));
            },
        });
        devlog("[*] OHTTP: PK11_HPKE_Open hooked (NSS)");
    } else {
        devlog("[!] OHTTP: PK11_HPKE_Open not found — NSS >= 3.58 required");
    }
}

/**
 * PK11_HPKE_Seal / PK11_HPKE_Open are exported by the nss3 module itself on every platform
 * (libnss3.so, libnss3.dylib, and (lib)nss3.dll in both the folded and the unfolded Windows
 * layout), and every platform row matches exactly that module, so they resolve in it.
 */
export function createNssHpkeDefinition(): HookDefinition {
    return {
        libraryId: "nss_hpke",
        offsetKey: "nss_hpke",
        functions: {
            librarySymbols: [...NSS_HPKE_SYMBOLS],
            socketSymbols: [],
        },
        nativeFunctions: [],
        fdDecoder: () => -1,
        sessionIdDecoder: () => "",
        keylog: { kind: "none" },
        extraHooks: [{ install: installNssHpkeOhttp }],
    };
}
