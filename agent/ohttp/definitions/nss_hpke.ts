import { looksLikeBhttp, sendOhttpPlaintext } from "./bhttp.js";
import { devlog } from "../../util/log.js";
import type { HookDefinition } from "../../core/hook_definition.js";

function readSECItem(ptr: NativePointer): { data: NativePointer; len: number } | null {
    if (ptr.isNull()) return null;
    const dataPtr = ptr.add(Process.pointerSize).readPointer();
    const len = ptr.add(Process.pointerSize * 2).readU32();
    if (len === 0 || dataPtr.isNull()) return null;
    return { data: dataPtr, len };
}

function installNssHpkeOhttp(
    addresses: { [key: string]: { [fn: string]: NativePointer } },
    moduleName: string,
): void {
    const addrs = addresses[moduleName] ?? {};

    const sealAddr = addrs["PK11_HPKE_Seal"];
    if (sealAddr && !sealAddr.isNull()) {
        Interceptor.attach(sealAddr, {
            onEnter(args) {
                const ptItem = readSECItem(args[2]);
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
                const ptItem = readSECItem(outPt);
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

export function createNssHpkeDefinition(): HookDefinition {
    return {
        libraryId: "nss_hpke",
        offsetKey: "nss_hpke",
        functions: {
            librarySymbols: [],
            socketSymbols: [],
            auxiliaryLibraries: [
                { pattern: "*libnss*", symbols: ["PK11_HPKE_Seal", "PK11_HPKE_Open"] }
            ],
        },
        nativeFunctions: [],
        fdDecoder: () => -1,
        sessionIdDecoder: () => "",
        keylog: { kind: "none" },
        extraHooks: [{ install: installNssHpkeOhttp }],
    };
}
