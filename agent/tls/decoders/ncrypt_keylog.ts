// Shared ncrypt.dll keylog extraction for Windows SSPI (in-process) and LSASS
// (out-of-process). Both call sites hook the same 6+1 ncrypt symbols and walk
// the same TLS 1.2 NcryptSslKey and TLS 1.3 BDDD struct chains; the legacy
// implementations duplicated this block verbatim.
//
// Reference: agent/legacy/tls/platforms/windows/{sspi,lsass}.ts.

import { sendKeylog } from "../../shared/shared_structures.js";
import { toHexString } from "../../shared/shared_functions.js";
import { devlog } from "../../util/log.js";

// NCryptBuffer / SecBuffer share layout: ULONG + ULONG + PVOID.
// 16 bytes on 64-bit, 12 bytes on 32-bit.
const NCRYPT_BUFFER_STRIDE = Process.pointerSize === 8 ? 16 : 12;

const NCRYPTBUFFER_SSL_CLIENT_RANDOM = 20;

const enum TLSVersion {
    ONE_TWO = 2,
    ONE_THREE = 3,
}

function noteKeylog(line: string, tlsVersion: TLSVersion): void {
    devlog(`Exporting TLS 1.${tlsVersion} handshake keying material`);
    sendKeylog(line);
}

function parseNcryptMasterKey(pMasterKey: NativePointer): string {
    const ssl5Ptr = pMasterKey.add(0x10).readPointer();
    const masterKey = ssl5Ptr.add(28).readByteArray(48);
    return toHexString(masterKey);
}

function parseParameterListForClientRandom(
    pParameterList: NativePointer,
    callingFunc: string,
): string | null {
    const bufferCount = pParameterList.add(4).readU32();
    const buffers = pParameterList.add(8).readPointer();
    for (let i = 0; i < bufferCount; i++) {
        const buf = buffers.add(NCRYPT_BUFFER_STRIDE * i);
        const bufSize = buf.readU32();
        const bufType = buf.add(4).readU32();
        if (bufType !== NCRYPTBUFFER_SSL_CLIENT_RANDOM) continue;
        const bufData = buf.add(8).readPointer().readByteArray(bufSize);
        const hex = toHexString(bufData);
        devlog(`Got client random from ${callingFunc}'s pParameterList: ${hex}`);
        return hex;
    }
    return null;
}

// TLS 1.3 secret extraction walks a fixed chain of pointer dereferences ending
// at a struct with size@+0x10 and secret_ptr@+0x18. Offsets come from the
// reverse-engineering trace shared with ngo/win-frida-scripts.
function getSecretFromBDDD(structBDDD: NativePointer): ArrayBuffer | null {
    const struct3lss = structBDDD.add(0x10).readPointer();
    const structRUUU = struct3lss.add(0x20).readPointer();
    const structYKSM = structRUUU.add(0x10).readPointer();
    const secretPtr = structYKSM.add(0x18).readPointer();
    const size = structYKSM.add(0x10).readU32();
    return secretPtr.readByteArray(size);
}

export interface NcryptKeylogOptions {
    /** Prefix for devlog messages: "[sspi]" or "[lsass]". */
    logPrefix: string;
    /** Whether to hook SslGenerateSessionKeysHkdf (older Windows alias). */
    includeHkdfAlias: boolean;
}

export function installNcryptKeylogHooks(
    addresses: { [key: string]: { [fn: string]: NativePointer } },
    moduleName: string,
    options: NcryptKeylogOptions,
): boolean {
    const moduleAddrs = addresses[moduleName] ?? {};
    const { logPrefix, includeHkdfAlias } = options;
    // Module-scoped per-thread state. Entries are .delete()'d when the
    // handshake's final keylog line is emitted to keep maps bounded over
    // long-lived (LSASS) agent sessions.
    const clientRandomByThread = new Map<number, string>();
    const tls13HandshakeSeenByThread = new Map<number, boolean>();

    const hashHsAddr = moduleAddrs["SslHashHandshake"];
    const genMasterAddr = moduleAddrs["SslGenerateMasterKey"];
    const importMasterAddr = moduleAddrs["SslImportMasterKey"];
    const genSessionAddr = moduleAddrs["SslGenerateSessionKeys"];
    const genSessionHkdfAddr = moduleAddrs["SslGenerateSessionKeysHkdf"];
    const expandTrafficAddr = moduleAddrs["SslExpandTrafficKeys"];
    const expandExporterAddr = moduleAddrs["SslExpandExporterMasterKey"];

    let installedAny = false;

    if (hashHsAddr && !hashHsAddr.isNull()) {
        Interceptor.attach(hashHsAddr, {
            onEnter(args) {
                const buf = ptr(args[2].toString());
                const len = args[3].toInt32();
                if (len < 6 + 32) return;
                const msgType = buf.readU8();
                const version = buf.add(4).readU16();
                if (msgType !== 1 || version !== 0x0303) return;
                const crandom = toHexString(buf.add(6).readByteArray(32));
                devlog(`Got client random from SslHashHandshake: ${crandom}`);
                clientRandomByThread.set(Process.getCurrentThreadId(), crandom);
            },
        });
        installedAny = true;
    }

    function attachMasterKeyHook(
        addr: NativePointer,
        label: string,
        masterKeyArgIdx: number,
        paramListArgIdx: number,
    ): void {
        Interceptor.attach(addr, {
            onEnter(args) {
                (this as any).phMasterKey = ptr(args[masterKeyArgIdx].toString());
                const pParameterList = ptr(args[paramListArgIdx].toString());
                const tid = Process.getCurrentThreadId();
                (this as any).tid = tid;
                (this as any).client_random =
                    parseParameterListForClientRandom(pParameterList, label) ||
                    clientRandomByThread.get(tid) ||
                    "???";
            },
            onLeave() {
                try {
                    const masterKey = parseNcryptMasterKey((this as any).phMasterKey.readPointer());
                    devlog(`Got masterkey from ${label}`);
                    noteKeylog(
                        "CLIENT_RANDOM " + (this as any).client_random + " " + masterKey,
                        TLSVersion.ONE_TWO,
                    );
                    clientRandomByThread.delete((this as any).tid);
                } catch (e) {
                    devlog(`${logPrefix} ${label} onLeave error: ${e}`);
                }
            },
        });
    }

    if (genMasterAddr && !genMasterAddr.isNull()) {
        attachMasterKeyHook(genMasterAddr, "SslGenerateMasterKey", 3, 6);
        installedAny = true;
    }
    if (importMasterAddr && !importMasterAddr.isNull()) {
        attachMasterKeyHook(importMasterAddr, "SslImportMasterKey", 2, 5);
        installedAny = true;
    }

    function attachGenerateSessionKeys(addr: NativePointer, label: string): void {
        Interceptor.attach(addr, {
            onEnter(args) {
                const hMasterKey = ptr(args[1].toString());
                const pParameterList = ptr(args[4].toString());
                const tid = Process.getCurrentThreadId();
                const clientRandom =
                    parseParameterListForClientRandom(pParameterList, label) ||
                    clientRandomByThread.get(tid) ||
                    "???";
                try {
                    const masterKey = parseNcryptMasterKey(hMasterKey);
                    devlog(`Got masterkey from ${label}`);
                    noteKeylog(
                        "CLIENT_RANDOM " + clientRandom + " " + masterKey,
                        TLSVersion.ONE_TWO,
                    );
                    clientRandomByThread.delete(tid);
                } catch (e) {
                    devlog(`${logPrefix} ${label} onEnter error: ${e}`);
                }
            },
        });
    }

    if (genSessionAddr && !genSessionAddr.isNull()) {
        attachGenerateSessionKeys(genSessionAddr, "SslGenerateSessionKeys");
        installedAny = true;
    }
    if (includeHkdfAlias && genSessionHkdfAddr && !genSessionHkdfAddr.isNull()) {
        attachGenerateSessionKeys(genSessionHkdfAddr, "SslGenerateSessionKeysHkdf");
        installedAny = true;
    }

    if (expandTrafficAddr && !expandTrafficAddr.isNull()) {
        Interceptor.attach(expandTrafficAddr, {
            onEnter(args) {
                const tid = Process.getCurrentThreadId();
                (this as any).tid = tid;
                (this as any).retkey1 = ptr(args[3].toString());
                (this as any).retkey2 = ptr(args[4].toString());
                (this as any).client_random = clientRandomByThread.get(tid) || "???";
                if (tls13HandshakeSeenByThread.get(tid)) {
                    tls13HandshakeSeenByThread.delete(tid);
                    (this as any).suffix = "TRAFFIC_SECRET_0";
                    (this as any).isAppPhase = true;
                } else {
                    tls13HandshakeSeenByThread.set(tid, true);
                    (this as any).suffix = "HANDSHAKE_TRAFFIC_SECRET";
                    (this as any).isAppPhase = false;
                }
            },
            onLeave() {
                try {
                    const key1 = getSecretFromBDDD((this as any).retkey1.readPointer());
                    const key2 = getSecretFromBDDD((this as any).retkey2.readPointer());
                    noteKeylog(
                        "CLIENT_" + (this as any).suffix + " " + (this as any).client_random + " " + toHexString(key1),
                        TLSVersion.ONE_THREE,
                    );
                    noteKeylog(
                        "SERVER_" + (this as any).suffix + " " + (this as any).client_random + " " + toHexString(key2),
                        TLSVersion.ONE_THREE,
                    );
                    if ((this as any).isAppPhase) {
                        clientRandomByThread.delete((this as any).tid);
                    }
                } catch (e) {
                    devlog(`${logPrefix} SslExpandTrafficKeys onLeave error: ${e}`);
                }
            },
        });
        installedAny = true;
    }

    if (expandExporterAddr && !expandExporterAddr.isNull()) {
        Interceptor.attach(expandExporterAddr, {
            onEnter(args) {
                const tid = Process.getCurrentThreadId();
                (this as any).tid = tid;
                (this as any).retkey = ptr(args[3].toString());
                (this as any).client_random = clientRandomByThread.get(tid) || "???";
            },
            onLeave() {
                try {
                    const key = (this as any).retkey
                        .readPointer()
                        .add(0x10).readPointer()
                        .add(0x20).readPointer()
                        .add(0x10).readPointer()
                        .add(0x18).readPointer()
                        .readByteArray(48);
                    noteKeylog(
                        "EXPORTER_SECRET " + (this as any).client_random + " " + toHexString(key),
                        TLSVersion.ONE_THREE,
                    );
                } catch (e) {
                    devlog(`${logPrefix} SslExpandExporterMasterKey onLeave error: ${e}`);
                }
            },
        });
        installedAny = true;
    }

    return installedAny;
}
