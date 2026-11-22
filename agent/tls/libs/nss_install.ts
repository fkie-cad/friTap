// agent/tls/libs/nss_install.ts
//
// The one NSS key-extraction installer shared by the modern definition
// (agent/tls/definitions/nss.ts) and the legacy platform hookers. Tier order:
//   1. keylog-writer hook (agent/shared/nss_keylog_locator.ts), read-only;
//   2. SSL_SecretCallback API with call-through + restore on detach; its client_random
//      offset comes from tier 1, the learned cache, or the read-only PK11_GenerateRandom
//      learner (agent/shared/nss_client_random_learner.ts);
//   3. read-only offset table, only for NSS < NSS.TABLE_VERIFIED_BELOW.
// Tiers 2/3 are installed only after the tier-1 promise settled false.
// Plaintext (PR_Read/PR_Write) hooking is not touched here.

import { installNssKeylogHook } from "../../shared/nss_keylog_locator.js";
import { devlog } from "../../util/log.js";
import { NSS, NssFunctionAddresses } from "./nss.js";

/** Module that owns the NSS SSL code: the module of SSL_ImportFD, else the hooked module. */
function sslModuleOf(moduleName: string, fnAddrs: NssFunctionAddresses): Module | null {
    const importFd = fnAddrs["SSL_ImportFD"];
    if (importFd && !importFd.isNull()) {
        const owner = Process.findModuleByAddress(importFd);
        if (owner !== null) return owner;
    }
    return Process.findModuleByName(moduleName);
}

type ExportFinder = (name: string) => NativePointer | null;

/**
 * The exports the fallback tiers use, filled in module-scoped when the caller did not
 * resolve them. SSL_ImportFD / SSL_HandshakeCallback are among them because callers
 * differ: the legacy Android hooker resolves them in the folded libnss3.so, the modern
 * definition through a `*libssl*.so` glob that matches no NSS module on Android (and the
 * global-export fallback cannot see the app's linker namespace), so without this the
 * modern tree reached tiers 2/3 without SSL_ImportFD.
 */
const FALLBACK_TIER_EXPORTS = ["SSL_ImportFD", "SSL_HandshakeCallback", "SSL_GetExperimentalAPI", "PR_Close", "PK11_GenerateRandom"];

/** Copy of fnAddrs with FALLBACK_TIER_EXPORTS filled in module-scoped. */
function withFallbackExports(fnAddrs: NssFunctionAddresses, findExport: ExportFinder): NssFunctionAddresses {
    const filled: NssFunctionAddresses = { ...fnAddrs };
    for (const name of FALLBACK_TIER_EXPORTS) {
        if (filled[name] && !filled[name].isNull()) continue;
        const found = findExport(name);
        if (found !== null) filled[name] = found;
    }
    return filled;
}

async function tryKeylogWriterHook(sslModule: Module | null, findExport: ExportFinder): Promise<boolean> {
    if (sslModule === null) return false;
    try {
        return await installNssKeylogHook(sslModule, { findExport });
    } catch (e) {
        devlog(`[nss-keylog] ${sslModule.name}: keylog writer tier failed: ${e}`);
        return false;
    }
}

/**
 * Install NSS key extraction for one hooked NSS copy.
 *
 * @param moduleName the hooked module (the one PR_Read/PR_Write were resolved in)
 * @param fnAddrs    its resolved addresses, i.e. `addresses[moduleName]`
 *                   (SSL_ImportFD, SSL_HandshakeCallback, PR_GetDescType,
 *                   PR_GetNameForIdentity, PK11_ExtractKeyValue, PK11_GetKeyData,
 *                   optionally SSL_GetExperimentalAPI / PR_Close); any of
 *                   FALLBACK_TIER_EXPORTS missing here is looked up module-scoped
 * @returns resolves true iff a key-extraction hook (any tier) was installed.
 *          Binds the NSS helper NativeFunctions synchronously before the first await,
 *          so the plaintext hooks can rely on them right after the call. Never rejects.
 */
export async function installNssKeyExtraction(moduleName: string, fnAddrs: NssFunctionAddresses): Promise<boolean> {
    NSS.bindNativeHelpers(fnAddrs);
    const sslModule = sslModuleOf(moduleName, fnAddrs);
    NSS.setExportScope([sslModule, Process.findModuleByName(moduleName)]);
    // One loaded-module snapshot per install, shared by the keylog tier (incl. its NSS
    // version lookup) and the fallback exports, instead of an enumeration per export name.
    const findExport = NSS.nssExportFinder();

    if (await tryKeylogWriterHook(sslModule, findExport)) {
        devlog(`[*] ${moduleName}: NSS keys via the keylog-writer hook; no callback hooks installed`);
        return true;
    }
    try {
        const filled = withFallbackExports(fnAddrs, findExport);
        NSS.bindNativeHelpers(filled);   // SSL_HandshakeCallback may only now be resolved (tier 3 needs it)
        return NSS.installFallbackKeyHooks(filled);
    } catch (e) {
        devlog(`[-] ${moduleName}: NSS fallback key extraction failed: ${e}`);
        return false;
    }
}
