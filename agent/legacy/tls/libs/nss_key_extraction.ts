// agent/legacy/tls/libs/nss_key_extraction.ts
//
// The install_tls_keys_callback_hook body every legacy NSS platform hooker shares
// (linux / macos / android / windows). All tier logic lives in the shared installer
// agent/tls/libs/nss_install.ts; this only reports its verdict the way the legacy
// hookers always have.

import { devlog } from "../../../util/log.js";
import { installNssKeyExtraction } from "../../../tls/libs/nss_install.js";
import type { NssFunctionAddresses } from "../../../tls/libs/nss.js";

/**
 * Install NSS key extraction for one hooked module and log the outcome.
 *
 * @param moduleName the hooked module (the one PR_Read/PR_Write were resolved in)
 * @param fnAddrs    its resolved addresses, i.e. `addresses[moduleName]`
 * @returns the installer's verdict; never rejects (installNssKeyExtraction never does)
 */
export function installLegacyNssKeyExtraction(moduleName: string, fnAddrs: NssFunctionAddresses): Promise<boolean> {
    return installNssKeyExtraction(moduleName, fnAddrs).then(installed => {
        devlog(installed
            ? "[*] NSS key extraction installed via shared implementation"
            : "[-] NSS key extraction: no tier could be installed");
        return installed;
    });
}
