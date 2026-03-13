/**
 * IPSec (IKEv2/ESP) protocol definition.
 *
 * Targets strongSwan/libcharon for IKEv2 key extraction.
 */

import { Protocol, KeyMaterial } from "./base";

export class IPSecProtocol implements Protocol {
    name = "ipsec";
    displayName = "IPSec (IKEv2/ESP)";

    detect(moduleName: string): boolean {
        const lower = moduleName.toLowerCase();
        return /(?:libcharon|libstrongswan|libipsec|ikev2|pfkey)/.test(lower);
    }

    getLibraryPatterns(): RegExp[] {
        return [
            /.*libcharon\.so/,
            /.*libstrongswan\.so/,
            /.*libipsec\.so/,
        ];
    }

    getRequiredFunctions(): string[] {
        return [
            "ikev2_derive_child_sa_keys",
            "derive_ike_keys",
        ];
    }

    getKeyLabels(): string[] {
        return ["SK_ei", "SK_er", "SK_ai", "SK_ar", "SK_pi", "SK_pr"];
    }

    formatKeylog(keys: KeyMaterial): string {
        return `${keys.label} ${keys.secret}`;
    }
}
