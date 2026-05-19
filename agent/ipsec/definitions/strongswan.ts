// agent/ipsec/definitions/strongswan.ts
//
// Scaffolding HookDefinition for strongSwan IPSec.
// Current behaviour: delegates to legacy ipsec_detect_execute (detection-only stub).
// Future work: hook derive_ike_keys / ikev2_derive_child_sa_keys / child_sa_install
// and emit Wireshark IKEv2 + ESP SA decryption tables via a new
// IpsecKeylogFormatter on the Python side.
//
// The legacy ipsec_detect_execute path (agent/ipsec/platforms/linux/ipsec_linux.ts)
// remains the source of truth for runtime behaviour today. This file only
// routes the IPSec hook installation through executeFromDefinition() so that
// `use_modern=true` is a real toggle for IPSec, matching the wiring used by
// every other library in the modern path.
//
// A future PR can replace the delegation with a full register-aware
// reimplementation (derive_ike_keys + ikev2_derive_child_sa_keys +
// child_sa_install + child_sa_set_spi + keymat_v2_create), backed by a
// Wireshark-compatible IPSec keylog formatter on the Python side, without
// changing the call sites in agent/platforms/{linux,android}.ts.

import { HookDefinition, ResolvedFunctions } from "../../core/hook_definition.js";
import { STANDARD_SOCKET_SYMBOLS } from "../../tls/definitions/shared_constants.js";
import { noOpClientRandomDecoder } from "../../tls/definitions/shared_factories.js";
import { ipsec_detect_execute } from "../platforms/linux/ipsec_linux.js";

function strongswanFdDecoder(_ctx: NativePointer, _fns: ResolvedFunctions): number {
    return -1;
}

function strongswanSessionIdDecoder(_ctx: NativePointer, _fns: ResolvedFunctions): string {
    return "";
}

// Known strongSwan symbols that future work will target. None are required
// to resolve today — they may not be exported, especially in stripped
// production builds where vtable-based hooking will eventually be needed.
const STRONGSWAN_LIBRARY_SYMBOLS: string[] = [
    "derive_ike_keys",
    "ikev2_derive_child_sa_keys",
    "child_sa_install",
    "child_sa_set_spi",
    "keymat_v2_create",
];

export function createStrongswanDefinition(): HookDefinition {
    return {
        libraryId: "strongswan",
        offsetKey: "strongswan",
        functions: {
            librarySymbols: STRONGSWAN_LIBRARY_SYMBOLS,
            socketSymbols: STANDARD_SOCKET_SYMBOLS,
        },
        nativeFunctions: [],
        fdDecoder: strongswanFdDecoder,
        sessionIdDecoder: strongswanSessionIdDecoder,
        clientRandomDecoder: noOpClientRandomDecoder,
        // readHook / writeHook intentionally undefined — IPSec key
        // extraction will live in dedicated derive_ike_keys /
        // ikev2_derive_child_sa_keys hooks (see future work above),
        // not in the generic read/write executors.
        keylog: {
            kind: "custom",
            install: (_addresses, moduleName, _resolvedFns, _enableDefaultFd) => {
                // Delegate to the legacy executor. It currently handles
                // library detection and the partial derive_ike_keys /
                // ikev2_derive_child_sa_keys hooks that exist today.
                ipsec_detect_execute(moduleName, /* is_base_hook */ true);
                return true;
            },
        },
        libraryType: "ipsec_strongswan",
    };
}
