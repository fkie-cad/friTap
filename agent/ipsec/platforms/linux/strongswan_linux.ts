// agent/ipsec/platforms/linux/strongswan_linux.ts
//
// Modern-path entry point for strongSwan IPSec on Linux. Mirrors the wrapper
// pattern used by every TLS library under agent/tls/platforms/linux/ and by
// SSH under agent/ssh/platforms/linux/.
//
// The actual hook installation is delegated to the legacy
// ipsec_detect_execute() via the HookDefinition's keylog.install (see
// agent/ipsec/definitions/strongswan.ts) — this file only wires the
// definition into the generic executeFromDefinition() dispatcher so
// `use_modern=true` observably routes through the same scaffolding as
// every other modern executor.

import { socket_library } from "../../../platforms/linux.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeFromDefinition } from "../../../core/loader.js";
import { createStrongswanDefinition } from "../../definitions/strongswan.js";

export function strongswan_execute_modern(moduleName: string, is_base_hook: boolean): void {
    executeFromDefinition(createStrongswanDefinition(), moduleName, socket_library, is_base_hook, enable_default_fd);
}
