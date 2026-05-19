// agent/ssh/platforms/linux/openssh_linux.ts
//
// Modern-path entry point for OpenSSH. Mirrors the wrapper pattern used
// by every TLS library under agent/tls/platforms/linux/.
//
// The actual hook installation is delegated to the legacy
// ssh_detect_execute() via the HookDefinition's keylog.install (see
// agent/ssh/definitions/openssh.ts) — this file only wires the
// definition into the generic executeFromDefinition() dispatcher so
// `use_modern=true` observably routes through the same scaffolding as
// every other modern executor.

import { socket_library } from "../../../platforms/linux.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeFromDefinition } from "../../../core/loader.js";
import { createOpenSshDefinition } from "../../definitions/openssh.js";

export function openssh_execute_modern(moduleName: string, is_base_hook: boolean): void {
    executeFromDefinition(createOpenSshDefinition(), moduleName, socket_library, is_base_hook, enable_default_fd);
}
