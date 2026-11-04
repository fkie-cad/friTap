// agent/ssh/platforms/linux/libssh_linux.ts
//
// Modern-path entry point for libssh. See openssh_linux.ts for the
// wrapper rationale — libssh shares the same delegation pattern but
// advertises a different symbol set so future reimplementations have a
// distinct definition to specialise.

import { socket_library } from "../../../platforms/linux.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeFromDefinition } from "../../../core/loader.js";
import { createLibsshDefinition } from "../../definitions/libssh.js";

// Returns the definition's installed verdict (ModuleHookingType) so the loader
// reports library_detected only once hooks are actually in place.
export function libssh_execute_modern(moduleName: string, is_base_hook: boolean): Promise<boolean> {
    return executeFromDefinition(createLibsshDefinition(), moduleName, socket_library, is_base_hook, enable_default_fd);
}
