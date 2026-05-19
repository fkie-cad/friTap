import { socket_library } from "../../../platforms/linux.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeFromDefinition } from "../../../core/loader.js";
import { createMatrixSslDefinition } from "../../definitions/matrixssl.js";

export { matrixSSL_execute } from "../../../legacy/tls/platforms/linux/matrixssl_linux.js";

export function matrixSSL_execute_modern(moduleName: string, is_base_hook: boolean): void {
    executeFromDefinition(
        createMatrixSslDefinition(),
        moduleName,
        socket_library,
        is_base_hook,
        enable_default_fd,
    );
}
