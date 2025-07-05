import { log, devlog, devlog_error } from "./log.js";

class SSLLibraryInspector {
    public inspect(): string {
        log("Inspecting loaded SSL libraries...");
        const output: string[] = [];

        // Step 1: All loaded libraries
        output.push("=== [ Loaded Libraries ] ===");
        const modules = Process.enumerateModules();
        for (const mod of modules) {
            output.push(`- ${mod.name} @ ${mod.base} (${mod.size} bytes)`);
        }

        output.push("\n=== [ Libraries with 'ssl' in their name ] ===");
        const sslNameLibs = modules.filter(mod => mod.name.toLowerCase().includes("ssl"));
        for (const mod of sslNameLibs) {
            output.push(`- ${mod.name}`);
        }

        output.push("\n=== [ Libraries with at least one export containing '_ssl' ] ===");
        const sslExportLibs: string[] = [];

        for (const mod of modules) {
            try {
                const exports = Process.getModuleByName(mod.name).enumerateExports();
                const hasSslExport = exports.some(exp => exp.name.toLowerCase().includes("_ssl"));
                if (hasSslExport) {
                    sslExportLibs.push(mod.name);
                    output.push(`- ${mod.name}`);
                }
            } catch (err) {
                output.push(`[!] Could not enumerate exports of ${mod.name}: ${err}`);
            }
        }

        return output.join("\n");
    }
}

const inspector = new SSLLibraryInspector();

rpc.exports = {
    inspectssl(): string {
        return inspector.inspect();
    }
};

