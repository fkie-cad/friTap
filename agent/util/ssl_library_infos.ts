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

        output.push("\n=== [ Libraries with TLS/SSL-related exports ] ===");
        const sslExportLibs: string[] = [];
        const sslPatterns = [
            '_ssl', 'ssl_', 'SSL_', 'TLS_', 'tls_', 
            'mbedtls_', 'wolfssl', 'wolfSSL', 'gnutls_',
            'BIO_', 'X509_', 'EVP_', 'RAND_', 'RSA_',
            'PKCS', 'ASN1_', 'PEM_', 'CRYPTO_'
        ];

        for (const mod of modules) {
            try {
                const exports = Process.getModuleByName(mod.name).enumerateExports();
                const relevantExports = exports.filter(exp => 
                    sslPatterns.some(pattern => exp.name.includes(pattern))
                );
                
                if (relevantExports.length > 0) {
                    sslExportLibs.push(mod.name);
                    output.push(`- ${mod.name} (${relevantExports.length} TLS/SSL exports)`);
                    
                    // Show some key exports for debugging
                    const keyExports = relevantExports.slice(0, 5);
                    for (const exp of keyExports) {
                        output.push(`  * ${exp.name} @ ${exp.address}`);
                    }
                    if (relevantExports.length > 5) {
                        output.push(`  ... and ${relevantExports.length - 5} more`);
                    }
                }
            } catch (err) {
                output.push(`[!] Could not enumerate exports of ${mod.name}: ${err}`);
            }
        }

        // Step 2: Check for common SSL/TLS libraries
        output.push("\n=== [ Known SSL/TLS Library Detection ] ===");
        output.push("=== [ VERIFY these results as they could contain FALSE POSITIVES ] ===");
        const knownLibraries = [
            { name: 'OpenSSL', patterns: ['libssl', 'libcrypto', 'openssl'] },
            { name: 'WolfSSL', patterns: ['libwolfssl', 'wolfssl'] },
            { name: 'mbedTLS', patterns: ['libmbedtls', 'mbedtls'] },
            { name: 'GnuTLS', patterns: ['libgnutls', 'gnutls'] },
            { name: 'NSS', patterns: ['libnss', 'nss'] },
            { name: 'Schannel', patterns: ['schannel', 'secur32'] },
            { name: 'BoringSSL', patterns: ['boringssl'] },
            { name: 'LibreSSL', patterns: ['libressl'] }
        ];

        for (const lib of knownLibraries) {
            const foundModules = modules.filter(mod => 
                lib.patterns.some(pattern => 
                    mod.name.toLowerCase().includes(pattern.toLowerCase())
                )
            );
            
            if (foundModules.length > 0) {
                output.push(`✓ ${lib.name} detected:`);
                for (const mod of foundModules) {
                    output.push(`  - ${mod.name} @ ${mod.base}`);
                }
            }
        }

        return output.join("\n");
    }
}

const inspector = new SSLLibraryInspector();

rpc.exports = {
    //@ts-ignore
    inspectssl(): string {
        return inspector.inspect();
    }
};

