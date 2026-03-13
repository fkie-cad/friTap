/**
 * TLS/SSL protocol definition.
 *
 * Wraps the existing TLS hooking functionality as a Protocol,
 * enabling uniform protocol handling.
 */

import { Protocol, KeyMaterial } from "./base";

export class TLSProtocol implements Protocol {
    name = "tls";
    displayName = "TLS/SSL";

    detect(moduleName: string): boolean {
        const lower = moduleName.toLowerCase();
        return /(?:libssl|libcrypto|libgnutls|libwolfssl|libmbedtls|libnss|boringssl|schannel|secur32|security)/.test(lower);
    }

    getLibraryPatterns(): RegExp[] {
        return [
            /.*libssl\.so/,
            /.*libssl_sb\.so/,
            /.*libcrypto\.so/,
            /.*libgnutls\.so/,
            /.*libwolfssl\.so/,
            /.*libmbedtls\.so/,
            /.*libnss.*\.so/,
            /.*cronet.*\.so/,
            /.*libflutter\.so/,
            /.*schannel\.dll/i,
            /.*secur32\.dll/i,
        ];
    }

    getRequiredFunctions(): string[] {
        return [
            "SSL_read",
            "SSL_write",
            "SSL_get_session",
            "SSL_CTX_set_keylog_callback",
        ];
    }

    getKeyLabels(): string[] {
        return [
            "CLIENT_RANDOM",
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            "SERVER_HANDSHAKE_TRAFFIC_SECRET",
            "CLIENT_TRAFFIC_SECRET_0",
            "SERVER_TRAFFIC_SECRET_0",
            "EXPORTER_SECRET",
            "EARLY_EXPORTER_SECRET",
        ];
    }

    formatKeylog(keys: KeyMaterial): string {
        // NSS Key Log format: LABEL <client_random_hex> <secret_hex>
        if (keys.clientRandom) {
            return `${keys.label} ${keys.clientRandom} ${keys.secret}`;
        }
        return keys.secret;
    }
}
