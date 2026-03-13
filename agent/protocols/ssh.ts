/**
 * SSH protocol definition.
 *
 * Targets OpenSSH for session key extraction via memory scanning
 * and function hooking.
 */

import { Protocol, KeyMaterial } from "./base";

export class SSHProtocol implements Protocol {
    name = "ssh";
    displayName = "SSH";

    detect(moduleName: string): boolean {
        const lower = moduleName.toLowerCase();
        return /(?:libssh|sshd|ssh_|openssh)/.test(lower);
    }

    getLibraryPatterns(): RegExp[] {
        return [
            /.*libssh\.so/,
            /.*libssh2\.so/,
            /.*sshd/,
        ];
    }

    getRequiredFunctions(): string[] {
        return [
            "kex_derive_keys",
            "ssh_packet_send",
            "ssh_packet_read",
        ];
    }

    getKeyLabels(): string[] {
        return [
            "SSH_SESSION_KEY",
            "SSH_IV_CLIENT",
            "SSH_IV_SERVER",
            "SSH_ENC_KEY_CLIENT",
            "SSH_ENC_KEY_SERVER",
        ];
    }

    formatKeylog(keys: KeyMaterial): string {
        return `${keys.label} ${keys.secret}`;
    }
}
