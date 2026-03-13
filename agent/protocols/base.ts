/**
 * Base protocol interface for friTap agent.
 *
 * Protocols define what libraries to look for, what functions to hook,
 * and how to format extracted key material.
 */

export interface KeyMaterial {
    label: string;
    clientRandom?: string;
    secret: string;
    protocol: string;
}

export interface Protocol {
    /** Protocol identifier: "tls", "ipsec", "ssh", "signal", "smb3" */
    name: string;

    /** Human-readable display name */
    displayName: string;

    /** Check if a loaded module belongs to this protocol */
    detect(moduleName: string): boolean;

    /** Library name regex patterns to watch for */
    getLibraryPatterns(): RegExp[];

    /** Function names required for hooking */
    getRequiredFunctions(): string[];

    /** Key material labels for output identification */
    getKeyLabels(): string[];

    /** Format extracted keys into protocol-specific keylog format */
    formatKeylog(keys: KeyMaterial): string;
}
