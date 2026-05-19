// agent/core/hook_definition.ts
//
// Data-driven hook definition interfaces.
// A HookDefinition describes a TLS library's hooks declaratively;
// generic executors consume these definitions to install Frida interceptors.

import { LibraryType } from "../shared/shared_structures.js";
import type { FamilyKey } from "../shared/bundled_cronet_patterns.js";

export type ResolvedFunctions = Record<string, NativeFunction<any, any>>;

export interface NativeFnSpec {
    symbol: string;
    retType: string;
    argTypes: string[];
}

export interface ReadWriteArgLayout {
    sslCtxArgIndex: number;
    bufferArgIndex: number;
    lengthArgIndex?: number;
    bytesTransferred: "retval" | "arg";
}

export type FdDecoder = (sslCtx: NativePointer, resolvedFns: ResolvedFunctions) => number;
export type SessionIdDecoder = (sslCtx: NativePointer, resolvedFns: ResolvedFunctions) => string;
export type ClientRandomDecoder = (sslCtx: NativePointer, resolvedFns: ResolvedFunctions) => string;

export interface ReadHookDef {
    symbol: string;
    args: ReadWriteArgLayout;
    functionLabel?: string;
}

export interface WriteHookDef {
    symbol: string;
    args: ReadWriteArgLayout;
    functionLabel?: string;
}

export type KeylogApproach =
    | {
        kind: "callback_on_init";
        initSymbol: string;
        callbackInstaller: (session: NativePointer, resolvedFns: ResolvedFunctions) => void;
    }
    | {
        kind: "callback_on_ssl_new";
        sslNewSymbol: string;
        callbackInstaller: (ssl: NativePointer, resolvedFns: ResolvedFunctions) => void;
    }
    | {
        kind: "manual_on_connect";
        connectSymbol: string;
        extractKeys: (ssl: NativePointer, resolvedFns: ResolvedFunctions) => void;
    }
    | {
        kind: "custom";
        install: (
            addresses: { [key: string]: { [fn: string]: NativePointer } },
            moduleName: string,
            resolvedFns: ResolvedFunctions,
            enableDefaultFd: boolean,
        ) => boolean;
    }
    | { kind: "none" };

export interface ExtraHookDef {
    install: (
        addresses: { [key: string]: { [fn: string]: NativePointer } },
        moduleName: string,
        resolvedFns: ResolvedFunctions,
        enableDefaultFd: boolean,
    ) => void;
}

export interface HookDefinition {
    libraryId: string;
    offsetKey: string;
    functions: {
        librarySymbols: string[];
        socketSymbols: string[];
        auxiliaryLibraries?: Array<{ pattern: string; symbols: string[] }>;
    };
    nativeFunctions: NativeFnSpec[];
    fdDecoder: FdDecoder;
    sessionIdDecoder: SessionIdDecoder;
    clientRandomDecoder?: ClientRandomDecoder;
    readHook?: ReadHookDef;
    writeHook?: WriteHookDef;
    keylog: KeylogApproach;
    customAddressExtractor?: (
        sslCtx: NativePointer,
        isRead: boolean,
        resolvedFns: ResolvedFunctions,
        enableDefaultFd: boolean,
    ) => { [key: string]: string | number } | null;
    extraHooks?: ExtraHookDef[];
    onNativeFunctionsResolved?: (fns: ResolvedFunctions) => void;
    /**
     * Optional library-family marker. When set to "boringssl", the loader
     * routes through the three-tier hook chain (see
     * agent/shared/boringssl_hook_chain.ts): tier 1 = SSL_CTX_set_keylog_callback,
     * tier 2 = bssl::ssl_log_secret symbol, tier 3 = pattern.json byte-pattern
     * scan. Typed as the shared LibraryType union so a typo can't silently
     * disable the chain.
     */
    libraryType?: LibraryType;
    /**
     * BoringSSL-only tier ordering for the three-tier hook chain. Default
     * "callback-first" tries SSL_CTX_set_keylog_callback before the
     * bssl::ssl_log_secret symbol hook. Set "symbol-first" for Cronet-derived
     * libs (libwarp_mobile, libcronet, libsignal_jni, libquiche_android,
     * librustls_android_13_ex) that bypass SSL_new internally — the callback
     * path would install cleanly there but never fire at runtime. Tier 3
     * (pattern scan) is always last regardless of priority. Ignored when
     * libraryType !== "boringssl".
     */
    keylogPriority?: "callback-first" | "symbol-first";
    /**
     * BoringSSL-only library-family marker consumed by the modern hook chain's
     * tier-3 fallback. When set (typically by cronet_execute_modern), the
     * pattern tier consults the bundled per-family byte patterns in
     * agent/shared/bundled_cronet_patterns.ts as part of its 3a→3d sub-cascade.
     * Leaving it unset is safe — the chain falls back to "generic_boringssl"
     * by classifying the module name itself. Ignored when libraryType !==
     * "boringssl".
     */
    family?: FamilyKey;
}
