// agent/core/hook_definition.ts
//
// Data-driven hook definition interfaces.
// A HookDefinition describes a TLS library's hooks declaratively;
// generic executors consume these definitions to install Frida interceptors.

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
        ) => void;
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
}
