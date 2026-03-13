// agent/core/context.ts
//
// AgentContext: Replaces globals with a scoped state object.
// Created once after handshake, passed to all hook installers.

import { HookingPipeline } from "../shared/hooking_pipeline";
import { HookRegistry } from "../shared/registry";

export interface AgentConfig {
    readonly experimental: boolean;
    readonly enableDefaultFd: boolean;
    readonly socketTracing: boolean;
    readonly protocol: string;
    readonly antiRoot: boolean;
    readonly payloadModification: boolean;
    readonly debug: boolean;
}

export interface ModuleIndex {
    /** Get resolved addresses for a module */
    getAddresses(moduleName: string): Record<string, NativePointer>;
    /** Store resolved addresses for a module */
    setAddresses(moduleName: string, addresses: Record<string, NativePointer>): void;
    /** Check if a module has been processed */
    hasModule(moduleName: string): boolean;
}

export interface AgentContext {
    readonly config: AgentConfig;
    readonly modules: ModuleIndex;
    readonly pipeline: HookingPipeline;
    readonly registry: HookRegistry;

    /** Send a message to the Python host */
    send(msg: object, data?: ArrayBuffer | null): void;
    /** Send keylog data */
    sendKeylog(line: string): void;
    /** Send datalog data */
    sendDatalog(meta: object, data: ArrayBuffer): void;
}

class SimpleModuleIndex implements ModuleIndex {
    private _modules: Map<string, Record<string, NativePointer>> = new Map();

    getAddresses(moduleName: string): Record<string, NativePointer> {
        return this._modules.get(moduleName) || {};
    }

    setAddresses(moduleName: string, addresses: Record<string, NativePointer>): void {
        this._modules.set(moduleName, addresses);
    }

    hasModule(moduleName: string): boolean {
        return this._modules.has(moduleName);
    }
}

export function createAgentContext(
    config: AgentConfig,
    pipeline: HookingPipeline,
    registry: HookRegistry,
): AgentContext {
    const modules = new SimpleModuleIndex();

    return {
        config,
        modules,
        pipeline,
        registry,

        send(msg: object, data?: ArrayBuffer | null): void {
            if (data) {
                send({ ...msg, protocol: config.protocol }, data);
            } else {
                send({ ...msg, protocol: config.protocol });
            }
        },

        sendKeylog(line: string): void {
            send({ contentType: "keylog", keylog: line, protocol: config.protocol });
        },

        sendDatalog(meta: object, data: ArrayBuffer): void {
            send({ contentType: "datalog", ...meta, protocol: config.protocol }, data);
        },
    };
}
