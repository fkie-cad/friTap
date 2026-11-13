/**
 * Per-request Java context for --attribute-sdk. Cronet / HttpEngine / WebView send from a
 * Chromium network thread, so the SDK frame is only on the Java stack that builds the
 * request. These hooks record that stack and emit `request_context` events, joined to
 * flows by friTap/flow/request_context_join.py.
 */

import { Java } from "./javalib.js";
import { registerDetachTeardown, revertJavaOverloads } from "./detach_teardown.js";
import { LruMap } from "./lru.js";
import { sendRequestContext, _isShuttingDown } from "./shared_structures.js";
import { log, devlog } from "../util/log.js";
import type { RequestContextMessage } from "../schemas/messages.js";

// --- Pure helpers ---

export interface RequestContextGateConfig {
    attribute_sdk: boolean;
    pcap_enabled: boolean;
    pairip_safe: boolean;
    quic_only: boolean;
}

/** Needs decrypted flows (-p); --pairip-safe forbids ART hooks; QUIC-only installs no Java hooks. */
export function requestContextHooksWanted(cfg: RequestContextGateConfig): boolean {
    return cfg.attribute_sdk && cfg.pcap_enabled && !cfg.pairip_safe && !cfg.quic_only;
}

export const MAX_REQUEST_FRAMES = 32;

/** One `\tat a.b.C.m(File.java:1)` line of Throwable.printStackTrace output. */
const STACK_FRAME_LINE = /^\s*at\s+([^\s(]+)\(/;
/** Frames of the capture itself (the probe Throwable + Log.getStackTraceString), never the app's. */
const HOOK_INTERNAL_FRAME_PREFIXES = ["java.lang.Throwable.", "android.util.Log.", "dalvik.system.VMStack."];

/**
 * `Log.getStackTraceString(throwable)` text -> "class.method" strings, capped.
 * The throwable header, `... N more` and `Caused by:` lines are not frames and
 * are skipped, as are the capture's own frames.
 */
export function parseStackTraceFrames(trace: string | null, cap: number = MAX_REQUEST_FRAMES): string[] {
    const out: string[] = [];
    if (!trace) return out;
    for (const line of trace.split("\n")) {
        if (out.length >= cap) break;
        const match = STACK_FRAME_LINE.exec(line);
        if (!match) continue;
        const frame = match[1];
        if (HOOK_INTERNAL_FRAME_PREFIXES.some((p) => frame.startsWith(p))) continue;
        out.push(frame);
    }
    return out;
}

export type StackKind = "cronet" | "gms-cronet" | "httpengine";

const HTTPENGINE_CLASS_PREFIXES = [
    "android.net.http.internal.org.chromium.",
    "android.net.connectivity.org.chromium.",
];
const GMS_LOADER_MARKERS = ["com.google.android.gms", "CronetDynamite", "cronet_dynamite"];

/** jarjar'd platform copy = httpengine; copy from the GMS Dynamite loader = gms-cronet; else cronet. */
export function stackKindFor(className: string, loaderDescription: string, hasGmsSentinel: boolean = false): StackKind {
    if (HTTPENGINE_CLASS_PREFIXES.some((p) => className.startsWith(p))) return "httpengine";
    if (hasGmsSentinel) return "gms-cronet";
    const desc = loaderDescription || "";
    return GMS_LOADER_MARKERS.some((m) => desc.includes(m)) ? "gms-cronet" : "cronet";
}

/** What the agent remembers about one in-flight request (keyed by identityHashCode). */
export interface RequestRecord {
    req_id: string;
    url: string | null;
    method: string | null;
    frames: string[];
    kind: StackKind;
}

export const DEFAULT_LRU_CAPACITY = 4096;
/** Distinct thread names remembered per tid (meta() runs on every event). */
const THREAD_NAME_CACHE_CAPACITY = 256;

export function createReqIdCounter(): () => string {
    let n = 0;
    return () => `rc-${++n}`;
}

export interface EventMeta {
    thread: string | null;
    tid: number | null;
    t_ms: number;
}

type RequestContextPayload = RequestContextMessage;

function basePayload(event: RequestContextPayload["event"], req_id: string, meta: EventMeta): RequestContextPayload {
    return { contentType: "request_context", event, req_id, thread: meta.thread, tid: meta.tid, t_ms: meta.t_ms };
}

type CronetEvent = "start" | "redirect" | "response" | "end";
type EventFields = Partial<Omit<RequestContextPayload, "contentType" | "event" | "req_id">>;

/** `fields` may override `url` (e.g. a redirect target). */
export function requestPayload(event: CronetEvent, rec: RequestRecord, meta: EventMeta, fields: EventFields = {}): RequestContextPayload {
    return { ...basePayload(event, rec.req_id, meta), stack_kind: rec.kind, url: rec.url, ...fields };
}

export function buildWebviewLoadPayload(
    req_id: string, webviewId: string, url: string | null, method: string | null, frames: string[], meta: EventMeta,
): RequestContextPayload {
    return { ...basePayload("webview_load", req_id, meta), webview_id: webviewId, url, method, frames };
}

export function buildWebviewRequestPayload(
    req_id: string, webviewId: string, url: string | null, method: string | null, mainFrame: boolean | null, meta: EventMeta,
): RequestContextPayload {
    return { ...basePayload("webview_request", req_id, meta), webview_id: webviewId, url, method, main_frame: mainFrame };
}

export function javaString(value: any): string | null {
    return value === null || value === undefined ? null : `${value}`;
}

// --- Hook installer ---

export interface RequestContextDeps {
    emit: (payload: RequestContextPayload) => void;
    isShuttingDown: () => boolean;
    now: () => number;
    currentThreadId: () => number;
    registerTeardown: (label: string, fn: () => void) => void;
}

const defaultDeps: RequestContextDeps = {
    emit: (payload) => sendRequestContext(payload),
    isShuttingDown: () => _isShuttingDown,
    now: () => Date.now(),
    currentThreadId: () => Process.getCurrentThreadId(),
    registerTeardown: registerDetachTeardown,
};

export const CRONET_REQUEST_CLASS = "org.chromium.net.impl.CronetUrlRequest";
// CronetUrlRequest.<init> (Cronet 143 / GMS 157 / HttpEngine 150): 23 args, url at 1, method at 16.
const CRONET_CTOR_ARG_COUNT = 23;
const CTOR_URL_ARG = 1;
const CTOR_METHOD_ARG = 16;
/** Every Builder(Context) ends in this(createBuilderDelegate(context)), so this ctor sees each delegate. */
const ENGINE_BUILDER_CLASS = "org.chromium.net.CronetEngine$Builder";
const BUILDER_DELEGATE_ARG = "org.chromium.net.ICronetEngineBuilder";
/** Classes that exist only in the GMS Cronet Dynamite module. */
const GMS_SENTINEL_CLASSES = [
    "org.chromium.net.impl.NativeCronetProviderSentinel",
    "org.chromium.net.impl.CronetPccAuditLogger",
    "org.chromium.net.impl.CronetUmaRecorder",
];
const WEBVIEW_CLASS = "android.webkit.WebView";
const WEBVIEW_CLIENT_CLASS = "android.webkit.WebViewClient";
const WEBVIEW_ARG = "android.webkit.WebView";
const WEB_RESOURCE_REQUEST_ARG = "android.webkit.WebResourceRequest";
const TEARDOWN_LABEL = "java-request-context";

export type HookCounts = Record<StackKind | "webview", number>;

function zeroCounts(): HookCounts {
    return { "cronet": 0, "gms-cronet": 0, "httpengine": 0, "webview": 0 };
}

/** Module state: one installation per process. */
class RequestContextState {
    installed = false;
    teardownRegistered = false;
    readonly overloads: any[] = [];
    readonly hookedClassKeys = new Set<string>();
    /** WebViewClient (sub)classes reflected once and found not to declare shouldInterceptRequest. */
    readonly nonInterceptingClassKeys = new Set<string>();
    readonly requests = new LruMap<number, RequestRecord>(DEFAULT_LRU_CAPACITY);
    readonly nextReqId = createReqIdCounter();
    /** tids currently inside an app-subclass shouldInterceptRequest (suppresses the base-class double emit). */
    readonly interceptInFlight = new Set<number>();
    counts: HookCounts = zeroCounts();

    reset(): void {
        this.installed = false;
        this.overloads.length = 0;
        this.hookedClassKeys.clear();
        this.nonInterceptingClassKeys.clear();
        this.requests.clear();
        this.interceptInFlight.clear();
        this.counts = zeroCounts();
    }
}

const state = new RequestContextState();

/** Snapshot of how many classes were hooked per kind (for logs and tests). */
export function requestContextHookCounts(): HookCounts {
    return { ...state.counts };
}

/** Number of overloads currently swapped (for tests). */
export function requestContextHookedOverloadCount(): number {
    return state.overloads.length;
}

/** `result` is set only for "after" hooks. */
type HookHandler = (self: any, args: any[], result?: any) => void;

export type HookTiming = "before" | "after";

interface HookOptions {
    /** Only overloads accepted here are hooked (default: all). */
    filter?: (overload: any) => boolean;
    timing?: HookTiming;
}

/** The only place `.implementation` is assigned, so the detach teardown sees every hook. */
function swapImplementation(overload: any, implementation: (this: any, ...args: any[]) => any): void {
    overload.implementation = implementation;
    state.overloads.push(overload);
}

/** The original always runs unchanged; the handler is skipped on shutdown and its errors are swallowed. */
export function wrapOverload(
    overload: any, label: string, handler: HookHandler, deps: RequestContextDeps, timing: HookTiming = "before",
): void {
    const observe = (self: any, args: any[], result?: any): void => {
        if (deps.isShuttingDown()) return;
        try { handler(self, args, result); } catch (e) { devlog(`[request-context] ${label} hook error: ${e}`); }
    };
    swapImplementation(overload, function (this: any, ...args: any[]) {
        if (timing === "after") {
            const result = overload.apply(this, args);
            observe(this, args, result);
            return result;
        }
        observe(this, args);
        return overload.apply(this, args);
    });
}

/** Hook every overload of `klass[method]` accepted by `opts.filter`; returns how many were hooked. */
function hookOverloads(
    klass: any, method: string, label: string, handler: HookHandler, deps: RequestContextDeps,
    opts: HookOptions = {},
): number {
    const filter = opts.filter ?? (() => true);
    let overloads: any[];
    try { overloads = klass[method].overloads; } catch (e) {
        devlog(`[request-context] ${label}.${method} not present: ${e}`);
        return 0;
    }
    let hooked = 0;
    for (const overload of overloads) {
        if (!filter(overload)) {
            devlog(`[request-context] ${label}.${method}: skipping overload with ${overload.argumentTypes?.length} args`);
            continue;
        }
        wrapOverload(overload, `${label}.${method}`, handler, deps, opts.timing);
        hooked++;
    }
    return hooked;
}

/** Helpers bound to one bridge: identity, thread, stack. */
class JavaRuntime {
    private readonly system: any;
    private readonly thread: any;
    private readonly throwable: any;
    private readonly androidLog: any;
    private readonly threadNames = new LruMap<number, string | null>(THREAD_NAME_CACHE_CAPACITY);

    constructor(bridge: any, private readonly deps: RequestContextDeps) {
        this.system = bridge.use("java.lang.System");
        this.thread = bridge.use("java.lang.Thread");
        this.throwable = bridge.use("java.lang.Throwable");
        this.androidLog = bridge.use("android.util.Log");
    }

    identity(obj: any): number { return this.system.identityHashCode(obj); }

    /** The current Java stack: a fixed two JNI calls (probe + getStackTraceString), not two per frame; parsed in JS. */
    frames(): string[] {
        try {
            return parseStackTraceFrames(`${this.androidLog.getStackTraceString(this.throwable.$new())}`);
        } catch (_e) {
            return [];
        }
    }

    meta(): EventMeta {
        const tid = this.deps.currentThreadId();
        return { thread: this.threadName(tid), tid, t_ms: this.deps.now() };
    }

    private threadName(tid: number): string | null {
        const cached = this.threadNames.get(tid);
        if (cached !== undefined) return cached;
        let name: string | null = null;
        try { name = `${this.thread.currentThread().getName()}`; } catch (_e) { /* unnamed */ }
        this.threadNames.set(tid, name);
        return name;
    }
}

// --- Cronet / HttpEngine ----------------------------------------------------

function isVerifiedCtorShape(overload: any): boolean {
    const types = overload.argumentTypes || [];
    return types.length === CRONET_CTOR_ARG_COUNT
        && types[CTOR_URL_ARG]?.className === "java.lang.String"
        && types[CTOR_METHOD_ARG]?.className === "java.lang.String";
}

/** The record for `self`, created on first sight (requests built before attach still get a req_id). */
function recordFor(rt: JavaRuntime, self: any, kind: StackKind): RequestRecord {
    return recordForKey(rt.identity(self), kind);
}

function recordForKey(key: number, kind: StackKind): RequestRecord {
    let rec = state.requests.get(key);
    if (!rec) {
        rec = { req_id: state.nextReqId(), url: null, method: null, frames: [], kind };
        state.requests.set(key, rec);
    }
    return rec;
}

function hookCronetRequestClass(klass: any, kind: StackKind, rt: JavaRuntime, deps: RequestContextDeps): number {
    const label = `${kind}:CronetUrlRequest`;
    let n = hookOverloads(klass, "$init", label, (self, a) => {
        state.requests.set(rt.identity(self), {
            req_id: state.nextReqId(), url: javaString(a[CTOR_URL_ARG]),
            method: javaString(a[CTOR_METHOD_ARG]), frames: rt.frames(), kind,
        });
    }, deps, { filter: isVerifiedCtorShape });
    n += hookOverloads(klass, "start", label, (self) => {
        const rec = recordFor(rt, self, kind);
        if (rec.frames.length === 0) rec.frames = rt.frames();
        deps.emit(requestPayload("start", rec, rt.meta(), { method: rec.method, frames: rec.frames }));
    }, deps);
    n += hookCronetCallbacks(klass, kind, label, rt, deps);
    return n;
}

function hookCronetCallbacks(klass: any, kind: StackKind, label: string, rt: JavaRuntime, deps: RequestContextDeps): number {
    // onRedirectReceived(newLocation, status, statusText, headers, wasCached, protocol, proxy, bytes)
    let n = hookOverloads(klass, "onRedirectReceived", label, (self, a) => {
        deps.emit(requestPayload("redirect", recordFor(rt, self, kind), rt.meta(), { url: javaString(a[0]), status: a[1] ?? null }));
    }, deps);
    // onResponseStarted(status, statusText, headers, wasCached, protocol, proxy, bytes[, isProxied])
    n += hookOverloads(klass, "onResponseStarted", label, (self, a) => {
        const cached = typeof a[3] === "boolean" ? a[3] : null;
        deps.emit(requestPayload("response", recordFor(rt, self, kind), rt.meta(), {
            status: a[0] ?? null, negotiated_protocol: javaString(a[4]), cached,
        }));
    }, deps);
    n += hookOverloads(klass, "onSucceeded", label, (self) => emitEnd(rt, self, kind, null, deps), deps);
    n += hookOverloads(klass, "onCanceled", label, (self) => emitEnd(rt, self, kind, "canceled", deps), deps);
    // onError(errorCode, ..., String errorString, long bytes): the string's position varies by version
    n += hookOverloads(klass, "onError", label, (self, a) => {
        const error = a.find((x) => typeof x === "string") ?? null;
        emitEnd(rt, self, kind, error ?? `error ${a[0]}`, deps);
    }, deps);
    return n;
}

function emitEnd(rt: JavaRuntime, self: any, kind: StackKind, error: string | null, deps: RequestContextDeps): void {
    const key = rt.identity(self);
    const rec = recordForKey(key, kind);
    state.requests.delete(key);
    deps.emit(requestPayload("end", rec, rt.meta(), error === null ? {} : { error }));
}

function enumerateLoaders(bridge: any): any[] {
    try { return bridge.enumerateClassLoadersSync(); } catch (e) {
        devlog(`[request-context] loader enumeration failed: ${e}`);
        return [];
    }
}

/** Call `visit(className, definingLoader)` once per distinct class found in `loaders`. */
function forEachDistinctClass(
    rt: JavaRuntime, loaders: any[], classNames: string[], visit: (className: string, loader: any) => void,
): void {
    for (const loader of loaders) {
        for (const className of classNames) {
            let klass: any;
            try { klass = loader.loadClass(className); } catch (_e) { continue; }
            const key = `${className}@${rt.identity(klass)}`;
            if (state.hookedClassKeys.has(key)) continue;
            state.hookedClassKeys.add(key);
            let defining: any = null;
            try { defining = klass.getClassLoader(); } catch (_e) { /* boot */ }
            visit(className, defining ?? loader);
        }
    }
}

function loaderHasGmsSentinel(loader: any): boolean {
    for (const sentinel of GMS_SENTINEL_CLASSES) {
        try { loader.loadClass(sentinel); return true; } catch (_e) { /* not this loader */ }
    }
    return false;
}

/** Hook the `org.chromium.net.impl.CronetUrlRequest` defined by `loader` (embedded or GMS); 1 if newly hooked. */
function hookCronetRequestIn(bridge: any, rt: JavaRuntime, deps: RequestContextDeps, phase: string, loader: any): number {
    let desc = "";
    try { desc = `${loader}`; } catch (_e) { /* undescribable */ }
    const kind = stackKindFor(CRONET_REQUEST_CLASS, desc, loaderHasGmsSentinel(loader));
    try {
        const klass = bridge.ClassFactory.get(loader).use(CRONET_REQUEST_CLASS);
        const hooked = hookCronetRequestClass(klass, kind, rt, deps) > 0;
        if (hooked) state.counts[kind]++;
        devlog(`[request-context] ${phase}: hooked ${kind} CronetUrlRequest in ${desc.slice(0, 200)}`);
        return hooked ? 1 : 0;
    } catch (e) {
        devlog(`[request-context] ${phase}: ${kind} CronetUrlRequest not hooked: ${e}`);
    }
    return 0;
}

/** Each new builder's delegate may come from a new loader (e.g. GMS Dynamite) with its own Cronet copy. */
function hookBuilderDelegateCtorIn(bridge: any, rt: JavaRuntime, deps: RequestContextDeps, loader: any): void {
    try {
        const klass = bridge.ClassFactory.get(loader).use(ENGINE_BUILDER_CLASS);
        hookOverloads(klass, "$init", ENGINE_BUILDER_CLASS, (_self, a) => {
            probeDelegateLoader(bridge, rt, deps, a[0]);
        }, deps, { filter: isBuilderDelegateCtor, timing: "after" });
    } catch (e) {
        devlog(`[request-context] ${ENGINE_BUILDER_CLASS}.<init> not hooked: ${e}`);
    }
}

function isBuilderDelegateCtor(overload: any): boolean {
    const types = overload.argumentTypes || [];
    return types.length === 1 && types[0]?.className === BUILDER_DELEGATE_ARG;
}

/** Install-time discovery: enumerate the loaders once, probe each for the request class and the builder. */
function discoverLoaderClasses(bridge: any, rt: JavaRuntime, deps: RequestContextDeps): void {
    const classNames = [CRONET_REQUEST_CLASS, ENGINE_BUILDER_CLASS];
    forEachDistinctClass(rt, enumerateLoaders(bridge), classNames, (className, loader) => {
        if (className === CRONET_REQUEST_CLASS) hookCronetRequestIn(bridge, rt, deps, "install", loader);
        else hookBuilderDelegateCtorIn(bridge, rt, deps, loader);
    });
}

function definingLoaderOf(obj: any): any | null {
    if (obj === null || obj === undefined) return null;
    try { return obj.getClass().getClassLoader() ?? null; } catch (_e) { return null; }
}

/** Runs in a hook: probe only the delegate's loader, never enumerate (that suspends every ART thread). */
function probeDelegateLoader(bridge: any, rt: JavaRuntime, deps: RequestContextDeps, delegate: any): void {
    const loader = definingLoaderOf(delegate);
    if (loader === null) return;
    let added = 0;
    forEachDistinctClass(rt, [loader], [CRONET_REQUEST_CLASS], (_className, defining) => {
        added += hookCronetRequestIn(bridge, rt, deps, "builder delegate", defining);
    });
    if (added > 0) logCounts("new Cronet loader");
}

/** HttpEngine's jarjar'd copy lives in the boot loader; probe both known prefixes. */
function hookHttpEngine(bridge: any, rt: JavaRuntime, deps: RequestContextDeps): void {
    for (const prefix of HTTPENGINE_CLASS_PREFIXES) {
        const className = `${prefix}net.impl.CronetUrlRequest`;
        if (state.hookedClassKeys.has(className)) continue;
        let klass: any;
        try { klass = bridge.use(className); } catch (_e) {
            devlog(`[request-context] HttpEngine class absent: ${className}`);
            continue;
        }
        state.hookedClassKeys.add(className);
        if (hookCronetRequestClass(klass, "httpengine", rt, deps) > 0) state.counts.httpengine++;
    }
}

// --- WebView ------------------------------------------------------------------

function webviewLoadHandler(rt: JavaRuntime, deps: RequestContextDeps, method: string | null): HookHandler {
    return (self, a) => {
        deps.emit(buildWebviewLoadPayload(
            state.nextReqId(), `${rt.identity(self)}`, javaString(a[0]), method, rt.frames(), rt.meta(),
        ));
    };
}

function emitWebviewRequest(rt: JavaRuntime, deps: RequestContextDeps, view: any, req: any): void {
    if (req === null || req === undefined) return;
    const webviewId = view === null || view === undefined ? "" : `${rt.identity(view)}`;
    let mainFrame: boolean | null = null;
    try { mainFrame = !!req.isForMainFrame(); } catch (_e) { /* unknown */ }
    deps.emit(buildWebviewRequestPayload(
        state.nextReqId(), webviewId, javaString(req.getUrl()), javaString(req.getMethod()), mainFrame, rt.meta(),
    ));
}

/** Base WebViewClient.shouldInterceptRequest: WebView calls it for every request, main frame included. */
function hookBaseInterceptRequest(bridge: any, rt: JavaRuntime, deps: RequestContextDeps): number {
    const overload = bridge.use(WEBVIEW_CLIENT_CLASS).shouldInterceptRequest.overload(WEBVIEW_ARG, WEB_RESOURCE_REQUEST_ARG);
    wrapOverload(overload, "WebViewClient.shouldInterceptRequest", (_self, a) => {
        if (state.interceptInFlight.has(deps.currentThreadId())) return; // the subclass hook already emitted
        emitWebviewRequest(rt, deps, a[0], a[1]);
    }, deps);
    return 1;
}

/** Does `cls` itself declare shouldInterceptRequest(WebView, WebResourceRequest)? */
function declaresInterceptRequest(cls: any): boolean {
    const methods = cls.getDeclaredMethods();
    for (let i = 0; i < methods.length; i++) {
        const m = methods[i];
        if (`${m.getName()}` !== "shouldInterceptRequest") continue;
        const params = m.getParameterTypes();
        if (params.length === 2 && `${params[0].getName()}` === WEBVIEW_ARG && `${params[1].getName()}` === WEB_RESOURCE_REQUEST_ARG) return true;
    }
    return false;
}

/**
 * Hook the override in the client's class hierarchy (below WebViewClient), once
 * per class; a class found not to declare it is remembered and never reflected again.
 */
function hookClientOverride(bridge: any, rt: JavaRuntime, deps: RequestContextDeps, client: any): void {
    let cls = client.getClass();
    while (cls !== null && `${cls.getName()}` !== WEBVIEW_CLIENT_CLASS) {
        const name = `${cls.getName()}`;
        const key = `client:${name}@${rt.identity(cls)}`;
        if (state.hookedClassKeys.has(key)) return;
        if (state.nonInterceptingClassKeys.has(key)) {
            cls = cls.getSuperclass();
            continue;
        }
        if (declaresInterceptRequest(cls)) {
            state.hookedClassKeys.add(key);
            const klass = bridge.ClassFactory.get(cls.getClassLoader()).use(name);
            wrapInterceptOverride(klass.shouldInterceptRequest.overload(WEBVIEW_ARG, WEB_RESOURCE_REQUEST_ARG), name, rt, deps);
            devlog(`[request-context] hooked ${name}.shouldInterceptRequest`);
            return;
        }
        state.nonInterceptingClassKeys.add(key);
        cls = cls.getSuperclass();
    }
}

function wrapInterceptOverride(overload: any, name: string, rt: JavaRuntime, deps: RequestContextDeps): void {
    // Not a wrapOverload: it must bracket the original (in-flight marker), but it
    // still goes through swapImplementation so the teardown reverts it.
    swapImplementation(overload, function (this: any, ...args: any[]) {
        if (deps.isShuttingDown()) return overload.apply(this, args);
        const tid = deps.currentThreadId();
        const outermost = !state.interceptInFlight.has(tid);
        if (outermost) {
            try { emitWebviewRequest(rt, deps, args[0], args[1]); } catch (e) { devlog(`[request-context] ${name} hook error: ${e}`); }
            state.interceptInFlight.add(tid);
        }
        try { return overload.apply(this, args); } finally { if (outermost) state.interceptInFlight.delete(tid); }
    });
}

function hookWebView(bridge: any, rt: JavaRuntime, deps: RequestContextDeps): void {
    const webView = bridge.use(WEBVIEW_CLASS);
    // The two loadUrl overloads do not call each other; both are hooked.
    let n = hookOverloads(webView, "loadUrl", "WebView", webviewLoadHandler(rt, deps, "GET"), deps);
    n += hookOverloads(webView, "postUrl", "WebView", webviewLoadHandler(rt, deps, "POST"), deps);
    // loadDataWithBaseURL never fetches its base URL: no method, so the host registers
    // the WebView owner without indexing the base URL as a request.
    n += hookOverloads(webView, "loadDataWithBaseURL", "WebView", webviewLoadHandler(rt, deps, null), deps);
    n += hookBaseInterceptRequest(bridge, rt, deps);
    n += hookOverloads(webView, "setWebViewClient", "WebView", (_self, a) => {
        if (a[0]) hookClientOverride(bridge, rt, deps, a[0]);
    }, deps);
    if (n > 0) state.counts.webview++;
}

// --- install / revert ---------------------------------------------------------

function logCounts(reason: string): void {
    const c = state.counts;
    log(`[request-context] ${reason}: Java request hooks on cronet=${c.cronet} gms-cronet=${c["gms-cronet"]} `
        + `httpengine=${c.httpengine} webview=${c.webview} class(es); ${state.overloads.length} overload(s)`);
}

function runStep(label: string, fn: () => void): void {
    try { fn(); } catch (e) { devlog(`[request-context] ${label} not hooked: ${e}`); }
}

/** Once per process. The teardown is registered before `perform` so a partial install is still reverted. */
export function installJavaRequestContextHooks(bridge: any = Java, deps: RequestContextDeps = defaultDeps): void {
    if (state.installed) return;
    if (!bridge || !bridge.available) {
        devlog("[request-context] Java bridge unavailable; per-request hooks skipped");
        return;
    }
    state.installed = true;
    if (!state.teardownRegistered) {
        deps.registerTeardown(TEARDOWN_LABEL, () => revertJavaRequestContextHooks(bridge));
        state.teardownRegistered = true;
    }
    bridge.perform(() => {
        let rt: JavaRuntime;
        try {
            rt = new JavaRuntime(bridge, deps);
        } catch (e) {
            // frida-java-bridge can fail early in a cold-starting app; skip rather than throw.
            devlog(`[request-context] Java runtime not ready; per-request hooks skipped: ${e}`);
            return;
        }
        runStep("cronet loaders + engine builder", () => discoverLoaderClasses(bridge, rt, deps));
        runStep("httpengine", () => hookHttpEngine(bridge, rt, deps));
        runStep("webview", () => hookWebView(bridge, rt, deps));
        logCounts("installed");
    });
}

/** Revert every swapped overload and clear the once-per-process guard. */
export function revertJavaRequestContextHooks(bridge: any = Java): void {
    if (state.overloads.length === 0) { state.reset(); return; }
    const overloads = state.overloads.slice();
    revertJavaOverloads(bridge, overloads, "request-context");
    state.reset();
    state.teardownRegistered = false; // runDetachTeardowns empties the registry
    devlog(`[request-context] reverted ${overloads.length} Java overload(s)`);
}
