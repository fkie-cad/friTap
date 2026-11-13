// Unit tests for shared/java_request_context.ts.
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";

import {
    requestContextHooksWanted, parseStackTraceFrames, stackKindFor, createReqIdCounter, requestPayload,
    buildWebviewLoadPayload, buildWebviewRequestPayload, installJavaRequestContextHooks,
    revertJavaRequestContextHooks, requestContextHookCounts, requestContextHookedOverloadCount,
    CRONET_REQUEST_CLASS, MAX_REQUEST_FRAMES, RequestRecord, RequestContextDeps, EventMeta,
} from "./java_request_context.js";

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

test("requestContextHooksWanted: only attribute_sdk && pcap && !pairip_safe && !quic_only", () => {
    for (let mask = 0; mask < 16; mask++) {
        const cfg = {
            attribute_sdk: !!(mask & 1), pcap_enabled: !!(mask & 2),
            pairip_safe: !!(mask & 4), quic_only: !!(mask & 8),
        };
        assert.equal(requestContextHooksWanted(cfg), mask === 3, JSON.stringify(cfg));
    }
});

/** Log.getStackTraceString output for a fresh Throwable whose stack is `frames`. */
function traceText(...frames: string[]): string {
    return ["java.lang.Throwable", ...frames.map((f) => `\tat ${f}`), ""].join("\n");
}

test("parseStackTraceFrames: class.method per frame, header skipped", () => {
    assert.deepEqual(parseStackTraceFrames(traceText("a.B.c(B.java:10)", "d.E.f(E.java:2)")), ["a.B.c", "d.E.f"]);
    assert.deepEqual(parseStackTraceFrames("java.lang.Throwable: probe\n"), []);
});

test("parseStackTraceFrames: Native Method, Unknown Source, lambda/synthetic and inner classes", () => {
    const trace = traceText(
        "dalvik.system.VMRuntime.newNonMovableArray(Native Method)",
        "com.sdk.a.b(Unknown Source:4)",
        "com.sdk.Alpha.lambda$fetch$0(Alpha.java:12)",
        "com.sdk.Alpha.access$000(Alpha.java)",
        "com.sdk.Alpha$Inner$1.run(Alpha.java:40)",
        "com.sdk.Alpha$$ExternalSyntheticLambda0.run(D8$$SyntheticClass)",
    );
    assert.deepEqual(parseStackTraceFrames(trace), [
        "dalvik.system.VMRuntime.newNonMovableArray", "com.sdk.a.b", "com.sdk.Alpha.lambda$fetch$0",
        "com.sdk.Alpha.access$000", "com.sdk.Alpha$Inner$1.run", "com.sdk.Alpha$$ExternalSyntheticLambda0.run",
    ]);
});

test("parseStackTraceFrames: skips hook-internal frames, CRLF, Caused by / ... more; caps", () => {
    const trace = traceText(
        "java.lang.Throwable.<init>(Throwable.java:1)", "android.util.Log.getStackTraceString(Log.java:2)",
        "dalvik.system.VMStack.getThreadStackTrace(Native Method)", "x.Y.z(Y.java:3)",
    ).replace(/\n/g, "\r\n") + "Caused by: java.io.IOException\n\t... 4 more\n";
    assert.deepEqual(parseStackTraceFrames(trace), ["x.Y.z"]);
    const many = traceText(...Array.from({ length: 50 }, (_, i) => `k.C${i}.m(C.java:1)`));
    assert.equal(parseStackTraceFrames(many).length, MAX_REQUEST_FRAMES);
    assert.equal(parseStackTraceFrames(many, 3).length, 3);
    assert.deepEqual(parseStackTraceFrames(null), []);
    assert.deepEqual(parseStackTraceFrames(""), []);
});

test("stackKindFor classifies httpengine / gms-cronet / cronet", () => {
    assert.equal(stackKindFor("android.net.http.internal.org.chromium.net.impl.CronetUrlRequest", ""), "httpengine");
    assert.equal(stackKindFor("android.net.connectivity.org.chromium.net.impl.CronetUrlRequest", ""), "httpengine");
    assert.equal(stackKindFor(CRONET_REQUEST_CLASS,
        "dalvik.system.DelegateLastClassLoader[/data/app/x/com.google.android.gms-1/split_CronetDynamite_installtime.apk]"), "gms-cronet");
    assert.equal(stackKindFor(CRONET_REQUEST_CLASS, "loader[CronetDynamite]"), "gms-cronet");
    assert.equal(stackKindFor(CRONET_REQUEST_CLASS, "dalvik.system.PathClassLoader[app]", true), "gms-cronet");
    assert.equal(stackKindFor(CRONET_REQUEST_CLASS, "dalvik.system.PathClassLoader[/data/app/com.example/base.apk]"), "cronet");
});

test("createReqIdCounter is monotonic rc-<n>", () => {
    const next = createReqIdCounter();
    assert.deepEqual([next(), next(), next()], ["rc-1", "rc-2", "rc-3"]);
});

const META: EventMeta = { thread: "alpha-worker", tid: 42, t_ms: 1000 };
const REC: RequestRecord = { req_id: "rc-7", url: "https://h/p", method: "GET", frames: ["a.B.c"], kind: "cronet" };

test("payload builders use the messages.ts field names", () => {
    assert.deepEqual(requestPayload("start", REC, META, { method: REC.method, frames: REC.frames }), {
        contentType: "request_context", event: "start", req_id: "rc-7", thread: "alpha-worker", tid: 42, t_ms: 1000,
        stack_kind: "cronet", url: "https://h/p", method: "GET", frames: ["a.B.c"],
    });
    const redirect = requestPayload("redirect", REC, META, { url: "https://h/q", status: 302 });
    assert.equal(redirect.event, "redirect");
    assert.equal(redirect.url, "https://h/q", "the event's url overrides the record's");
    assert.equal(redirect.status, 302);
    const response = requestPayload("response", REC, META, { status: 200, negotiated_protocol: "h2", cached: false });
    assert.equal(response.negotiated_protocol, "h2");
    assert.equal(response.cached, false);
    assert.equal(response.status, 200);
    assert.equal(response.url, "https://h/p");
    assert.ok(!("protocol" in response), "`protocol` is reserved by sendWithProtocol");
    assert.deepEqual(requestPayload("end", REC, META), {
        contentType: "request_context", event: "end", req_id: "rc-7", thread: "alpha-worker", tid: 42, t_ms: 1000,
        stack_kind: "cronet", url: "https://h/p",
    });
    assert.equal(requestPayload("end", REC, META, { error: "net::ERR_X" }).error, "net::ERR_X");
    const load = buildWebviewLoadPayload("rc-8", "123", "https://w/", "POST", ["x.Y.z"], META);
    assert.deepEqual([load.event, load.webview_id, load.method, load.frames], ["webview_load", "123", "POST", ["x.Y.z"]]);
    const req = buildWebviewRequestPayload("rc-9", "123", "https://w/a.js", "GET", false, META);
    assert.deepEqual([req.event, req.webview_id, req.main_frame], ["webview_request", "123", false]);
});

// ---------------------------------------------------------------------------
// Fake Java bridge
// ---------------------------------------------------------------------------

interface FakeOverload {
    argumentTypes: { className: string }[];
    implementation: any;
    calls: any[][];
    apply: (self: any, args: any[]) => any;
}

function fakeOverload(argTypes: string[], ret: any = "orig"): FakeOverload {
    const ov: FakeOverload = {
        argumentTypes: argTypes.map((className) => ({ className })),
        implementation: null,
        calls: [],
        apply(_self: any, args: any[]) { ov.calls.push(args); return ret; },
    };
    return ov;
}

function method(...overloads: FakeOverload[]): any {
    return { overloads, overload: () => overloads[0] };
}

const CTOR_TYPES = Array.from({ length: 23 }, (_, i) => (i === 1 || i === 16 ? "java.lang.String" : "x"));

function fakeCronetClass(): any {
    return {
        $init: method(fakeOverload(CTOR_TYPES), fakeOverload(["a", "b"])),
        start: method(fakeOverload([])),
        onRedirectReceived: method(fakeOverload(Array(8).fill("x"))),
        onResponseStarted: method(fakeOverload(Array(7).fill("x")), fakeOverload(Array(8).fill("x"))),
        onSucceeded: method(fakeOverload(["long"])),
        onCanceled: method(fakeOverload([])),
        onError: method(
            fakeOverload(["int", "int", "int", "int", "java.lang.String", "long"]),   // 143/150/157
            fakeOverload(["int", "int", "int", "java.lang.String", "long"]),          // older Cronet
            fakeOverload(["int", "int", "int"]),                                      // no error string
        ),
    };
}

/** Call a hooked overload's implementation as ART would. */
function invoke(ov: FakeOverload, self: any, ...args: any[]): any {
    assert.equal(typeof ov.implementation, "function", "overload is hooked");
    return ov.implementation.apply(self, args);
}

function makeBridge() {
    const embedded = fakeCronetClass();
    const httpengine = fakeCronetClass();
    const builder = {
        $init: method(fakeOverload(["org.chromium.net.ICronetEngineBuilder"]), fakeOverload(["android.content.Context"])),
    };
    const webView = {
        loadUrl: method(fakeOverload(["java.lang.String"]), fakeOverload(["java.lang.String", "java.util.Map"])),
        postUrl: method(fakeOverload(["java.lang.String", "[B"])),
        loadDataWithBaseURL: method(fakeOverload(Array(5).fill("java.lang.String"))),
        setWebViewClient: method(fakeOverload(["android.webkit.WebViewClient"])),
    };
    const baseIntercept = fakeOverload(["android.webkit.WebView", "android.webkit.WebResourceRequest"], null);
    const subIntercept = fakeOverload(["android.webkit.WebView", "android.webkit.WebResourceRequest"], null);
    let loaders: any[] = [];
    const classObj = (id: number, name: string): any => ({ id, getClassLoader: () => appLoader, getName: () => name });
    const appLoader: any = {
        id: 800,
        toString: () => "dalvik.system.PathClassLoader[/data/app/com.example/base.apk]",
        loadClass(name: string) {
            if (name === CRONET_REQUEST_CLASS) return classObj(900, name);
            if (name === "org.chromium.net.CronetEngine$Builder") return classObj(901, name);
            throw new Error("ClassNotFoundException " + name);
        },
    };
    loaders = [appLoader];
    const byName: Record<string, any> = {
        [CRONET_REQUEST_CLASS]: embedded,
        "org.chromium.net.CronetEngine$Builder": builder,
        "com.app.Client": { shouldInterceptRequest: method(subIntercept) },
    };
    const calls = { loadClass: 0, threadName: 0, enumerate: 0 };
    const baseLoadClass = appLoader.loadClass;
    appLoader.loadClass = (name: string) => { calls.loadClass++; return baseLoadClass(name); };
    const bridge = {
        available: true,
        perform: (fn: () => void) => fn(),
        enumerateClassLoadersSync: () => { calls.enumerate++; return loaders; },
        ClassFactory: { get: (_loader: any) => ({ use: (n: string) => byName[n] }) },
        use(name: string): any {
            switch (name) {
                case "java.lang.System": return { identityHashCode: (o: any) => o.id };
                case "java.lang.Thread": return { currentThread: () => { calls.threadName++; return { getName: () => "alpha-worker" }; } };
                case "java.lang.Throwable": return { $new: () => ({ probe: true }) };
                case "android.util.Log": return {
                    getStackTraceString: (t: any) => (t?.probe ? traceText("com.sdk.Alpha.fetch(Alpha.java:7)") : ""),
                };
                case "android.net.http.internal.org.chromium.net.impl.CronetUrlRequest": return httpengine;
                case "android.webkit.WebView": return webView;
                case "android.webkit.WebViewClient": return { shouldInterceptRequest: method(baseIntercept) };
                default: throw new Error("ClassNotFoundException " + name);
            }
        },
    };
    return {
        bridge, embedded, httpengine, builder, webView, baseIntercept, subIntercept, appLoader, calls,
        setLoaders: (l: any[]) => { loaders = l; },
    };
}

function makeDeps() {
    const emitted: any[] = [];
    const teardowns: { label: string; fn: () => void }[] = [];
    let shuttingDown = false;
    let tid = 7;
    const deps: RequestContextDeps = {
        emit: (p) => emitted.push(p),
        isShuttingDown: () => shuttingDown,
        now: () => 1234,
        currentThreadId: () => tid,
        registerTeardown: (label, fn) => teardowns.push({ label, fn }),
    };
    return {
        deps, emitted, teardowns,
        setShuttingDown: (v: boolean) => { shuttingDown = v; },
        setTid: (v: number) => { tid = v; },
    };
}

function freshInstall() {
    revertJavaRequestContextHooks({ available: true, perform: (fn: () => void) => fn() });
    const fake = makeBridge();
    const d = makeDeps();
    installJavaRequestContextHooks(fake.bridge, d.deps);
    return { ...fake, ...d };
}

function ctorArgs(url: string, method: string): any[] {
    const a: any[] = Array(23).fill(null);
    a[1] = url;
    a[16] = method;
    return a;
}

// ---------------------------------------------------------------------------
// Installer
// ---------------------------------------------------------------------------

test("install hooks embedded Cronet, HttpEngine and WebView; registers the teardown first", () => {
    const f = freshInstall();
    assert.deepEqual(requestContextHookCounts(), { "cronet": 1, "gms-cronet": 0, "httpengine": 1, "webview": 1 });
    assert.equal(f.teardowns.length, 1);
    assert.equal(f.teardowns[0].label, "java-request-context");
    assert.equal(f.embedded.$init.overloads[1].implementation, null, "non-23-arg ctor shape is skipped");
    assert.equal(typeof f.builder.$init.overloads[0].implementation, "function");
    assert.equal(f.builder.$init.overloads[1].implementation, null, "only the delegate ctor is hooked");
    // once per process
    installJavaRequestContextHooks(f.bridge, f.deps);
    assert.equal(f.teardowns.length, 1);
});

test("install skips quietly when the Java runtime classes cannot be resolved", () => {
    revertJavaRequestContextHooks({ available: true, perform: (fn: () => void) => fn() });
    const fake = makeBridge();
    const d = makeDeps();
    const baseUse = fake.bridge.use.bind(fake.bridge);
    fake.bridge.use = (name: string) => {
        if (name === "java.lang.System") throw new Error("access violation accessing 0x0");
        return baseUse(name);
    };
    assert.doesNotThrow(() => installJavaRequestContextHooks(fake.bridge, d.deps));
    assert.equal(requestContextHookedOverloadCount(), 0);
});

test("Cronet lifecycle emits start/redirect/response/end with one req_id and drops the record", () => {
    const f = freshInstall();
    const req = { id: 55 };
    invoke(f.embedded.$init.overloads[0], req, ...ctorArgs("https://h/a", "POST"));
    invoke(f.embedded.start.overloads[0], req);
    invoke(f.embedded.onRedirectReceived.overloads[0], req, "https://h/b", 302, "Found", [], false, "h2", "", 0);
    invoke(f.embedded.onResponseStarted.overloads[1], req, 200, "OK", [], true, "h3", "", 10, false);
    invoke(f.embedded.onSucceeded.overloads[0], req, 10);
    const events = f.emitted.map((p) => p.event);
    assert.deepEqual(events, ["start", "redirect", "response", "end"]);
    assert.equal(new Set(f.emitted.map((p) => p.req_id)).size, 1);
    const start = f.emitted[0];
    assert.deepEqual([start.url, start.method, start.stack_kind, start.thread, start.tid, start.t_ms],
        ["https://h/a", "POST", "cronet", "alpha-worker", 7, 1234]);
    assert.deepEqual(start.frames, ["com.sdk.Alpha.fetch"]);
    assert.equal(f.emitted[1].url, "https://h/b");
    assert.deepEqual([f.emitted[2].status, f.emitted[2].negotiated_protocol, f.emitted[2].cached], [200, "h3", true]);
    assert.ok(!("error" in f.emitted[3]));
    // a later callback on the same object gets a NEW req_id (record was dropped)
    invoke(f.embedded.onCanceled.overloads[0], req);
    assert.notEqual(f.emitted[4].req_id, f.emitted[0].req_id);
    assert.equal(f.emitted[4].error, "canceled");
    // every hook still ran the original
    assert.equal(f.embedded.start.overloads[0].calls.length, 1);
});

test("onError ends with the error string; HttpEngine is tagged httpengine", () => {
    const f = freshInstall();
    const req = { id: 77 };
    invoke(f.httpengine.$init.overloads[0], req, ...ctorArgs("https://e/", "GET"));
    invoke(f.httpengine.onError.overloads[0], req, 11, -2, 0, 0, "net::ERR_FAILED", 0);
    assert.equal(f.emitted[0].event, "end");
    assert.equal(f.emitted[0].stack_kind, "httpengine");
    assert.equal(f.emitted[0].url, "https://e/");
    assert.equal(f.emitted[0].error, "net::ERR_FAILED");
});

test("onError picks the String argument wherever it sits (older 5-arg shape)", () => {
    const f = freshInstall();
    const req = { id: 78 };
    invoke(f.embedded.$init.overloads[0], req, ...ctorArgs("https://o/", "GET"));
    invoke(f.embedded.onError.overloads[1], req, 11, -2, 0, "net::ERR_TIMED_OUT", 4096);
    assert.equal(f.emitted.at(-1).event, "end");
    assert.equal(f.emitted.at(-1).error, "net::ERR_TIMED_OUT");
});

test("onError without a String parameter falls back to the error code", () => {
    const f = freshInstall();
    const req = { id: 79 };
    invoke(f.embedded.onError.overloads[2], req, 11, -2, 0);
    assert.equal(f.emitted.at(-1).event, "end");
    assert.equal(f.emitted.at(-1).error, "error 11");
});

test("hooks call the original and emit nothing during shutdown", () => {
    const f = freshInstall();
    f.setShuttingDown(true);
    const req = { id: 1 };
    assert.equal(invoke(f.embedded.$init.overloads[0], req, ...ctorArgs("https://h/", "GET")), "orig");
    assert.equal(invoke(f.embedded.start.overloads[0], req), "orig");
    invoke(f.webView.loadUrl.overloads[0], { id: 3 }, "https://w/");
    assert.equal(invoke(f.baseIntercept, {}, { id: 3 }, { getUrl: () => "u", getMethod: () => "GET", isForMainFrame: () => true }), null);
    assert.equal(f.emitted.length, 0);
    assert.equal(f.embedded.$init.overloads[0].calls.length, 1);
    assert.equal(f.embedded.start.overloads[0].calls.length, 1);
    assert.equal(f.webView.loadUrl.overloads[0].calls.length, 1);
});

test("a handler error never changes app behaviour", () => {
    const f = freshInstall();
    f.deps.emit = () => { throw new Error("send failed"); };
    assert.equal(invoke(f.embedded.start.overloads[0], { id: 9 }), "orig");
    assert.equal(f.embedded.start.overloads[0].calls.length, 1);
});

test("WebView load + intercept emit webview_load / webview_request", () => {
    const f = freshInstall();
    const view = { id: 314 };
    invoke(f.webView.postUrl.overloads[0], view, "https://w/form", []);
    const req = { getUrl: () => "https://w/app.js", getMethod: () => "GET", isForMainFrame: () => false };
    invoke(f.baseIntercept, {}, view, req);
    assert.deepEqual(f.emitted.map((p) => p.event), ["webview_load", "webview_request"]);
    assert.deepEqual([f.emitted[0].webview_id, f.emitted[0].method, f.emitted[0].url], ["314", "POST", "https://w/form"]);
    assert.deepEqual(f.emitted[0].frames, ["com.sdk.Alpha.fetch"]);
    assert.deepEqual([f.emitted[1].webview_id, f.emitted[1].main_frame, f.emitted[1].url], ["314", false, "https://w/app.js"]);
    assert.notEqual(f.emitted[0].req_id, f.emitted[1].req_id);
});

test("loadDataWithBaseURL emits webview_load without a method", () => {
    const f = freshInstall();
    invoke(f.webView.loadDataWithBaseURL.overloads[0], { id: 315 }, "https://base/", "<p>x</p>", "text/html", "utf-8", null);
    assert.deepEqual(f.emitted.map((p) => [p.event, p.webview_id, p.url, p.method]),
        [["webview_load", "315", "https://base/", null]]);
});

function fakeClientClass(declares: boolean): any {
    const params = [{ getName: () => "android.webkit.WebView" }, { getName: () => "android.webkit.WebResourceRequest" }];
    const declared = declares ? [{ getName: () => "shouldInterceptRequest", getParameterTypes: () => params }] : [];
    const base = { getName: () => "android.webkit.WebViewClient" };
    return { id: 500, getName: () => "com.app.Client", getDeclaredMethods: () => declared,
        getSuperclass: () => base, getClassLoader: () => ({}) };
}

test("setWebViewClient hooks a declaring subclass once and suppresses the base double emit", () => {
    const f = freshInstall();
    const client = { getClass: () => fakeClientClass(true) };
    invoke(f.webView.setWebViewClient.overloads[0], { id: 1 }, client);
    invoke(f.webView.setWebViewClient.overloads[0], { id: 1 }, client);
    assert.equal(typeof f.subIntercept.implementation, "function");
    const before = requestContextHookedOverloadCount();
    // subclass override calls super -> base hook must not emit a second event
    const req = { getUrl: () => "https://w/", getMethod: () => "GET", isForMainFrame: () => true };
    f.subIntercept.apply = (_self: any, args: any[]) => invoke(f.baseIntercept, {}, ...args);
    invoke(f.subIntercept, {}, { id: 1 }, req);
    assert.equal(f.emitted.length, 1);
    assert.equal(f.emitted[0].main_frame, true);
    assert.equal(requestContextHookedOverloadCount(), before, "hooked once per class");
});

test("revert nulls every hooked overload, clears the guard and allows a reinstall", () => {
    const f = freshInstall();
    const hooked = requestContextHookedOverloadCount();
    assert.ok(hooked > 10);
    const all: FakeOverload[] = [
        ...Object.values(f.embedded).flatMap((m: any) => m.overloads),
        ...Object.values(f.httpengine).flatMap((m: any) => m.overloads),
        ...Object.values(f.webView).flatMap((m: any) => m.overloads),
        ...f.builder.$init.overloads, f.baseIntercept,
    ];
    assert.equal(all.filter((o) => typeof o.implementation === "function").length, hooked);
    f.teardowns[0].fn();
    assert.equal(all.filter((o) => o.implementation !== null).length, 0);
    assert.equal(requestContextHookedOverloadCount(), 0);
    assert.deepEqual(requestContextHookCounts(), { "cronet": 0, "gms-cronet": 0, "httpengine": 0, "webview": 0 });
    installJavaRequestContextHooks(f.bridge, f.deps);
    assert.equal(requestContextHookedOverloadCount(), hooked);
    assert.equal(f.teardowns.length, 2, "teardown re-registered after the registry was drained");
});

function fakeGmsLoader(gmsClass: any): any {
    const gmsLoader: any = {
        id: 810,
        toString: () => "dalvik.system.DelegateLastClassLoader[module com.google.android.gms.cronet_dynamite]",
        loadClass(name: string) {
            if (name === CRONET_REQUEST_CLASS) return { id: 950, getClassLoader: () => gmsLoader };
            if (name === "org.chromium.net.impl.CronetUmaRecorder") return { id: 951 };
            throw new Error("CNFE");
        },
    };
    return gmsLoader;
}

/** Route ClassFactory.get(gmsLoader) to `gmsClass`. */
function serveGmsClass(f: ReturnType<typeof freshInstall>, gmsLoader: any, gmsClass: any): void {
    const baseGet = f.bridge.ClassFactory.get;
    f.bridge.ClassFactory.get = (l: any) => (l === gmsLoader ? { use: () => gmsClass } : baseGet(l));
}

/** An object whose class was defined by `loader`. */
function definedBy(loader: any): any {
    return { getClass: () => ({ getClassLoader: () => loader }) };
}

test("install enumerates the class loaders once for the request class and the engine builder", () => {
    const f = freshInstall();
    assert.equal(f.calls.enumerate, 1);
    assert.equal(typeof f.builder.$init.overloads[0].implementation, "function");
    assert.equal(requestContextHookCounts().cronet, 1);
});

test("a builder delegate from a new loader hooks that loader's GMS copy without enumerating", () => {
    const f = freshInstall();
    const gmsClass = fakeCronetClass();
    const gmsLoader = fakeGmsLoader(gmsClass);
    f.setLoaders([f.appLoader, gmsLoader]);
    serveGmsClass(f, gmsLoader, gmsClass);
    const enumerated = f.calls.enumerate;
    const delegate = definedBy(gmsLoader);
    assert.equal(invoke(f.builder.$init.overloads[0], {}, delegate), "orig");
    assert.deepEqual(f.builder.$init.overloads[0].calls, [[delegate]], "the original ctor ran");
    assert.equal(f.calls.enumerate, enumerated, "enumerateClassLoadersSync suspends all threads: never from a hook");
    assert.equal(requestContextHookCounts()["gms-cronet"], 1);
    assert.equal(requestContextHookCounts().cronet, 1, "embedded copy not hooked twice");
    invoke(gmsClass.$init.overloads[0], { id: 2 }, ...ctorArgs("https://g/", "GET"));
    invoke(gmsClass.start.overloads[0], { id: 2 });
    assert.equal(f.emitted[0].stack_kind, "gms-cronet");
});

test("probing the same loader twice never hooks its Cronet copy twice", () => {
    const f = freshInstall();
    const gmsClass = fakeCronetClass();
    const gmsLoader = fakeGmsLoader(gmsClass);
    serveGmsClass(f, gmsLoader, gmsClass);
    invoke(f.builder.$init.overloads[0], {}, definedBy(gmsLoader));
    const hooked = requestContextHookedOverloadCount();
    invoke(f.builder.$init.overloads[0], {}, definedBy(gmsLoader));
    invoke(f.builder.$init.overloads[0], {}, definedBy(f.appLoader));
    assert.equal(requestContextHookedOverloadCount(), hooked);
    assert.deepEqual(requestContextHookCounts(), { "cronet": 1, "gms-cronet": 1, "httpengine": 1, "webview": 1 });
});

test("a delegate from the boot loader, or a null delegate, probes nothing", () => {
    const f = freshInstall();
    const probes = f.calls.loadClass;
    invoke(f.builder.$init.overloads[0], {}, definedBy(null));
    invoke(f.builder.$init.overloads[0], {}, null);
    assert.equal(f.calls.loadClass, probes);
    assert.equal(requestContextHookCounts()["gms-cronet"], 0);
});

test("meta() looks a thread name up once per tid", () => {
    const f = freshInstall();
    const req = { id: 60 };
    const before = f.calls.threadName;
    invoke(f.embedded.start.overloads[0], req);
    invoke(f.embedded.onCanceled.overloads[0], req);
    assert.equal(f.calls.threadName - before, 1);
    f.setTid(8);
    invoke(f.embedded.start.overloads[0], req);
    assert.equal(f.calls.threadName - before, 2);
    assert.deepEqual(f.emitted.map((p) => [p.thread, p.tid]), [["alpha-worker", 7], ["alpha-worker", 7], ["alpha-worker", 8]]);
});

test("setWebViewClient reflects a client class without an override only once", () => {
    const f = freshInstall();
    const cls = fakeClientClass(false);
    let reflections = 0;
    const declared = cls.getDeclaredMethods;
    cls.getDeclaredMethods = () => { reflections++; return declared(); };
    const client = { getClass: () => cls };
    const before = requestContextHookedOverloadCount();
    invoke(f.webView.setWebViewClient.overloads[0], { id: 1 }, client);
    invoke(f.webView.setWebViewClient.overloads[0], { id: 1 }, client);
    assert.equal(reflections, 1);
    assert.equal(requestContextHookedOverloadCount(), before);
    assert.equal(f.subIntercept.implementation, null);
});
