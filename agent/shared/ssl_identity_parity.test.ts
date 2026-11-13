// Static parity check for the per-SSL* identity wiring (P1, design B3/B4).
//
// Every BoringSSL-family emitter must hand its SSL* to the shared choke points,
// in BOTH hook trees (legacy is the default, modern needs --modern), or the
// client_random join key silently goes missing on one of them:
//   - keylog half (J3): every `sendKeylog(` call passes the SSL* as a 2nd arg.
//   - plaintext half (J4): every plaintext record builder stamps client_random
//     (a `stampRecordClientRandom(` per `stampRecordLibrary(`, and `ssl`/`clientRandom`
//     in every `buildRecordMessage(` context), unless it is a non-BoringSSL file
//     on PLAINTEXT_BUILDER_ALLOWLIST.
//   - library half (I2.4): every `sendDatalog(` call stamps the record's `library`
//     label in its own function (see LIBRARY_STAMP_ALLOWLIST for relays).
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const AGENT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SCANNED_ROOTS = ["tls", "legacy", "shared"];

/** File names that are BoringSSL-family emitters by definition. */
const SCOPED_FILE_NAME = /openssl_boringssl|cronet|flutter|boringssl_|tls13_secret|chromium_plaintext/;
/** Files that read the SSL struct themselves are in scope too. */
const SCOPED_IMPORT = /from\s+["'][^"']*ssl_struct_walk(\.js)?["']/;
/** In scope although their names do not say so (agent-relative paths). */
const EXTRA_SCOPED_FILES: ReadonlySet<string> = new Set([
    "tls/definitions/openssl.ts",   // createBoringSSLKeylogApproach: the modern BoringSSL keylog callback
    "tls/libs/monobtls.ts",         // Mono BTLS is a BoringSSL fork (ssl_log_secret dumpKeys)
    "legacy/tls/libs/monobtls.ts",
]);

/**
 * `sendKeylog(` calls allowed to omit the SSL*, as "<agent-relative file>:<call text>"
 * prefixes, each with the reason. Keep this short; prefer wiring the SSL*.
 */
const SEND_KEYLOG_ALLOWLIST: ReadonlyMap<string, string> = new Map([
    // (empty: every in-scope call site passes its SSL*)
]);

// ---------------------------------------------------------------------------
// Source scanning helpers (exported shape kept local; J4 reuses them below)
// ---------------------------------------------------------------------------

function listSourceFiles(dir: string): string[] {
    const out: string[] = [];
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const full = join(dir, entry.name);
        if (entry.isDirectory()) out.push(...listSourceFiles(full));
        else if (entry.name.endsWith(".ts") && !entry.name.endsWith(".test.ts")) out.push(full);
    }
    return out;
}

function agentRelative(file: string): string {
    return relative(AGENT, file).split("\\").join("/");
}

function isScopedFile(file: string, source: string): boolean {
    const rel = agentRelative(file);
    const name = rel.split("/").pop() ?? "";
    return SCOPED_FILE_NAME.test(name) || SCOPED_IMPORT.test(source) || EXTRA_SCOPED_FILES.has(rel);
}

interface ScopedSource {
    rel: string;
    source: string;
}

function scopedSources(): ScopedSource[] {
    const files = SCANNED_ROOTS.flatMap((root) => listSourceFiles(join(AGENT, root)));
    return files
        .map((file) => ({ file, source: readFileSync(file, "utf8") }))
        .filter(({ file, source }) => isScopedFile(file, source))
        .map(({ file, source }) => ({ rel: agentRelative(file), source }));
}

/** True when `index` sits inside a `//` line comment or a block-comment line. */
function isInComment(source: string, index: number): boolean {
    const lineStart = source.lastIndexOf("\n", index - 1) + 1;
    const before = source.slice(lineStart, index);
    return before.includes("//") || /^\s*(\*|\/\*)/.test(before);
}

const CLOSERS: Record<string, string> = { "(": ")", "[": "]", "{": "}" };

/** Skip a '...' or "..." literal starting at `i`; returns the index after it. */
function skipQuoted(text: string, i: number): number {
    const quote = text[i];
    for (let j = i + 1; j < text.length; j++) {
        if (text[j] === "\\") j++;
        else if (text[j] === quote) return j + 1;
    }
    return text.length;
}

/** Skip a `...` template literal (with nested ${...}) starting at `i`. */
function skipTemplate(text: string, i: number): number {
    for (let j = i + 1; j < text.length; j++) {
        if (text[j] === "\\") j++;
        else if (text[j] === "`") return j + 1;
        else if (text[j] === "$" && text[j + 1] === "{") j = skipBracketed(text, j + 1) - 1;
    }
    return text.length;
}

/** Skip a bracketed group opening at `i`; returns the index after its closer. */
function skipBracketed(text: string, i: number): number {
    const closer = CLOSERS[text[i]];
    let j = i + 1;
    while (j < text.length) {
        const c = text[j];
        if (c === closer) return j + 1;
        if (c === "'" || c === '"') j = skipQuoted(text, j);
        else if (c === "`") j = skipTemplate(text, j);
        else if (c in CLOSERS) j = skipBracketed(text, j);
        else j++;
    }
    return text.length;
}

/**
 * Number of top-level arguments of the call whose "(" is at `openParen`.
 * Nested brackets, strings and template literals are skipped. 0 for "()".
 * Empty segments (a trailing comma) are not counted.
 */
export function countTopLevelArgs(text: string, openParen: number): number {
    const end = skipBracketed(text, openParen) - 1;
    let args = 0;
    let segmentHasContent = false;
    let j = openParen + 1;
    while (j < end) {
        const c = text[j];
        if (c === ",") {
            if (segmentHasContent) args++;
            segmentHasContent = false;
            j++;
            continue;
        }
        if (!/\s/.test(c)) segmentHasContent = true;
        if (c === "'" || c === '"') j = skipQuoted(text, j);
        else if (c === "`") j = skipTemplate(text, j);
        else if (c in CLOSERS) j = skipBracketed(text, j);
        else j++;
    }
    // A trailing comma ("f(a, b,)") leaves an empty last segment: not an argument.
    return segmentHasContent ? args + 1 : args;
}

interface CallSite {
    rel: string;
    /** Offset of the call's name in the scanned source. */
    index: number;
    line: number;
    text: string;
    args: number;
}

/** Every `<name>(` call in `source` that is not a comment or a declaration. */
export function findCalls(rel: string, source: string, name: string): CallSite[] {
    const sites: CallSite[] = [];
    const re = new RegExp(`(?<![\\w.$])${name}\\(`, "g");
    for (let m = re.exec(source); m !== null; m = re.exec(source)) {
        const before = source.slice(Math.max(0, m.index - 9), m.index);
        if (isInComment(source, m.index) || before.endsWith("function ")) continue;
        const openParen = m.index + name.length;
        const close = skipBracketed(source, openParen);
        sites.push({
            rel,
            index: m.index,
            line: source.slice(0, m.index).split("\n").length,
            text: source.slice(m.index, close).replace(/\s+/g, " "),
            args: countTopLevelArgs(source, openParen),
        });
    }
    return sites;
}

function allowlistReason(site: CallSite): string | undefined {
    for (const [key, reason] of SEND_KEYLOG_ALLOWLIST) {
        if (`${site.rel}:${site.text}`.startsWith(key)) return reason;
    }
    return undefined;
}

// ---------------------------------------------------------------------------
// Scanner self-tests
// ---------------------------------------------------------------------------

test("countTopLevelArgs: nested parens, strings and templates are one argument each", () => {
    const count = (s: string) => countTopLevelArgs(s, s.indexOf("("));
    assert.equal(count("f()"), 0);
    assert.equal(count("f(a)"), 1);
    assert.equal(count("f(a.b(c, d), e)"), 2);
    assert.equal(count('f("x, y" + g(1, 2))'), 1);
    assert.equal(count("f(`${a}, ${h(b, c)} ${d}`, ssl, mod)"), 3);
    assert.equal(count("f([1, 2], { a: 1, b: 2 })"), 2);
    assert.equal(count("f(\n  line,\n  ssl,\n)"), 2);
});

test("findCalls skips comments and the function declaration", () => {
    const src = [
        "// sendKeylog(x) in a comment",
        " * sendKeylog() in a block comment",
        "export function sendKeylog(line: string, ssl?: NativePointer): void {}",
        "obj.sendKeylog(a);",
        "sendKeylog(a, b);",
    ].join("\n");
    const sites = findCalls("x.ts", src, "sendKeylog");
    assert.deepEqual(sites.map((s) => [s.line, s.args]), [[5, 2]]);
});

// ---------------------------------------------------------------------------
// Keylog half (J3)
// ---------------------------------------------------------------------------

test("parity scan covers both hook trees and the shared helpers", () => {
    const rels = scopedSources().map((s) => s.rel);
    assert.ok(rels.some((r) => r.startsWith("legacy/")), "no legacy file scanned");
    assert.ok(rels.some((r) => r.startsWith("tls/")), "no modern file scanned");
    assert.ok(rels.some((r) => r.startsWith("shared/")), "no shared file scanned");
    for (const extra of EXTRA_SCOPED_FILES) assert.ok(rels.includes(extra), `${extra} missing`);
});

test("every BoringSSL-family sendKeylog( call passes the SSL* (both trees)", () => {
    const sites = scopedSources().flatMap((s) => findCalls(s.rel, s.source, "sendKeylog"));
    assert.ok(sites.some((s) => s.rel.startsWith("legacy/")), "no legacy sendKeylog call found");
    assert.ok(sites.some((s) => s.rel.startsWith("tls/")), "no modern sendKeylog call found");
    const missing = sites
        .filter((s) => s.args < 2 && allowlistReason(s) === undefined)
        .map((s) => `${s.rel}:${s.line}  ${s.text}`);
    assert.deepEqual(missing, [], "sendKeylog( without the SSL* (pass it, or allowlist with a reason)");
});

test("SEND_KEYLOG_ALLOWLIST entries all carry a reason", () => {
    for (const [key, reason] of SEND_KEYLOG_ALLOWLIST) {
        assert.ok(reason.trim().length > 0, `allowlist entry without a reason: ${key}`);
    }
});

// ---------------------------------------------------------------------------
// Plaintext half (J4)
// ---------------------------------------------------------------------------

/** Roots scanned for plaintext record builders (core/ holds the generic read/write executor). */
const BUILDER_ROOTS = ["tls", "legacy", "shared", "core"];
/**
 * SslRecordSource helpers (record_message.ts): the source's `library` and client_random
 * probe are required fields, so every call stamps both by construction.
 */
const SSL_SOURCE_RECORD_CALLS = ["finishSslRecord", "buildEndpointlessSslRecord"];
/** A file builds plaintext records when it calls one of these. */
const RECORD_BUILDER_CALLS = ["stampRecordLibrary", "buildRecordMessage", ...SSL_SOURCE_RECORD_CALLS];
/** Builders taking a RecordContext: each call's context must feed client_random (an fd-less record needs it). */
const CONTEXT_BUILDER_CALLS = ["buildRecordMessage", "buildEndpointlessRecord"];
/** A RecordContext key that feeds client_random: `clientRandom:`, `ssl: x` or shorthand `ssl`. */
const CONTEXT_CLIENT_RANDOM_KEY = /\bclientRandom\s*:|(^|[{,\s])ssl\s*[:,}]/;

/** Shared BoringSSL plaintext builders that must stamp client_random although their names do not say so. */
const EXTRA_BUILDER_FILES: ReadonlySet<string> = new Set([
    "shared/ssl_plaintext_hooks.ts",   // SslPlaintextHooks: both OpenSSL_BoringSSL trees + Chromium plaintext
    "core/executors/read_write.ts",    // generic SSL_read/SSL_write executor (modern definitions)
]);

/**
 * Plaintext builder files exempt from client_random stamping, with the reason.
 * None of them is BoringSSL: the shared ssl_st layout does not apply to them.
 */
const PLAINTEXT_BUILDER_ALLOWLIST: ReadonlyMap<string, string> = new Map([
    ["shared/record_message.ts", "defines buildRecordMessage/stampRecordLibrary and stamps client_random itself"],
    ["legacy/tls/libs/gnutls.ts", "GnuTLS: own session struct, not a BoringSSL SSL*"],
    ["tls/libs/gnutls.ts", "GnuTLS: own session struct, not a BoringSSL SSL*"],
    ["legacy/tls/libs/nss.ts", "NSS: PRFileDesc/sslSocket, not a BoringSSL SSL*"],
    ["tls/libs/nss.ts", "NSS: PRFileDesc/sslSocket, not a BoringSSL SSL*"],
    ["legacy/tls/libs/wolfssl.ts", "wolfSSL: own WOLFSSL struct"],
    ["tls/libs/wolfssl.ts", "wolfSSL: own WOLFSSL struct"],
    ["legacy/tls/libs/mbedTLS.ts", "mbedTLS: mbedtls_ssl_context, not an SSL*"],
    ["tls/libs/mbedTLS.ts", "mbedTLS: mbedtls_ssl_context, not an SSL*"],
    ["legacy/tls/libs/s2ntls.ts", "s2n-tls: s2n_connection, not an SSL*"],
    ["tls/libs/s2ntls.ts", "s2n-tls: s2n_connection, not an SSL*"],
    ["legacy/tls/libs/matrixssl.ts", "MatrixSSL: ssl_t, not a BoringSSL SSL*"],
    ["tls/libs/matrixssl.ts", "MatrixSSL: ssl_t, not a BoringSSL SSL*"],
    ["tls/definitions/matrixssl.ts", "MatrixSSL: ssl_t, not a BoringSSL SSL*"],
    ["tls/definitions/sspi.ts", "SSPI/Schannel: CtxtHandle, not a BoringSSL SSL*"],
    ["legacy/tls/platforms/windows/sspi.ts", "SSPI/Schannel: CtxtHandle, not a BoringSSL SSL*"],
    ["tls/shared/go_plaintext.ts", "Go crypto/tls: *tls.Conn, not a BoringSSL SSL*"],
    ["legacy/tls/platforms/android/bouncycastle.ts", "BouncyCastle/SpongyCastle: Java JSSE provider, no SSL*"],
]);

function builderSources(): ScopedSource[] {
    const files = BUILDER_ROOTS.flatMap((root) => listSourceFiles(join(AGENT, root)));
    return files
        .map((file) => ({ rel: agentRelative(file), source: readFileSync(file, "utf8") }))
        .filter(({ rel, source }) => RECORD_BUILDER_CALLS.some((name) => findCalls(rel, source, name).length > 0));
}

function isScopedBuilder(file: ScopedSource): boolean {
    return EXTRA_BUILDER_FILES.has(file.rel) || isScopedFile(join(AGENT, file.rel), file.source);
}

/** Builder calls in `file` that produce a record without client_random stamping. */
function clientRandomGaps(file: ScopedSource): string[] {
    const gaps: string[] = [];
    const libraryStamps = findCalls(file.rel, file.source, "stampRecordLibrary");
    const crStamps = findCalls(file.rel, file.source, "stampRecordClientRandom");
    if (crStamps.length < libraryStamps.length) {
        gaps.push(`${file.rel}: ${libraryStamps.length} stampRecordLibrary( vs ${crStamps.length} stampRecordClientRandom(`);
    }
    for (const name of CONTEXT_BUILDER_CALLS) {
        for (const call of findCalls(file.rel, file.source, name)) {
            if (!CONTEXT_CLIENT_RANDOM_KEY.test(call.text)) gaps.push(`${call.rel}:${call.line}  ${call.text.slice(0, 120)}`);
        }
    }
    return gaps;
}

test("clientRandomGaps: counts stamps and inspects every buildRecordMessage( context", () => {
    const file = (source: string) => clientRandomGaps({ rel: "x.ts", source });
    assert.deepEqual(file("stampRecordLibrary(m, l); stampRecordClientRandom(m, cr);"), []);
    assert.equal(file("stampRecordLibrary(m, l); stampRecordLibrary(m, l); stampRecordClientRandom(m, cr);").length, 1);
    assert.deepEqual(file("buildRecordMessage({ fd, library, ssl }, f);"), []);
    assert.deepEqual(file("buildRecordMessage({ fd, ssl: sslCtx }, f);"), []);
    assert.deepEqual(file("buildRecordMessage({ fd, clientRandom: () => cr }, f);"), []);
    assert.equal(file("buildRecordMessage({ fd, library }, f);").length, 1);
    assert.deepEqual(file("buildEndpointlessRecord({ fd: -1, library, ssl }, f);"), []);
    assert.equal(file("buildEndpointlessRecord({ fd: -1, library }, f);").length, 1);
});

test("plaintext parity scan finds BoringSSL builders in both hook trees", () => {
    const rels = builderSources().filter(isScopedBuilder).map((s) => s.rel);
    assert.ok(rels.some((r) => r.startsWith("legacy/")), "no legacy BoringSSL plaintext builder found");
    assert.ok(rels.some((r) => r.startsWith("tls/")), "no modern BoringSSL plaintext builder found");
    for (const extra of EXTRA_BUILDER_FILES) assert.ok(rels.includes(extra), `${extra} missing`);
});

test("every BoringSSL plaintext record builder stamps client_random (both trees)", () => {
    const missing = builderSources()
        .filter((s) => !PLAINTEXT_BUILDER_ALLOWLIST.has(s.rel))
        .flatMap(clientRandomGaps);
    assert.deepEqual(missing, [], "plaintext builder without client_random stamping (wire it, or allowlist a non-BoringSSL file)");
});

test("PLAINTEXT_BUILDER_ALLOWLIST: every entry has a reason, is a builder, and is not BoringSSL-scoped", () => {
    const builders = new Map(builderSources().map((s) => [s.rel, s]));
    for (const [rel, reason] of PLAINTEXT_BUILDER_ALLOWLIST) {
        assert.ok(reason.trim().length > 0, `allowlist entry without a reason: ${rel}`);
        const file = builders.get(rel);
        assert.ok(file, `stale allowlist entry (not a plaintext builder): ${rel}`);
        assert.ok(!isScopedBuilder(file!), `BoringSSL-family file may not be allowlisted: ${rel}`);
    }
});

// ---------------------------------------------------------------------------
// Library half (I2.4): every datalog record carries its `library` label
// ---------------------------------------------------------------------------
//
// Per call, not per file: each `sendDatalog(` call must be preceded, inside its
// enclosing function, by one of
//   - a `stampRecordLibrary(` call,
//   - a `buildRecordMessage(` whose context has a `library` key,
//   - a 5-argument `buildQuicMessage(` (its 5th argument is the library).
// The enclosing function comes from the TypeScript AST; string, template and regex
// literal contents are blanked first, and findCalls skips comments, so neither a
// commented-out nor a quoted stamp counts.
// When the message is `this.<field>` (an Interceptor listener that builds the
// message in onEnter and sends it in onLeave), the search starts at the listener
// object literal that owns the function, so onEnter's stamp counts.

/** Roots scanned for `sendDatalog(` calls. ssh/, mtproto/, quic/, telegram/, signal/ are out of scope. */
const LIBRARY_ROOTS = ["tls", "legacy", "shared", "core"];
/** A RecordContext key naming the library: `library:` or shorthand `library`. */
const CONTEXT_LIBRARY_KEY = /(^|[{,\s])library\s*[:,}]/;
/** buildQuicMessage(…) takes the library as its 5th argument. */
const QUIC_MESSAGE_ARGS_WITH_LIBRARY = 5;

/**
 * `sendDatalog(` calls exempt from the library stamp, as "<agent-relative file>" (whole
 * file) or "<file>:<call text>" prefixes, each with the reason. Relays only: the message
 * they send was labelled by whoever built it.
 */
const LIBRARY_STAMP_ALLOWLIST: ReadonlyMap<string, string> = new Map([
    ["shared/shared_structures.ts", "defines sendDatalog; its internal call relays a caller-built message"],
    ["core/context.ts", "HookContext.sendDatalog forwards a definition-built message"],
    ["shared/write_hooks.ts", "relays the message of an injected builder (the callers stamp the library)"],
    ["tls/definitions/openssl.ts:sendDatalog(this.message", "message from buildExMessage (buildRecordMessage with library: modName)"],
    ["core/executors/read_write.ts:sendDatalog(this.message", "message from recordMessageBuilder (buildRecordMessage with library: moduleName)"],
    ["shared/ssl_plaintext_hooks.ts:sendDatalog(this.message", "message from SslPlaintextHooks.buildMessage (buildRecordMessage with library: host.moduleName)"],
    ["shared/ssl_plaintext_hooks.ts:sendDatalog(message, call.", "emitWrite relays SslPlaintextHooks.buildMessage output (stamps the library)"],
    ["tls/shared/go_plaintext.ts:sendDatalog(message, record.", "relays GoRecordMessageBuilder output (goDefaultFdMessageBuilder stamps the library)"],
    ["tls/shared/go_plaintext.ts:sendDatalog(message, copy.", "relays GoRecordMessageBuilder output (goDefaultFdMessageBuilder stamps the library)"],
]);

interface Span {
    start: number;
    end: number;
}

interface FunctionSpan {
    body: Span;
    /** The object literal the function is a member of (an Interceptor listener), if any. */
    owner?: Span;
}

function nodeSpan(node: ts.Node, file: ts.SourceFile): Span {
    return { start: node.getStart(file), end: node.end };
}

function ownerObjectSpan(fn: ts.Node, file: ts.SourceFile): Span | undefined {
    const parent = ts.isPropertyAssignment(fn.parent) ? fn.parent.parent : fn.parent;
    return ts.isObjectLiteralExpression(parent) ? nodeSpan(parent, file) : undefined;
}

function isLiteralText(node: ts.Node): boolean {
    // A whole template (its ${...} parts included) is blanked: no stamp lives inside one.
    return ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node) || ts.isTemplateExpression(node)
        || ts.isRegularExpressionLiteral(node);
}

/** `source` with the inside of `spans` replaced by spaces (newlines kept, so offsets and lines hold). */
function blankSpans(source: string, spans: Span[]): string {
    const chars = source.split("");
    for (const { start, end } of spans) {
        for (let i = start + 1; i < end - 1; i++) if (chars[i] !== "\n") chars[i] = " ";
    }
    return chars.join("");
}

interface LibraryScanSource {
    /** The source with literal contents blanked. */
    masked: string;
    /** Every function-like node with a body, in source order (outer before inner). */
    functions: FunctionSpan[];
}

export function parseForLibraryScan(rel: string, source: string): LibraryScanSource {
    const file = ts.createSourceFile(rel, source, ts.ScriptTarget.Latest, true);
    const functions: FunctionSpan[] = [];
    const literals: Span[] = [];
    const visit = (node: ts.Node): void => {
        if (isLiteralText(node)) literals.push(nodeSpan(node, file));
        if (ts.isFunctionLike(node) && (node as ts.FunctionLikeDeclaration).body) {
            functions.push({ body: nodeSpan(node, file), owner: ownerObjectSpan(node, file) });
        }
        ts.forEachChild(node, visit);
    };
    visit(file);
    return { masked: blankSpans(source, literals), functions };
}

/** Start of the source region a stamp for `call` may live in (see the section comment). */
function stampRegionStart(call: CallSite, spans: FunctionSpan[]): number {
    const enclosing = spans.filter((s) => s.body.start <= call.index && call.index < s.body.end).pop();
    if (enclosing === undefined) return 0;
    const sendsListenerField = /^sendDatalog\(\s*this\./.test(call.text);
    return sendsListenerField && enclosing.owner ? enclosing.owner.start : enclosing.body.start;
}

/** True when `region` (or the call itself) labels the record's library. */
function regionStampsLibrary(rel: string, region: string): boolean {
    if (findCalls(rel, region, "stampRecordLibrary").length > 0) return true;
    if (SSL_SOURCE_RECORD_CALLS.some((name) => findCalls(rel, region, name).length > 0)) return true;
    if (findCalls(rel, region, "buildRecordMessage").some((c) => CONTEXT_LIBRARY_KEY.test(c.text))) return true;
    return findCalls(rel, region, "buildQuicMessage").some((c) => c.args === QUIC_MESSAGE_ARGS_WITH_LIBRARY);
}

function libraryAllowlistReason(site: CallSite): string | undefined {
    for (const [key, reason] of LIBRARY_STAMP_ALLOWLIST) {
        if (key === site.rel || `${site.rel}:${site.text}`.startsWith(key)) return reason;
    }
    return undefined;
}

/** `sendDatalog(` calls in `file` whose record carries no library label. */
export function libraryStampGaps(file: ScopedSource): CallSite[] {
    const { masked, functions } = parseForLibraryScan(file.rel, file.source);
    return findCalls(file.rel, masked, "sendDatalog").filter((call) => {
        const region = masked.slice(stampRegionStart(call, functions), call.index + call.text.length);
        return !regionStampsLibrary(file.rel, region);
    });
}

function datalogSources(): ScopedSource[] {
    return LIBRARY_ROOTS.flatMap((root) => listSourceFiles(join(AGENT, root)))
        .map((file) => ({ rel: agentRelative(file), source: readFileSync(file, "utf8") }))
        .filter(({ rel, source }) => findCalls(rel, source, "sendDatalog").length > 0);
}

test("libraryStampGaps: per call, within the enclosing function or its listener object", () => {
    const gaps = (source: string) => libraryStampGaps({ rel: "x.ts", source }).map((c) => c.line);
    assert.deepEqual(gaps("function f(m) {\n stampRecordLibrary(m, lib);\n sendDatalog(m, d);\n}"), []);
    assert.deepEqual(gaps("function f(m) {\n sendDatalog(m, d);\n stampRecordLibrary(m, lib);\n}"), [2], "stamp after the send");
    assert.deepEqual(gaps("function a(m) { stampRecordLibrary(m, l); }\nfunction b(m) {\n sendDatalog(m, d);\n}"), [3],
        "a stamp in another function does not count");
    assert.deepEqual(gaps("function f(m) {\n // stampRecordLibrary(m, l);\n sendDatalog(m, d);\n}"), [3], "commented-out stamp");
    assert.deepEqual(gaps("function f() {\n const s = \"stampRecordLibrary(m, l)\";\n sendDatalog(m, d);\n}"), [3],
        "a stamp inside a string");
    assert.deepEqual(gaps("function f() {\n log(`${stampRecordLibrary(m, l)}`);\n sendDatalog(m, d);\n}"), [3],
        "a stamp inside a template");
    const listener = "Interceptor.attach(p, {\n onEnter(a) { this.message = buildRecordMessage({ fd, library }, f); },\n"
        + " onLeave(r) {\n sendDatalog(this.message, b);\n }\n});";
    assert.deepEqual(gaps(listener), [], "onEnter builds, onLeave sends this.message");
    assert.deepEqual(gaps(listener.replace("{ fd, library }", "{ fd }")), [4], "buildRecordMessage without library");
    assert.deepEqual(gaps("function f() {\n const m = buildQuicMessage(a, b, c, d, lib);\n sendDatalog(m, x);\n}"), []);
    assert.deepEqual(gaps("function f() {\n const m = buildQuicMessage(a, b, c, d);\n sendDatalog(m, x);\n}"), [3]);
});

test("every sendDatalog( call stamps the record's library (both trees)", () => {
    const sources = datalogSources();
    assert.ok(sources.some((s) => s.rel.startsWith("legacy/")), "no legacy sendDatalog call found");
    assert.ok(sources.some((s) => s.rel.startsWith("tls/")), "no modern sendDatalog call found");
    const missing = sources
        .flatMap(libraryStampGaps)
        .filter((call) => libraryAllowlistReason(call) === undefined)
        .map((call) => `${call.rel}:${call.line}  ${call.text}`);
    assert.deepEqual(missing, [], "sendDatalog( without a library label (stamp it, or allowlist a relay with a reason)");
});

test("LIBRARY_STAMP_ALLOWLIST: every entry has a reason and still matches a sendDatalog( call", () => {
    const calls = datalogSources().flatMap((s) => findCalls(s.rel, s.source, "sendDatalog"));
    for (const [key, reason] of LIBRARY_STAMP_ALLOWLIST) {
        assert.ok(reason.trim().length > 0, `allowlist entry without a reason: ${key}`);
        const matches = calls.some((c) => key === c.rel || `${c.rel}:${c.text}`.startsWith(key));
        assert.ok(matches, `stale allowlist entry (no sendDatalog( call): ${key}`);
    }
});
