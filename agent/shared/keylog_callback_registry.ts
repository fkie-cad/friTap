// agent/shared/keylog_callback_registry.ts
//
// Pure bookkeeping (no Frida globals, unit-testable under node) for the
// BoringSSL "callback tier": every SSL_CTX into which friTap wrote its own,
// script-owned keylog NativeCallback. On unload that callback is freed, so any
// SSL_CTX still pointing at it would SIGSEGV the target on its next handshake.
// releaseAgentHooks() drains this registry and puts each live CTX's previous
// callback back (see keylog_callback_tracker.ts for the Frida glue).
//
// Two ways an entry leaves the registry before teardown:
//
//   1. Observed destruction (preferred; "destructionObserved" entries). The
//      tracker hooks the libcrypto call that only the FINAL SSL_CTX_free makes
//      (OpenSSL 1.1/3.x: CRYPTO_free_ex_data(CRYPTO_EX_INDEX_SSL_CTX, ctx, ..))
//      and reports it via noteDestroyed(). Refcounts are then informational
//      only: reaching 0 never drops such an entry.
//   2. Refcount lower bound (fallback, when no destruction signal exists):
//      * recordInstall() is only ever called while the caller provably holds a
//        reference (SSL_CTX_new's return value, or SSL_new's ctx argument), so
//        "at least 1" is always true at that moment: refs = max(refs, 1).
//      * noteUpRef() (an observed SSL_CTX_up_ref) raises the bound by one.
//      * noteFree() (an observed SSL_CTX_free) lowers it by one.
//      An up_ref we fail to observe (inlined into SSL_new / ossl_ssl_init, as in
//      Homebrew OpenSSL 3.x, or LibreSSL's CRYPTO_add) makes the bound reach 0
//      while the CTX is still ALIVE. Dropping the entry there is NOT fail-safe:
//      the CTX keeps pointing at our callback, is never restored, and its next
//      handshake after detach jumps into the freed NativeCallback (observed as a
//      SIGSEGV ~7 ms after detach). So at 0 the entry is never silently dropped:
//      noteFree() hands it to `releaseLastRef`, which puts the previous callback
//      back right there (SSL_CTX_free's onEnter, the CTX is still alive); the
//      next SSL_new re-installs. Only a missed SSL_CTX_free could keep a freed
//      CTX registered; the tracker guards that case with a getter check.
//
// Size cap: least-recently-installed entries are evicted first. SSL_new
// re-records its ctx on every connection, so busy long-lived CTXs stay at the
// fresh end; an evicted CTX simply is not restored (the pre-fix behaviour).

export const DEFAULT_KEYLOG_REGISTRY_CAP = 4096;

interface TrackedRecord<E> {
    entry: E;
    refs: number;
    /** True when the CTX's real destruction is reported via noteDestroyed(). */
    destructionObserved: boolean;
}

export class KeylogCallbackRegistry<E> {
    private readonly records = new Map<string, TrackedRecord<E>>();
    private isSealed = false;

    constructor(private readonly maxEntries: number = DEFAULT_KEYLOG_REGISTRY_CAP) {
        if (!(maxEntries >= 1)) throw new Error(`maxEntries must be >= 1, got ${maxEntries}`);
    }

    get sealed(): boolean { return this.isSealed; }
    get size(): number { return this.records.size; }

    has(key: string): boolean { return this.records.has(key); }
    get(key: string): E | undefined { return this.records.get(key)?.entry; }
    refsOf(key: string): number { return this.records.get(key)?.refs ?? 0; }

    /**
     * Record that our callback is about to be written into `key`. The entry
     * factory runs only for a new key, so the first-seen previous callback is
     * kept across re-installs. Returns false once sealed: the caller must then
     * NOT install (teardown has started). `destructionObserved` declares that
     * noteDestroyed() will be called for this CTX's final free (mode 1 above).
     */
    recordInstall(key: string, makeEntry: () => E, destructionObserved = false): boolean {
        if (this.isSealed) return false;
        const existing = this.records.get(key);
        const record = existing ?? { entry: makeEntry(), refs: 0, destructionObserved };
        record.refs = Math.max(record.refs, 1);
        record.destructionObserved = destructionObserved;
        this.records.delete(key);            // re-insert = move to the fresh end
        this.records.set(key, record);
        this.evictOverflow();
        return true;
    }

    noteUpRef(key: string): void {
        const record = this.records.get(key);
        if (record) record.refs++;
    }

    /**
     * An observed SSL_CTX_free. For a refcount-tracked entry whose bound reaches
     * 0 the entry is removed and handed to `releaseLastRef` (which must restore
     * the previous callback; a throw is swallowed). Destruction-observed entries
     * are never dropped here -- only noteDestroyed() removes them.
     */
    noteFree(key: string, releaseLastRef?: (entry: E) => void): void {
        const record = this.records.get(key);
        if (!record) return;
        record.refs = Math.max(record.refs - 1, 0);
        if (record.refs > 0 || record.destructionObserved) return;
        this.records.delete(key);
        if (releaseLastRef === undefined) return;
        try { releaseLastRef(record.entry); } catch (_e) { /* best effort */ }
    }

    /**
     * The CTX is really being destroyed (final free observed): forget it without
     * restoring -- it will never run another handshake.
     */
    noteDestroyed(key: string): void {
        this.records.delete(key);
    }

    /**
     * Seal (no further installs are accepted) and hand every remaining entry to
     * `restore` exactly once. Idempotent: a second call finds nothing. A throwing
     * or false-returning restore is counted as skipped, never propagated.
     */
    sealAndDrain(restore: (key: string, entry: E) => boolean): { restored: number; skipped: number } {
        this.isSealed = true;
        const snapshot = Array.from(this.records.entries());
        this.records.clear();
        let restored = 0;
        let skipped = 0;
        for (const [key, record] of snapshot) {
            let ok = false;
            try { ok = restore(key, record.entry); } catch (_e) { ok = false; }
            if (ok) restored++; else skipped++;
        }
        return { restored, skipped };
    }

    private evictOverflow(): void {
        while (this.records.size > this.maxEntries) {
            const oldest = this.records.keys().next().value;
            if (oldest === undefined) return;
            this.records.delete(oldest);
        }
    }
}
