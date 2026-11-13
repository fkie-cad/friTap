// agent/shared/ssl_fd_cache.ts
//
// Bounded SSL object -> socket fd cache for socket_fd_tracker.ts, with a reverse
// fd -> SSL objects index so close(fd) forgets the fd's entries in O(entries for that fd)
// instead of scanning the whole cache on every close() in the process.

export class SslFdCache {
    /** SSL object (pointer string) -> fd. Map order doubles as LRU order. */
    private readonly fdBySsl = new Map<string, number>();
    /** fd -> the SSL objects currently cached with it (kept in sync with fdBySsl). */
    private readonly sslsByFd = new Map<number, Set<string>>();

    constructor(private readonly maxEntries: number) { }

    get size(): number {
        return this.fdBySsl.size;
    }

    get(ssl: string): number | undefined {
        return this.fdBySsl.get(ssl);
    }

    /** Cache ssl -> fd as the most recently used entry, evicting the oldest past the bound. */
    set(ssl: string, fd: number): void {
        this.deleteSsl(ssl);                 // re-insert: refreshes LRU order and the reverse index
        this.fdBySsl.set(ssl, fd);
        let ssls = this.sslsByFd.get(fd);
        if (ssls === undefined) {
            ssls = new Set<string>();
            this.sslsByFd.set(fd, ssls);
        }
        ssls.add(ssl);
        if (this.fdBySsl.size > this.maxEntries) {
            this.deleteSsl(this.fdBySsl.keys().next().value as string);
        }
    }

    /** SSL_free(ssl): drop its entry. */
    deleteSsl(ssl: string): void {
        const fd = this.fdBySsl.get(ssl);
        if (fd === undefined) return;
        this.fdBySsl.delete(ssl);
        const ssls = this.sslsByFd.get(fd);
        if (ssls === undefined) return;
        ssls.delete(ssl);
        if (ssls.size === 0) this.sslsByFd.delete(fd);
    }

    /** close(fd): drop every SSL object cached with fd (the number may be reused). */
    deleteFd(fd: number): void {
        const ssls = this.sslsByFd.get(fd);
        if (ssls === undefined) return;
        this.sslsByFd.delete(fd);
        for (const ssl of ssls) this.fdBySsl.delete(ssl);
    }

    /** Forget everything (closed-fd notifications were lost; no cached fd is trustworthy). */
    clear(): void {
        this.fdBySsl.clear();
        this.sslsByFd.clear();
    }

    /** Number of fds in the reverse index (test hook for index consistency). */
    get indexedFdCount(): number {
        return this.sslsByFd.size;
    }
}
