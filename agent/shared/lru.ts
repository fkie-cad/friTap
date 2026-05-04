/**
 * Minimal bounded-size cache helpers for the Frida agent.
 *
 * LruMap: Map-backed LRU cache — promotes entries on access.
 * FifoSet: Set-backed FIFO cache — no hit promotion (oldest evicted first).
 *
 * Both leverage JS Map/Set insertion-order guarantees (ECMAScript spec).
 */

export class LruMap<K, V> {
    private _map = new Map<K, V>();

    constructor(private readonly _max: number) {}

    get(key: K): V | undefined {
        const val = this._map.get(key);
        if (val !== undefined) {
            // Promote to most-recently-used by delete + re-insert.
            this._map.delete(key);
            this._map.set(key, val);
        }
        return val;
    }

    set(key: K, value: V): void {
        // If key exists, delete first to refresh insertion order.
        this._map.delete(key);
        if (this._map.size >= this._max) {
            const oldest = this._map.keys().next().value;
            if (oldest !== undefined) this._map.delete(oldest);
        }
        this._map.set(key, value);
    }

    delete(key: K): boolean {
        return this._map.delete(key);
    }

    get size(): number {
        return this._map.size;
    }
}

export class FifoSet<T> {
    private _set = new Set<T>();

    constructor(private readonly _max: number) {}

    has(value: T): boolean {
        return this._set.has(value);
    }

    add(value: T): void {
        if (this._set.has(value)) return;
        if (this._set.size >= this._max) {
            const oldest = this._set.values().next().value;
            if (oldest !== undefined) this._set.delete(oldest);
        }
        this._set.add(value);
    }

    get size(): number {
        return this._set.size;
    }
}
