package com.fritap.attributionfixture.common;

import java.util.concurrent.Callable;

/** Lazily builds an engine once; remembers why it could not be built. */
public final class EngineSlot<T> {
    private final Callable<T> factory;
    private T engine;
    private String failure;
    private boolean attempted;

    public EngineSlot(Callable<T> factory) {
        this.factory = factory;
    }

    /** @return the engine, or null (see {@link #failure()}). */
    public synchronized T get() {
        if (!attempted) {
            attempted = true;
            try {
                engine = factory.call();
            } catch (Exception | LinkageError e) {
                failure = e.getClass().getSimpleName() + ": " + e.getMessage();
            }
        }
        return engine;
    }

    public synchronized String failure() {
        return failure;
    }
}
