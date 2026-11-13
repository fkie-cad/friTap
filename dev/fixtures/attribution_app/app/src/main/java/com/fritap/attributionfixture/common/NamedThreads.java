package com.fritap.attributionfixture.common;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Single-thread executors with a stable thread name (visible in GT "thread" and Java stacks). */
public final class NamedThreads {
    private NamedThreads() {}

    public static ExecutorService single(String name) {
        return Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, name);
            t.setDaemon(true);
            return t;
        });
    }
}
