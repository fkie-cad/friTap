package com.fritap.attributionfixture.common;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** One in-flight request: logs exactly one terminal ground-truth event and lets the worker wait. */
public final class PendingRequest {
    public final RequestDescriptor descriptor;
    private final CountDownLatch finished = new CountDownLatch(1);
    private final AtomicBoolean terminal = new AtomicBoolean(false);

    public PendingRequest(RequestDescriptor descriptor) {
        this.descriptor = descriptor;
    }

    public void succeed(int status, String protocol, boolean cached) {
        if (terminal.compareAndSet(false, true)) {
            GroundTruthLog.done(descriptor, status, protocol, cached);
            finished.countDown();
        }
    }

    public void fail(String error) {
        if (terminal.compareAndSet(false, true)) {
            GroundTruthLog.fail(descriptor, error);
            finished.countDown();
        }
    }

    public boolean isTerminal() {
        return terminal.get();
    }

    /** @return true if the request finished in time; otherwise logs a timeout failure. */
    public boolean awaitOrTimeOut(long timeoutMs) {
        try {
            if (finished.await(timeoutMs, TimeUnit.MILLISECONDS)) return true;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        fail("timeout after " + timeoutMs + " ms");
        return false;
    }
}
