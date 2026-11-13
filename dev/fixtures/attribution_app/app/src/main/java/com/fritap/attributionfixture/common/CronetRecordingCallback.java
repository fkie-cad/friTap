package com.fritap.attributionfixture.common;

import java.nio.ByteBuffer;
import org.chromium.net.CronetException;
import org.chromium.net.UrlRequest;
import org.chromium.net.UrlResponseInfo;

/** Drains a Cronet response and reports the outcome to a {@link PendingRequest}. */
public final class CronetRecordingCallback extends UrlRequest.Callback {
    private static final int BUFFER_BYTES = 32 * 1024;
    private final PendingRequest pending;

    public CronetRecordingCallback(PendingRequest pending) {
        this.pending = pending;
    }

    @Override
    public void onRedirectReceived(UrlRequest request, UrlResponseInfo info, String newLocationUrl) {
        request.followRedirect();
    }

    @Override
    public void onResponseStarted(UrlRequest request, UrlResponseInfo info) {
        request.read(ByteBuffer.allocateDirect(BUFFER_BYTES));
    }

    @Override
    public void onReadCompleted(UrlRequest request, UrlResponseInfo info, ByteBuffer buffer) {
        buffer.clear();
        request.read(buffer);
    }

    @Override
    public void onSucceeded(UrlRequest request, UrlResponseInfo info) {
        pending.succeed(info.getHttpStatusCode(), info.getNegotiatedProtocol(), info.wasCached());
    }

    @Override
    public void onFailed(UrlRequest request, UrlResponseInfo info, CronetException error) {
        pending.fail(error.getClass().getSimpleName() + ": " + error.getMessage());
    }

    @Override
    public void onCanceled(UrlRequest request, UrlResponseInfo info) {
        pending.fail("canceled");
    }
}
