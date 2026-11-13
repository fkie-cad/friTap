package com.fritap.attributionfixture.common;

import android.net.http.HttpException;
import android.net.http.UrlRequest;
import android.net.http.UrlResponseInfo;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import java.nio.ByteBuffer;

/** Platform HttpEngine twin of {@link CronetRecordingCallback}. */
@RequiresApi(34)
public final class HttpEngineRecordingCallback implements UrlRequest.Callback {
    private static final int BUFFER_BYTES = 32 * 1024;
    private final PendingRequest pending;

    public HttpEngineRecordingCallback(PendingRequest pending) {
        this.pending = pending;
    }

    @Override
    public void onRedirectReceived(@NonNull UrlRequest request, @NonNull UrlResponseInfo info,
            @NonNull String newLocationUrl) {
        request.followRedirect();
    }

    @Override
    public void onResponseStarted(@NonNull UrlRequest request, @NonNull UrlResponseInfo info) {
        request.read(ByteBuffer.allocateDirect(BUFFER_BYTES));
    }

    @Override
    public void onReadCompleted(@NonNull UrlRequest request, @NonNull UrlResponseInfo info,
            @NonNull ByteBuffer buffer) {
        buffer.clear();
        request.read(buffer);
    }

    @Override
    public void onSucceeded(@NonNull UrlRequest request, @NonNull UrlResponseInfo info) {
        pending.succeed(info.getHttpStatusCode(), info.getNegotiatedProtocol(), info.wasCached());
    }

    @Override
    public void onFailed(@NonNull UrlRequest request, @Nullable UrlResponseInfo info,
            @NonNull HttpException error) {
        pending.fail(error.getClass().getSimpleName() + ": " + error.getMessage());
    }

    @Override
    public void onCanceled(@NonNull UrlRequest request, @Nullable UrlResponseInfo info) {
        pending.fail("canceled");
    }
}
