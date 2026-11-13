package com.fritap.attributionfixture.common;

import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebView;
import android.webkit.WebViewClient;

/** Maps WebView page lifecycle callbacks onto the currently expected {@link PendingRequest}. */
public final class WebViewRecordingClient extends WebViewClient {
    private static final int STATUS_UNKNOWN = 0;
    private volatile PendingRequest expected;
    private volatile int mainFrameStatus = STATUS_UNKNOWN;

    public void expect(PendingRequest pending) {
        mainFrameStatus = STATUS_UNKNOWN;
        expected = pending;
    }

    @Override
    public void onPageFinished(WebView view, String url) {
        PendingRequest pending = expected;
        if (pending != null && url != null && url.startsWith(pending.descriptor.url)) {
            pending.succeed(mainFrameStatus, "", false);
        }
    }

    @Override
    public void onReceivedHttpError(WebView view, WebResourceRequest request, WebResourceResponse response) {
        if (request.isForMainFrame()) mainFrameStatus = response.getStatusCode();
    }

    @Override
    public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
        PendingRequest pending = expected;
        if (pending != null && request.isForMainFrame()) {
            pending.fail("webview error " + error.getErrorCode() + ": " + error.getDescription());
        }
    }
}
