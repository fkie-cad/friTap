package com.fritap.sdkbeta;

import android.content.Context;
import android.net.http.HttpEngine;
import android.webkit.WebView;
import androidx.annotation.RequiresApi;
import com.fritap.attributionfixture.common.CronetEngines;
import com.fritap.attributionfixture.common.FixtureSdk;
import com.fritap.attributionfixture.common.HttpEngines;
import java.util.concurrent.Executor;
import org.chromium.net.CronetEngine;
import org.chromium.net.UrlRequest;

/**
 * Fake third-party SDK "beta". Every engine build and request start happens in a method of
 * this class, so com.fritap.sdkbeta is on the Java stack when the transport is entered.
 */
public final class BetaSdk extends FixtureSdk {
    public static final String NAME = "beta";

    public BetaSdk(Context context) {
        super(context, NAME);
    }

    @Override
    protected WebView createWebView(Context context) {
        return new WebView(context);
    }

    @Override
    protected CronetEngine buildCronetEngine(String providerName) {
        return CronetEngines.build(appContext, providerName, NAME);
    }

    @RequiresApi(34)
    @Override
    protected HttpEngine buildHttpEngine() {
        return HttpEngines.build(appContext, NAME);
    }

    @Override
    protected UrlRequest startCronetRequest(CronetEngine engine, String url,
            UrlRequest.Callback callback, Executor executor) {
        UrlRequest request = engine.newUrlRequestBuilder(url, callback, executor)
                .addHeader("X-Fritap-Sdk", NAME)
                .build();
        request.start();
        return request;
    }

    @RequiresApi(34)
    @Override
    protected android.net.http.UrlRequest startHttpEngineRequest(HttpEngine engine, String url,
            android.net.http.UrlRequest.Callback callback, Executor executor) {
        android.net.http.UrlRequest request = engine.newUrlRequestBuilder(url, executor, callback)
                .addHeader("X-Fritap-Sdk", NAME)
                .build();
        request.start();
        return request;
    }

    @Override
    protected void startWebViewLoad(WebView view, String url) {
        view.loadUrl(url);
    }
}
