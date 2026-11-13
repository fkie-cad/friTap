package com.fritap.attributionfixture.common;

import android.content.Context;
import android.net.http.HttpEngine;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.webkit.WebView;
import androidx.annotation.RequiresApi;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import org.chromium.net.CronetEngine;
import org.chromium.net.UrlRequest;

/**
 * Scenario driver shared by the fake SDKs. It only sequences requests and records ground truth;
 * every engine build and request start is delegated to the concrete SDK class so the SDK package
 * is on the Java stack (and is the innermost app frame) when the transport is entered.
 */
public abstract class FixtureSdk {
    private static final long REQUEST_TIMEOUT_MS = 20_000;
    private static final long WEBVIEW_TIMEOUT_MS = 45_000; // first renderer start is slow on emulators
    private static final long WEBVIEW_INIT_TIMEOUT_MS = 90_000;
    private static final long SPACING_MS = 300;

    protected final Context appContext;
    private final String name;
    private final ExecutorService worker;
    private final ExecutorService callbackExecutor;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final EngineSlot<CronetEngine> embeddedEngine;
    private final EngineSlot<CronetEngine> gmsEngine;
    private final EngineSlot<HttpEngine> httpEngine;
    private WebView webView; // main thread only, created lazily on first load
    private final WebViewRecordingClient webViewClient = new WebViewRecordingClient();
    private int run;
    private int sequence;

    protected FixtureSdk(Context context, String name) {
        this.appContext = context.getApplicationContext();
        this.name = name;
        this.worker = NamedThreads.single(name + "-worker");
        this.callbackExecutor = NamedThreads.single(name + "-callbacks");
        this.embeddedEngine = new EngineSlot<>(() -> buildCronetEngine(CronetEngines.APP_PACKAGED));
        this.gmsEngine = new EngineSlot<>(() -> {
            GmsCronet.ensureInstalled(appContext);
            return buildCronetEngine(CronetEngines.GMS);
        });
        this.httpEngine = new EngineSlot<>(this::buildHttpEngineIfSupported);
    }

    public final String name() {
        return name;
    }

    /** Runs one round on this SDK's worker thread. */
    public final Future<?> submitRound(int runId, int round, EngineSlot<CronetEngine> sharedEngine) {
        return worker.submit(() -> {
            if (round == 0) {
                run = runId;
                sequence = 0;
            }
            runRound(sharedEngine);
        });
    }

    /**
     * Creates this SDK's WebView on the main thread and waits (bounded) for it, so the slow first
     * WebView/Chromium init does not eat into the first request's timeout. Call off the main thread.
     */
    public final void prepareWebView() {
        CountDownLatch ready = new CountDownLatch(1);
        mainHandler.post(() -> {
            ensureWebView();
            ready.countDown();
        });
        try {
            if (!ready.await(WEBVIEW_INIT_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                Log.w(CronetEngines.LOG_TAG, name + " WebView not ready after " + WEBVIEW_INIT_TIMEOUT_MS + " ms");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    // ---- hooks implemented inside the SDK packages ----

    protected abstract WebView createWebView(Context context);

    protected abstract CronetEngine buildCronetEngine(String providerName);

    @RequiresApi(34)
    protected abstract HttpEngine buildHttpEngine();

    protected abstract UrlRequest startCronetRequest(CronetEngine engine, String url,
            UrlRequest.Callback callback, Executor executor);

    @RequiresApi(34)
    protected abstract android.net.http.UrlRequest startHttpEngineRequest(HttpEngine engine, String url,
            android.net.http.UrlRequest.Callback callback, Executor executor);

    protected abstract void startWebViewLoad(WebView view, String url);

    // ---- scenario ----

    private void runRound(EngineSlot<CronetEngine> sharedEngine) {
        cronetPair(Transport.CRONET_EMBEDDED, embeddedEngine);
        cronetPair(Transport.CRONET_SHARED, sharedEngine);
        cronetPair(Transport.GMS_CRONET, gmsEngine);
        httpEnginePair();
        webViewLoad();
    }

    private void cronetPair(Transport transport, EngineSlot<CronetEngine> slot) {
        for (boolean quic : new boolean[] {false, true}) {
            CronetEngine engine = slot.get();
            issue(next(transport, quic), engine == null ? slot.failure() : null, pending -> {
                UrlRequest request = startCronetRequest(engine, pending.descriptor.url,
                        new CronetRecordingCallback(pending), callbackExecutor);
                return request::cancel;
            });
        }
    }

    private void httpEnginePair() {
        for (boolean quic : new boolean[] {false, true}) {
            HttpEngine engine = httpEngine.get();
            issue(next(Transport.HTTPENGINE, quic), engine == null ? httpEngine.failure() : null, pending -> {
                android.net.http.UrlRequest request = startHttpEngineRequest(engine, pending.descriptor.url,
                        new HttpEngineRecordingCallback(pending), callbackExecutor);
                return request::cancel;
            });
        }
    }

    private void webViewLoad() {
        RequestDescriptor descriptor = next(Transport.WEBVIEW, false);
        PendingRequest pending = new PendingRequest(descriptor);
        webViewClient.expect(pending);
        mainHandler.post(() -> {
            if (pending.isTerminal()) return; // already timed out while queued: never log start after fail
            GroundTruthLog.start(descriptor);
            startWebViewLoad(ensureWebView(), descriptor.url);
        });
        if (!pending.awaitOrTimeOut(WEBVIEW_TIMEOUT_MS)) mainHandler.post(() -> ensureWebView().stopLoading());
        pause();
    }

    /** Main thread only. Created on first use: WebView init in Application.onCreate ANRs slow devices. */
    private WebView ensureWebView() {
        if (webView == null) {
            webView = createWebView(appContext);
            webView.setWebViewClient(webViewClient);
        }
        return webView;
    }

    /** Logs start, starts the request via {@code starter} (returns a canceller), waits, spaces. */
    private void issue(RequestDescriptor descriptor, String unavailableReason,
            Function<PendingRequest, Runnable> starter) {
        if (unavailableReason != null) {
            GroundTruthLog.skip(descriptor, unavailableReason);
            return;
        }
        PendingRequest pending = new PendingRequest(descriptor);
        GroundTruthLog.start(descriptor);
        Runnable cancel = null;
        try {
            cancel = starter.apply(pending);
        } catch (RuntimeException e) {
            pending.fail("start failed: " + e);
        }
        if (!pending.awaitOrTimeOut(REQUEST_TIMEOUT_MS) && cancel != null) cancel.run();
        pause();
    }

    private RequestDescriptor next(Transport transport, boolean quicHost) {
        int n = ++sequence;
        String url = transport == Transport.WEBVIEW || !quicHost
                ? FixtureUrls.h2(name, transport, run, n)
                : FixtureUrls.h3(name, transport, run, n);
        return new RequestDescriptor(run, name, transport, n, url);
    }

    private HttpEngine buildHttpEngineIfSupported() {
        if (Build.VERSION.SDK_INT < 34) {
            throw new UnsupportedOperationException("HttpEngine requires API 34, device is " + Build.VERSION.SDK_INT);
        }
        return buildHttpEngine();
    }

    private static void pause() {
        try {
            Thread.sleep(SPACING_MS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
