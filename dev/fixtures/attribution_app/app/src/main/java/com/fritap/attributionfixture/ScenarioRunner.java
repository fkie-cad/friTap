package com.fritap.attributionfixture;

import android.content.Context;
import android.util.Log;
import com.fritap.attributionfixture.common.CronetEngines;
import com.fritap.attributionfixture.common.EngineSlot;
import com.fritap.attributionfixture.common.FixtureSdk;
import com.fritap.attributionfixture.common.NamedThreads;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.chromium.net.CronetEngine;

/** Runs scenario "runs": per round, all SDKs fire concurrently on their own worker threads. */
public final class ScenarioRunner {
    public static final int DEFAULT_ROUNDS = 3;
    private static final String LOG_TAG = "FritapFixture";
    private static final long ROUND_TIMEOUT_MIN = 5;

    private final List<FixtureSdk> sdks;
    private final ExecutorService coordinator = NamedThreads.single("fixture-run");
    private final EngineSlot<CronetEngine> sharedEngine;

    public ScenarioRunner(Context context, List<FixtureSdk> sdks) {
        Context appContext = context.getApplicationContext();
        this.sdks = sdks;
        this.sharedEngine = new EngineSlot<>(
                () -> CronetEngines.build(appContext, CronetEngines.APP_PACKAGED, "shared"));
    }

    /** Queues a run; runs never overlap. */
    public void requestRun(int rounds) {
        coordinator.execute(() -> runOnce(Math.max(1, rounds)));
    }

    private void runOnce(int rounds) {
        int runId = (int) (System.currentTimeMillis() / 1000L);
        sharedEngine.get(); // created by app code, on the coordinator thread
        for (FixtureSdk sdk : sdks) sdk.prepareWebView();
        Log.i(LOG_TAG, "run " + runId + " begin, rounds=" + rounds);
        for (int round = 0; round < rounds; round++) {
            List<Future<?>> inFlight = new ArrayList<>();
            for (FixtureSdk sdk : sdks) inFlight.add(sdk.submitRound(runId, round, sharedEngine));
            for (Future<?> f : inFlight) awaitRound(f);
        }
        Log.i(LOG_TAG, "run " + runId + " end");
    }

    private static void awaitRound(Future<?> future) {
        try {
            future.get(ROUND_TIMEOUT_MIN, TimeUnit.MINUTES);
        } catch (Exception e) {
            Log.w(LOG_TAG, "round did not complete cleanly: " + e);
        }
    }
}
