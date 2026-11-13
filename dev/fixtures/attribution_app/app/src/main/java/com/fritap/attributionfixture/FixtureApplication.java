package com.fritap.attributionfixture;

import android.app.Application;
import com.fritap.sdkalpha.AlphaSdk;
import com.fritap.sdkbeta.BetaSdk;
import java.util.Arrays;

/** Owns the process-wide scenario runner so the RUN broadcast works without the activity. */
public final class FixtureApplication extends Application {
    private ScenarioRunner runner;

    @Override
    public void onCreate() {
        super.onCreate();
        runner = new ScenarioRunner(this, Arrays.asList(new AlphaSdk(this), new BetaSdk(this)));
    }

    public ScenarioRunner runner() {
        return runner;
    }
}
