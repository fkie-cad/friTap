package com.fritap.attributionfixture;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/** {@code am broadcast -a com.fritap.attributionfixture.RUN -n <pkg>/.RunReceiver [--ei rounds N]}. */
public final class RunReceiver extends BroadcastReceiver {
    public static final String ACTION_RUN = "com.fritap.attributionfixture.RUN";
    public static final String EXTRA_ROUNDS = "rounds";

    @Override
    public void onReceive(Context context, Intent intent) {
        if (!ACTION_RUN.equals(intent.getAction())) return;
        int rounds = intent.getIntExtra(EXTRA_ROUNDS, ScenarioRunner.DEFAULT_ROUNDS);
        ((FixtureApplication) context.getApplicationContext()).runner().requestRun(rounds);
    }
}
