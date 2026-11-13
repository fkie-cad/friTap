package com.fritap.attributionfixture;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.widget.LinearLayout;
import android.widget.TextView;

/** Status screen; the SDKs' WebViews stay offscreen (never attached). Starts a run on {@code --ez autorun true}. */
public final class MainActivity extends Activity {
    public static final String EXTRA_AUTORUN = "autorun";
    private TextView status;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        status = new TextView(this);
        status.setText(R.string.status_idle);
        root.addView(status);
        setContentView(root);
        if (savedInstanceState == null) maybeAutorun(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        maybeAutorun(intent);
    }

    private void maybeAutorun(Intent intent) {
        if (intent == null || !intent.getBooleanExtra(EXTRA_AUTORUN, false)) return;
        int rounds = intent.getIntExtra(RunReceiver.EXTRA_ROUNDS, ScenarioRunner.DEFAULT_ROUNDS);
        status.setText(getString(R.string.status_running, rounds));
        runner().requestRun(rounds);
    }

    private ScenarioRunner runner() {
        return ((FixtureApplication) getApplication()).runner();
    }
}
