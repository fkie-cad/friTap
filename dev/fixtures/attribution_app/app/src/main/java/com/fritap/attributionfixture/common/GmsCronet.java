package com.fritap.attributionfixture.common;

import android.content.Context;
import android.util.Log;
import com.google.android.gms.net.CronetProviderInstaller;
import com.google.android.gms.tasks.Tasks;
import java.util.concurrent.TimeUnit;

/** Process-wide, one-shot installation of the Play Services Cronet provider. */
public final class GmsCronet {
    private static final long INSTALL_TIMEOUT_S = 30;
    private static String installFailure;
    private static boolean attempted;

    private GmsCronet() {}

    /** Blocks (bounded) until installed. Must not run on the main thread. */
    public static synchronized void ensureInstalled(Context context) {
        if (!attempted) {
            attempted = true;
            try {
                Tasks.await(CronetProviderInstaller.installProvider(context), INSTALL_TIMEOUT_S, TimeUnit.SECONDS);
                Log.i(CronetEngines.LOG_TAG, "GMS Cronet provider installed");
            } catch (Exception e) {
                installFailure = "gms installProvider failed: " + e;
                Log.w(CronetEngines.LOG_TAG, installFailure);
            }
        }
        if (installFailure != null) throw new IllegalStateException(installFailure);
    }
}
