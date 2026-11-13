package com.fritap.attributionfixture.common;

import android.content.Context;
import android.util.Log;
import java.util.ArrayList;
import java.util.List;
import org.chromium.net.CronetEngine;
import org.chromium.net.CronetProvider;

/** Builds Cronet engines pinned to an explicit provider, with H2 + QUIC enabled. */
public final class CronetEngines {
    public static final String APP_PACKAGED = CronetProvider.PROVIDER_NAME_APP_PACKAGED;
    public static final String GMS = "Google-Play-Services-Cronet-Provider";
    static final String LOG_TAG = "FritapFixture";

    private CronetEngines() {}

    /** @throws IllegalStateException if the named provider is missing or disabled. */
    public static CronetEngine build(Context context, String providerName, String owner) {
        List<String> seen = new ArrayList<>();
        for (CronetProvider provider : CronetProvider.getAllProviders(context)) {
            seen.add(provider.getName() + (provider.isEnabled() ? "" : "(disabled)"));
            if (provider.getName().equals(providerName) && provider.isEnabled()) {
                CronetEngine engine = configure(provider.createBuilder()).build();
                Log.i(LOG_TAG, owner + " built engine via provider " + provider.getName() + " "
                        + provider.getVersion() + " (" + engine.getVersionString() + ")");
                return engine;
            }
        }
        throw new IllegalStateException("cronet provider " + providerName + " unavailable; have " + seen);
    }

    private static CronetEngine.Builder configure(CronetEngine.Builder builder) {
        return builder.enableHttp2(true)
                .enableQuic(true)
                .enableBrotli(false)
                .addQuicHint(FixtureUrls.H3_HOST, 443, 443);
    }
}
