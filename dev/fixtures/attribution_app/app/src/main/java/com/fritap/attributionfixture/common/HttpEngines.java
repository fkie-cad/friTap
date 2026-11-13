package com.fritap.attributionfixture.common;

import android.content.Context;
import android.net.http.HttpEngine;
import android.util.Log;
import androidx.annotation.RequiresApi;

/** Builds platform {@link HttpEngine}s (API 34+) with the same options as the Cronet engines. */
@RequiresApi(34)
public final class HttpEngines {
    private HttpEngines() {}

    public static HttpEngine build(Context context, String owner) {
        HttpEngine engine = new HttpEngine.Builder(context)
                .setEnableHttp2(true)
                .setEnableQuic(true)
                .addQuicHint(FixtureUrls.H3_HOST, 443, 443)
                .build();
        Log.i(CronetEngines.LOG_TAG, owner + " built platform HttpEngine " + HttpEngine.getVersionString());
        return engine;
    }
}
