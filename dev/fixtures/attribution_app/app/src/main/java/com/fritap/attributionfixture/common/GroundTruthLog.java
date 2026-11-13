package com.fritap.attributionfixture.common;

import android.util.Log;

/** Emits the FRITAP_GT logcat contract: one compact JSON object per INFO line. */
public final class GroundTruthLog {
    public static final String TAG = "FRITAP_GT";
    private static final int MAX_TEXT = 200;

    private GroundTruthLog() {}

    public static void start(RequestDescriptor d) {
        emit(base("start", d));
    }

    public static void done(RequestDescriptor d, int status, String protocol, boolean cached) {
        emit(base("done", d).put("status", status).put("protocol", protocol == null ? "" : protocol)
                .put("cached", cached));
    }

    public static void fail(RequestDescriptor d, String error) {
        emit(base("fail", d).put("error", shorten(error)));
    }

    public static void skip(RequestDescriptor d, String reason) {
        emit(base("skip", d).put("reason", shorten(reason)));
    }

    private static JsonLine base(String event, RequestDescriptor d) {
        return new JsonLine().put("v", 1).put("event", event).put("run", d.run).put("sdk", d.sdk)
                .put("transport", d.transport.label).put("req_id", d.reqId()).put("url", d.url)
                .put("method", "GET").put("t_ms", System.currentTimeMillis())
                .put("thread", Thread.currentThread().getName());
    }

    private static String shorten(String text) {
        String single = String.valueOf(text).replaceAll("\\s+", " ").trim();
        return single.length() <= MAX_TEXT ? single : single.substring(0, MAX_TEXT);
    }

    private static void emit(JsonLine line) {
        Log.i(TAG, line.toString());
    }
}
