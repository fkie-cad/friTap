package com.fritap.attributionfixture.common;

/** Builds the unique, path-addressable request URLs. */
public final class FixtureUrls {
    public static final String H2_HOST = "httpbingo.org";
    public static final String H3_HOST = "cloudflare-quic.com";

    private FixtureUrls() {}

    public static String h2(String sdk, Transport transport, int run, int n) {
        return "https://" + H2_HOST + "/anything/" + sdk + "/" + transport.label + "/" + run + "/" + n;
    }

    public static String h3(String sdk, Transport transport, int run, int n) {
        return "https://" + H3_HOST + "/fritap/" + sdk + "/" + transport.label + "/" + run + "/" + n;
    }
}
