package com.fritap.attributionfixture.common;

/** Identity of one ground-truth request. */
public final class RequestDescriptor {
    public final int run;
    public final String sdk;
    public final Transport transport;
    public final int n;
    public final String url;

    public RequestDescriptor(int run, String sdk, Transport transport, int n, String url) {
        this.run = run;
        this.sdk = sdk;
        this.transport = transport;
        this.n = n;
        this.url = url;
    }

    public String reqId() {
        return sdk + "-" + transport.label + "-" + run + "-" + n;
    }
}
