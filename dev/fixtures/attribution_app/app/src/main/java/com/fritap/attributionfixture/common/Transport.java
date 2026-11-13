package com.fritap.attributionfixture.common;

/** Transport labels used in the ground-truth contract. */
public enum Transport {
    CRONET_EMBEDDED("cronet-embedded"),
    CRONET_SHARED("cronet-shared"),
    GMS_CRONET("gms-cronet"),
    HTTPENGINE("httpengine"),
    WEBVIEW("webview");

    public final String label;

    Transport(String label) {
        this.label = label;
    }
}
