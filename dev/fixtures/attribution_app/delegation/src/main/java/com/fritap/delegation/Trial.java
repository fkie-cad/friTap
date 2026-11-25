package com.fritap.delegation;

import android.app.Application;
import android.os.Bundle;
import android.os.Process;
import android.os.SystemClock;
import android.util.Log;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import org.json.JSONException;
import org.json.JSONObject;

final class Trial {
    static boolean validId(Bundle args) {
        String id = args.getString("id");
        return id != null && id.matches("[A-Za-z0-9_-]{1,64}");
    }

    static void log(Bundle args, String event) {
        try {
            Log.i("TLSHUNTER_FIXTURE", new JSONObject()
                    .put("id", args.getString("id")).put("event", event)
                    .put("pid", Process.myPid()).put("process", Application.getProcessName())
                    .put("device_ns", SystemClock.elapsedRealtimeNanos()).toString());
        } catch (JSONException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    static void run(Bundle args) {
        new Thread(() -> {
            // The emulator reaches its host at this fixed address.
            String host = "10.0.2.2";
            int port = 8443;
            int delay = Math.max(0, Math.min(5000, args.getInt("delay_ms")));
            try (Socket wire = new Socket()) {
                log(args, "connect_start");
                wire.connect(new InetSocketAddress(host, port), 3000);
                wire.setSoTimeout(8000);
                log(args, "connected");
                SystemClock.sleep(delay);
                SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
                try (SSLSocket tls = (SSLSocket) factory.createSocket(wire, host, port, true)) {
                    SSLParameters parameters = tls.getSSLParameters();
                    parameters.setEndpointIdentificationAlgorithm("HTTPS");
                    tls.setSSLParameters(parameters);
                    log(args, "handshake_start");
                    tls.startHandshake();
                    log(args, "handshake_complete");
                    String request = "GET /" + args.getString("id") + " HTTP/1.1\r\nHost: "
                            + host + "\r\nConnection: close\r\n\r\n";
                    tls.getOutputStream().write(request.getBytes(StandardCharsets.US_ASCII));
                    if (tls.getInputStream().read() != -1) log(args, "response");
                }
            } catch (java.io.IOException ex) {
                log(args, "network_failed");
            }
        }, "tlshunter-fixture").start();
    }
}
