package com.fritap.delegation;

import android.app.Service;
import android.content.Intent;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Messenger;

public final class Worker extends Service {
    private final Messenger messenger = new Messenger(new Handler(Looper.getMainLooper(), message -> {
        if (!Trial.validId(message.getData())) return false;
        Trial.log(message.getData(), "binder_received");
        if (message.what == 1) Trial.run(message.getData());
        return true;
    }));

    @Override public IBinder onBind(Intent intent) {
        return messenger.getBinder();
    }
}
