package com.fritap.delegation;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;

public final class Driver extends Activity {
    private static final String WORKER = "com.fritap.delegation.worker";
    private ServiceConnection connection;

    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        runTrial(getIntent());
    }

    @Override public void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        releaseWorker();
        runTrial(intent);
    }

    private void runTrial(Intent intent) {
        String mode = intent.getStringExtra("mode");
        Bundle trial = intent.getExtras();
        if (trial == null || !Trial.validId(trial)) {
            finish();
            return;
        }
        Trial.log(trial, "action");
        if ("direct".equals(mode)) {
            Trial.run(trial);
        } else if ("ui".equals(mode)) {
            startActivity(new Intent().setClassName(WORKER, Idle.class.getName()));
        } else if ("local".equals(mode) || "delegate".equals(mode) || "control".equals(mode)) {
            String target = "local".equals(mode) ? getPackageName() : WORKER;
            connection = new ServiceConnection() {
                @Override public void onServiceConnected(ComponentName component, IBinder binder) {
                    Message message = Message.obtain(null, "control".equals(mode) ? 0 : 1);
                    message.setData(trial);
                    try {
                        new Messenger(binder).send(message);
                    } catch (RemoteException ex) {
                        Trial.log(trial, "binder_failed");
                    }
                }

                @Override public void onServiceDisconnected(ComponentName component) {}
            };
            if (!bindService(new Intent().setClassName(target, Worker.class.getName()),
                    connection, BIND_AUTO_CREATE)) {
                connection = null;
                Trial.log(trial, "bind_failed");
            }
        }
    }

    private void releaseWorker() {
        if (connection != null) {
            unbindService(connection);
            connection = null;
        }
    }

    @Override public void onDestroy() {
        releaseWorker();
        super.onDestroy();
    }
}
