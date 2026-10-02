package df.root;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.IBinder;
import android.os.PowerManager;
import android.util.Log;

import java.util.concurrent.atomic.AtomicBoolean;

public final class RootService extends Service implements IReporter {
    private static final String TAG = "dfroot";
    private static final String CHANNEL = "root-operation";
    private static final int NOTIFICATION = 1701;
    static final String EXTRA_UNATTENDED_ONLY = "df.root.extra.UNATTENDED_ONLY";
    static final String EXTRA_SOFT_REBOOT = "df.root.extra.SOFT_REBOOT";

    private final AtomicBoolean running = new AtomicBoolean(false);

    @Override
    public void onCreate() {
        super.onCreate();
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager != null) {
            manager.createNotificationChannel(new NotificationChannel(
                    CHANNEL, "Root operation", NotificationManager.IMPORTANCE_LOW));
        }
        Notification notification = new Notification.Builder(this, CHANNEL)
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setContentTitle("DFRoot active")
                .setContentText("Patch restoration watchdog is running")
                .setOngoing(true)
                .build();
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION, notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(NOTIFICATION, notification);
        }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (!running.compareAndSet(false, true)) {
            Log.i(TAG, "root service already active; ignoring duplicate start");
            return START_NOT_STICKY;
        }
        boolean unattendedOnly = intent != null
                && intent.getBooleanExtra(EXTRA_UNATTENDED_ONLY, false);
        boolean softReboot = intent != null
                && intent.getBooleanExtra(EXTRA_SOFT_REBOOT, false);
        PowerManager manager = getSystemService(PowerManager.class);
        PowerManager.WakeLock wakeLock = manager == null ? null
                : manager.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK,
                                      "dfroot:operation");
        if (wakeLock != null) wakeLock.acquire(60000);
        new Thread(() -> {
            try {
                Context storage = createDeviceProtectedStorageContext();
                int rc = unattendedOnly
                        ? ExploitRunner.runUnattended(storage, this, softReboot)
                        : ExploitRunner.run(storage, this, softReboot);
                Log.i(TAG, "root service result=" + rc);
            } catch (Exception e) {
                Log.e(TAG, "root service exception", e);
            } finally {
                if (wakeLock != null && wakeLock.isHeld()) wakeLock.release();
                running.set(false);
                stopForeground(STOP_FOREGROUND_REMOVE);
                stopSelf();
            }
        }, "dfroot-operation").start();
        return START_NOT_STICKY;
    }

    @Override
    public void report(String message) {
        Log.i(TAG, message.trim());
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
