package df.root;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.PowerManager;
import android.util.Log;


public class BootReceiver extends BroadcastReceiver implements IReporter {
    private static final String TAG = "dfroot";

    @Override
    public void report(String msg) {
        Log.i(TAG, msg.trim());
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        Log.i(TAG, "boot: " + intent.getAction());
        final Context deCtx = context.createDeviceProtectedStorageContext();
        PowerManager pm = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
        PowerManager.WakeLock wl = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "dfroot:boot");
        wl.acquire();
        new Thread(() -> {
            try {
                android.content.SharedPreferences prefs = deCtx.getSharedPreferences(
                        ExploitRunner.PREFS_NAME, Context.MODE_PRIVATE);
                if (prefs.getBoolean(ExploitRunner.PREF_SOFT_REBOOT, false)) {
                    if (prefs.getBoolean(ExploitRunner.PREF_BOOT_REBOOT_GUARD, false)) {
                        Log.i(TAG, "boot: reboot guard set, skipping exploit to prevent bootloop");
                        prefs.edit().remove(ExploitRunner.PREF_BOOT_REBOOT_GUARD).apply();
                        return;
                    }
                    prefs.edit().putBoolean(ExploitRunner.PREF_BOOT_REBOOT_GUARD, true).apply();
                }
                int rc = ExploitRunner.run(deCtx, this);
                Log.i(TAG, "boot: exploit rc=" + rc);
            } catch (Exception e) {
                Log.e(TAG, "boot: exploit exception", e);
            } finally {
                wl.release();
            }
        }, "dfroot-boot").start();
    }
}
