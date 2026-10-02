package df.root;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

import java.io.File;

public class BootReceiver extends BroadcastReceiver {
    private static final String TAG = "dfroot";

    @Override
    public void onReceive(Context context, Intent intent) {
        if (new File("/dev/df").exists() || new File("/dev/dfi").exists()) {
            Log.i(TAG, "boot: root stage already started, skipping");
            return;
        }
        Log.i(TAG, "boot: " + intent.getAction());
        Context deCtx = context.createDeviceProtectedStorageContext();
        boolean softReboot = deCtx.getSharedPreferences("dfroot", Context.MODE_PRIVATE)
                .getBoolean("auto_soft_reboot", true);
        Intent service = new Intent(deCtx, RootService.class)
                .putExtra(RootService.EXTRA_UNATTENDED_ONLY, true)
                .putExtra(RootService.EXTRA_SOFT_REBOOT, softReboot);
        deCtx.startForegroundService(service);
    }
}
