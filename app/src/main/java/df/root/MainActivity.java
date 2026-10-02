package df.root;

import android.content.ComponentName;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.View;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import df.root.databinding.ActivityMainBinding;

import java.io.File;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

public class MainActivity extends AppCompatActivity implements IReporter {

    private static final String TAG = "dfroot";

    private ActivityMainBinding binding;
    private final Handler mMain = new Handler(Looper.getMainLooper());
    private final Executor mExec = Executors.newSingleThreadExecutor();

    @Override
    public void report(String msg) {
        Log.i(TAG, msg.trim());
        mMain.post(() -> {
            binding.outputView.append(msg);
            binding.outputScroll.post(() -> binding.outputScroll.fullScroll(View.FOCUS_DOWN));
        });
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());
        setSupportActionBar(binding.toolbar);

        if (new File("/dev/df").exists()) binding.btnRun.setEnabled(false);

        binding.btnRun.setOnClickListener(v -> {
            binding.btnRun.setEnabled(false);
            binding.outputView.setText("");
            boolean softReboot = binding.switchManualSoftReboot.isChecked();
            mExec.execute(() -> runExploit(softReboot));
        });

        ComponentName bootReceiver = new ComponentName(this, BootReceiver.class);
        int state = getPackageManager().getComponentEnabledSetting(bootReceiver);
        boolean bootEnabled = state == PackageManager.COMPONENT_ENABLED_STATE_ENABLED;
        binding.switchBootStart.setChecked(bootEnabled);
        binding.switchBootStart.setOnCheckedChangeListener((btn, checked) -> {
            getPackageManager().setComponentEnabledSetting(bootReceiver,
                checked ? PackageManager.COMPONENT_ENABLED_STATE_ENABLED
                        : PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                PackageManager.DONT_KILL_APP);
            binding.switchAutoSoftReboot.setEnabled(checked);
        });

        boolean autoSoftReboot = createDeviceProtectedStorageContext()
                .getSharedPreferences("dfroot", MODE_PRIVATE)
                .getBoolean("auto_soft_reboot", true);
        binding.switchAutoSoftReboot.setChecked(autoSoftReboot);
        binding.switchAutoSoftReboot.setEnabled(bootEnabled);
        binding.switchAutoSoftReboot.setOnCheckedChangeListener((btn, checked) ->
            createDeviceProtectedStorageContext()
                .getSharedPreferences("dfroot", MODE_PRIVATE)
                .edit().putBoolean("auto_soft_reboot", checked).apply());
    }

    private void runExploit(boolean softReboot) {
        try {
            int rc = ExploitRunner.run(this, this, softReboot);
            String msg = rc == 0 ? "DFRoot: SUCCESS"
                       : rc == 1 ? "DFRoot FAILED: root stage exited with error"
                       : rc == 2 ? "DFRoot FAILED: check logs"
                       : rc == ExploitRunner.RESULT_WINDOW_RESTORED
                           ? "Patch window restored; verify the fresh ADB shell UID"
                       : rc == ExploitRunner.RESULT_UNSUPPORTED
                           ? "No exact runtime target matched"
                       : rc == ExploitRunner.RESULT_BUSY
                           ? "Another root operation is already active"
                       : rc == ExploitRunner.RESULT_INTERACTION_REQUIRED
                           ? "This target requires an interactive host trigger"
                       : "DFRoot FAILED: failed to patch files";
            mMain.post(() -> Toast.makeText(this, msg, Toast.LENGTH_LONG).show());
        } catch (Exception e) {
            Log.e(TAG, "exploit exception", e);
            report("\nexception: " + e + "\n");
        } finally {
            mMain.post(() -> binding.btnRun.setEnabled(!new File("/dev/df").exists()));
        }
    }
}
