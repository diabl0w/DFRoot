package df.root;

import android.Manifest;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.util.Log;
import android.view.View;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;

import df.root.databinding.ActivityMainBinding;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.security.MessageDigest;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

public class MainActivity extends AppCompatActivity implements IReporter {

    private static final String TAG = "dfroot";

    private ActivityMainBinding binding;
    private Context deCtx;
    private final Handler mMain = new Handler(Looper.getMainLooper());
    private final Executor mExec = Executors.newSingleThreadExecutor();

    private final ActivityResultLauncher<String[]> mFilePicker = registerForActivityResult(
            new ActivityResultContracts.OpenDocument(),
            uri -> {
                if (uri != null) {
                    String filePath = getPathFromUri(uri);
                    if (filePath != null && !filePath.isEmpty()) {
                        saveCustomKsud(filePath);
                    } else {
                        report("failed to resolve file path\n");
                    }
                }
            });

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
        deCtx = createDeviceProtectedStorageContext();
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

        boolean autoSoftReboot = deCtx.getSharedPreferences("dfroot", MODE_PRIVATE)
                .getBoolean("auto_soft_reboot", true);
        binding.switchAutoSoftReboot.setChecked(autoSoftReboot);
        binding.switchAutoSoftReboot.setEnabled(bootEnabled);
        binding.switchAutoSoftReboot.setOnCheckedChangeListener((btn, checked) ->
            deCtx.getSharedPreferences("dfroot", MODE_PRIVATE)
                .edit().putBoolean("auto_soft_reboot", checked).apply());

        SharedPreferences prefs = deCtx.getSharedPreferences("dfroot", MODE_PRIVATE);
        boolean customKsud = prefs.getBoolean("custom_ksud", false);
        String customPath = prefs.getString("custom_ksud_path", null);

        if (customPath != null && !customPath.isEmpty()) {
            if (hasStoragePermission()) {
                File src = new File(customPath);
                if (!src.exists()) {
                    clearCustomKsud();
                    customKsud = false;
                    customPath = null;
                }
            }
        }

        binding.switchCustomKsud.setChecked(customKsud);
        if (customPath != null && !customPath.isEmpty()) {
            binding.btnSelectKsud.setText(customPath);
        } else {
            binding.btnSelectKsud.setText("Select ksud");
        }
        binding.btnSelectKsud.setVisibility(customKsud ? View.VISIBLE : View.GONE);

        binding.switchCustomKsud.setOnCheckedChangeListener((btn, checked) -> {
            if (checked) {
                deCtx.getSharedPreferences("dfroot", MODE_PRIVATE).edit().putBoolean("custom_ksud", true).apply();
                if (!hasStoragePermission()) requestStoragePermission();
                
                String path = deCtx.getSharedPreferences("dfroot", MODE_PRIVATE).getString("custom_ksud_path", null);
                binding.btnSelectKsud.setText(path != null && !path.isEmpty() ? path : "Select ksud");
                binding.btnSelectKsud.setVisibility(View.VISIBLE);
            } else {
                binding.btnSelectKsud.setVisibility(View.GONE);
                mExec.execute(() -> {
                    clearCustomKsud();
                });
            }
        });

        binding.btnSelectKsud.setOnClickListener(v -> {
            if (!hasStoragePermission()) {
                requestStoragePermission();
                return;
            }
            mFilePicker.launch(new String[]{"*/*"});
        });
    }

    private boolean hasStoragePermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            if (Environment.isExternalStorageManager()) return true;
        }
        return checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED;
    }

    private void requestStoragePermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            try {
                Intent intent = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION);
                intent.setData(Uri.parse("package:" + getPackageName()));
                startActivity(intent);
                return;
            } catch (Exception ignored) {}
            try {
                Intent intent = new Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION);
                startActivity(intent);
                return;
            } catch (Exception ignored) {}
        }
        requestPermissions(new String[]{Manifest.permission.READ_EXTERNAL_STORAGE}, 100);
    }

    @Override
    protected void onResume() {
        super.onResume();
        checkCustomKsudFileChange();
    }

    private String getPathFromUri(Uri uri) {
        if (uri == null) return null;
        if ("file".equalsIgnoreCase(uri.getScheme())) return uri.getPath();

        String decoded;
        try {
            decoded = URLDecoder.decode(uri.toString(), "UTF-8");
        } catch (Exception e) {
            decoded = uri.toString();
        }

        int idx;
        if ((idx = decoded.indexOf("/storage/")) != -1) return decoded.substring(idx);
        if ((idx = decoded.indexOf("/document/raw:")) != -1) return decoded.substring(idx + 14);
        if ((idx = decoded.indexOf("raw:")) != -1) return decoded.substring(idx + 4);
        if ((idx = decoded.indexOf("primary:")) != -1) return new File(Environment.getExternalStorageDirectory(), decoded.substring(idx + 8)).getAbsolutePath();

        String path = uri.getPath();
        if (path != null) {
            try {
                path = URLDecoder.decode(path, "UTF-8");
            } catch (Exception ignored) {}
            if ((idx = path.indexOf("primary:")) != -1) return new File(Environment.getExternalStorageDirectory(), path.substring(idx + 8)).getAbsolutePath();
        }
        return path;
    }

    private boolean copyFile(File src, File dest) {
        if (src == null || !src.exists()) return false;
        
        File dir = dest.getParentFile();
        if (dir != null && !dir.exists() && !dir.mkdirs()) {
            Log.e(TAG, "Failed to create dir: " + dir);
        }
        if (dir != null) {
            dir.setReadable(true, false);
            dir.setExecutable(true, false);
        }

        File tmp = new File(dir, "ksud.tmp");
        if (tmp.exists()) tmp.delete();

        long bytesCopied = 0;
        try (InputStream in = new FileInputStream(src); OutputStream out = new FileOutputStream(tmp)) {
            byte[] buf = new byte[8192];
            for (int n; (n = in.read(buf)) != -1; ) {
                out.write(buf, 0, n);
                bytesCopied += n;
            }
        } catch (Exception e) {
            Log.e(TAG, "copyFile failed", e);
            tmp.delete();
            return false;
        }

        if (bytesCopied == 0) {
            tmp.delete();
            return false;
        }

        if (dest.exists()) dest.delete();

        if (!tmp.renameTo(dest)) {
            Log.e(TAG, "rename failed");
            tmp.delete();
            return false;
        }

        if (!dest.setExecutable(true, false)) Log.w(TAG, "setExecutable returned false for " + dest);
        return true;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static String computeFileSha256(File file) {
        if (file == null || !file.exists()) return null;
        try (InputStream in = new FileInputStream(file)) {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[8192];
            int n;
            long total = 0;
            while ((n = in.read(buf)) != -1) {
                md.update(buf, 0, n);
                total += n;
            }
            if (total == 0) return null;
            return bytesToHex(md.digest());
        } catch (Exception e) {
            return null;
        }
    }

    private void clearCustomKsud() {
        File customKsud = ExploitRunner.getCustomKsudFile(deCtx);
        if (customKsud.exists()) customKsud.delete();
        deCtx.getSharedPreferences("dfroot", MODE_PRIVATE).edit()
                .putBoolean("custom_ksud", false)
                .remove("custom_ksud_path")
                .remove("custom_ksud_hash")
                .apply();
    }

    private void saveCustomKsud(String filePath) {
        mExec.execute(() -> {
            try {
                if (filePath == null || filePath.isEmpty()) throw new IOException("Invalid file path");
                File srcFile = new File(filePath);
                if (!srcFile.exists()) throw new IOException("File does not exist: " + filePath);

                File customKsud = ExploitRunner.getCustomKsudFile(deCtx);

                if (!copyFile(srcFile, customKsud)) throw new IOException("Cannot read or copy custom ksud from: " + filePath);

                String fileHash = computeFileSha256(customKsud);
                if (fileHash == null) fileHash = computeFileSha256(srcFile);

                deCtx.getSharedPreferences("dfroot", MODE_PRIVATE).edit()
                        .putBoolean("custom_ksud", true)
                        .putString("custom_ksud_path", filePath)
                        .putString("custom_ksud_hash", fileHash)
                        .apply();

                report("ksud copied to: " + customKsud.getAbsolutePath() + "\n");
                mMain.post(() -> {
                    binding.btnSelectKsud.setText(filePath);
                    binding.btnSelectKsud.setVisibility(View.VISIBLE);
                    binding.switchCustomKsud.setChecked(true);
                });
            } catch (Exception e) {
                report("failed to copy ksud: " + e.getMessage() + "\n");
            }
        });
    }

    private void checkCustomKsudFileChange() {
        mExec.execute(() -> {
            try {
                if (!hasStoragePermission()) return;

                SharedPreferences prefs = deCtx.getSharedPreferences("dfroot", MODE_PRIVATE);
                String pathStr = prefs.getString("custom_ksud_path", null);
                if (pathStr == null || pathStr.isEmpty()) return;

                File srcFile = new File(pathStr);
                File customKsud = ExploitRunner.getCustomKsudFile(deCtx);

                if (!srcFile.exists()) {
                    clearCustomKsud();
                    report("ksud is missing\n");
                    mMain.post(() -> {
                        binding.switchCustomKsud.setChecked(false);
                        binding.btnSelectKsud.setVisibility(View.GONE);
                        binding.btnSelectKsud.setText("select ksud");
                    });
                    return;
                }

                boolean destExists = customKsud.exists() && customKsud.length() > 0;
                String destHash = destExists ? computeFileSha256(customKsud) : null;
                String sourceHash = computeFileSha256(srcFile);
                String savedHash = prefs.getString("custom_ksud_hash", null);

                if (sourceHash == null) return;

                if (!destExists || savedHash == null || !sourceHash.equalsIgnoreCase(savedHash) || (destHash != null && !sourceHash.equalsIgnoreCase(destHash))) {
                    if (!copyFile(srcFile, customKsud)) {
                        report("failed to update ksud: cannot read source file (" + pathStr + ")\n");
                        return;
                    }

                    String newHash = computeFileSha256(customKsud);
                    prefs.edit().putString("custom_ksud_hash", newHash == null ? sourceHash : newHash).apply();

                    report("ksud updated :" + customKsud.getAbsolutePath() + "\n");
                    mMain.post(() -> {
                        binding.btnSelectKsud.setText(pathStr);
                        binding.btnSelectKsud.setVisibility(View.VISIBLE);
                    });
                }
            } catch (Exception e) {
                Log.e(TAG, "checkCustomKsudFileChange error", e);
            }
        });
    }

    private void runExploit(boolean softReboot) {
        try {
            int rc = ExploitRunner.run(deCtx, this, softReboot);
            String msg = rc == 0 ? "DFRoot: SUCCESS"
                       : rc == 1 ? "DFRoot FAILED: ksud exited with error"
                       : rc == 2 ? "DFRoot FAILED: check logs"
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

