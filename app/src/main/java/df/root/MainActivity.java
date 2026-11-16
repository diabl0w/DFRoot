package df.root;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;
import android.util.Log;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.MotionEvent;
import android.view.VelocityTracker;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.OverScroller;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

public class MainActivity extends Activity implements IReporter {

    private static final String TAG = "PixelRoot";
    private static final int REQ_INSTALL_MODULE = 1001;

    private Button btnRun;
    private ScrollView outputScroll;
    private TextView outputView;
    private TextView previewLogView;
    private TextView statusBadgeView;
    private Spinner spinnerSuManager;
    private LinearLayout modulesListContainer;
    private TextView modulesHeaderSubtitle;

    private CarouselPager carouselPager;
    private View navPillIndicator;
    private final TextView[] navLabels = new TextView[3];
    private final CrosshairTabIcon[] navIcons = new CrosshairTabIcon[3];

    private Context mDeCtx;
    private final Handler mMain = new Handler(Looper.getMainLooper());
    private final Executor mExec = Executors.newSingleThreadExecutor();
    private int mValidSuManagerPos = 0;
    private volatile boolean mIsRootActive = false;

    @Override
    public void report(String msg) {
        Log.i(TAG, msg.trim());
        mMain.post(() -> {
            if (outputView != null) {
                outputView.append(msg);
                outputScroll.post(() -> outputScroll.fullScroll(View.FOCUS_DOWN));
            }
            if (previewLogView != null) {
                String full = outputView != null ? outputView.getText().toString().trim() : msg.trim();
                String[] lines = full.split("\n");
                int start = Math.max(0, lines.length - 4);
                StringBuilder sb = new StringBuilder();
                for (int i = start; i < lines.length; i++) {
                    if (sb.length() > 0) sb.append("\n");
                    sb.append(lines[i]);
                }
                previewLogView.setText(sb.toString());
            }
        });
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        mDeCtx = createDeviceProtectedStorageContext();

        if (getActionBar() != null) {
            getActionBar().setTitle("PixelRoot");
            getActionBar().setSubtitle("Monochrome SU & KernelSU Bridge");
        }

        buildCarouselUi();
        setupSuManagerSpinner();
        updateRunButton();
        refreshRootStatusAndModules();
    }

    private int dp(int value) {
        return Math.round(TypedValue.applyDimension(
                TypedValue.COMPLEX_UNIT_DIP, value, getResources().getDisplayMetrics()));
    }

    private GradientDrawable roundedBox(int fillColor, int strokeColor, int radiusDp) {
        GradientDrawable gd = new GradientDrawable();
        gd.setColor(fillColor);
        gd.setCornerRadius(dp(radiusDp));
        if (strokeColor != Color.TRANSPARENT) {
            gd.setStroke(dp(1), strokeColor);
        }
        return gd;
    }

    private void buildCarouselUi() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Color.BLACK);
        root.setFitsSystemWindows(true);

        carouselPager = new CarouselPager(this, dp(12));
        LinearLayout.LayoutParams pagerLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f);
        carouselPager.setLayoutParams(pagerLp);

        carouselPager.addView(buildLauncherPage());
        carouselPager.addView(buildRootLogPage());
        carouselPager.addView(buildModulesPage());

        View divider = new View(this);
        divider.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(1)));
        divider.setBackgroundColor(Color.parseColor("#1C1C1C"));

        View bottomBar = buildBottomNavBar();

        root.addView(carouselPager);
        root.addView(divider);
        root.addView(bottomBar);
        setContentView(root);

        carouselPager.setPageListener(new CarouselPager.OnPageChangeListener() {
            @Override
            public void onPageScrolled(float positionOffsetTotal) {
                updateNavPillPosition(positionOffsetTotal);
            }

            @Override
            public void onPageSelected(int page) {
                updateNavSelection(page);
                if (page == 2) {
                    refreshRootStatusAndModules();
                }
            }
        });
        updateNavSelection(0);
    }

    private View buildLauncherPage() {
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);

        LinearLayout container = new LinearLayout(this);
        container.setOrientation(LinearLayout.VERTICAL);
        container.setPadding(dp(16), dp(14), dp(16), dp(16));

        // Hero Card with Crosshair Emblem
        LinearLayout heroCard = new LinearLayout(this);
        heroCard.setOrientation(LinearLayout.HORIZONTAL);
        heroCard.setGravity(Gravity.CENTER_VERTICAL);
        heroCard.setPadding(dp(16), dp(16), dp(16), dp(16));
        heroCard.setBackground(roundedBox(Color.parseColor("#0E0E0E"), Color.parseColor("#242424"), 20));

        CrosshairLogoView logo = new CrosshairLogoView(this);
        LinearLayout.LayoutParams logoLp = new LinearLayout.LayoutParams(dp(44), dp(44));
        logoLp.rightMargin = dp(14);
        heroCard.addView(logo, logoLp);

        LinearLayout heroTextCol = new LinearLayout(this);
        heroTextCol.setOrientation(LinearLayout.VERTICAL);
        heroTextCol.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        TextView heroTitle = new TextView(this);
        heroTitle.setText("PixelRoot");
        heroTitle.setTextColor(Color.WHITE);
        heroTitle.setTextSize(TypedValue.COMPLEX_UNIT_SP, 19);
        heroTitle.setTypeface(Typeface.DEFAULT_BOLD);

        TextView heroSub = new TextView(this);
        heroSub.setText(System.getProperty("os.version", "5.15.189-android13-8"));
        heroSub.setTextColor(Color.parseColor("#9E9E9E"));
        heroSub.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        heroSub.setSingleLine(true);
        heroSub.setEllipsize(TextUtils.TruncateAt.END);

        heroTextCol.addView(heroTitle);
        heroTextCol.addView(heroSub);
        heroCard.addView(heroTextCol);

        statusBadgeView = new TextView(this);
        statusBadgeView.setText("CHECKING");
        statusBadgeView.setTextColor(Color.WHITE);
        statusBadgeView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        statusBadgeView.setTypeface(Typeface.DEFAULT_BOLD);
        statusBadgeView.setPadding(dp(10), dp(5), dp(10), dp(5));
        statusBadgeView.setBackground(roundedBox(Color.parseColor("#1D1D1D"), Color.parseColor("#333333"), 12));
        heroCard.addView(statusBadgeView);

        container.addView(heroCard);

        // SU Manager Card
        LinearLayout managerCard = new LinearLayout(this);
        managerCard.setOrientation(LinearLayout.VERTICAL);
        managerCard.setPadding(dp(16), dp(14), dp(16), dp(12));
        managerCard.setBackground(roundedBox(Color.parseColor("#0E0E0E"), Color.parseColor("#242424"), 20));
        LinearLayout.LayoutParams mgrLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        mgrLp.topMargin = dp(12);
        managerCard.setLayoutParams(mgrLp);

        TextView mgrLabel = new TextView(this);
        mgrLabel.setText("SU Manager Bridge");
        mgrLabel.setTextColor(Color.parseColor("#BDBDBD"));
        mgrLabel.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        mgrLabel.setTypeface(Typeface.DEFAULT_BOLD);
        managerCard.addView(mgrLabel);

        spinnerSuManager = new Spinner(this);
        LinearLayout.LayoutParams spLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        spLp.topMargin = dp(6);
        spinnerSuManager.setLayoutParams(spLp);
        managerCard.addView(spinnerSuManager);

        container.addView(managerCard);

        // Primary Monochrome Action Button
        btnRun = new Button(this);
        btnRun.setText("Launch Root");
        btnRun.setTextSize(TypedValue.COMPLEX_UNIT_SP, 15);
        btnRun.setTypeface(Typeface.DEFAULT_BOLD);
        btnRun.setAllCaps(false);
        LinearLayout.LayoutParams btnLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(52));
        btnLp.topMargin = dp(14);
        btnRun.setLayoutParams(btnLp);
        btnRun.setOnClickListener(v -> {
            btnRun.setEnabled(false);
            outputView.setText("");
            previewLogView.setText("Starting privilege escalation...");
            carouselPager.setCurrentPage(1, true);
            mExec.execute(this::runExploit);
        });
        container.addView(btnRun);

        // Live Log Preview Card
        LinearLayout previewCard = new LinearLayout(this);
        previewCard.setOrientation(LinearLayout.VERTICAL);
        previewCard.setPadding(dp(16), dp(14), dp(16), dp(14));
        previewCard.setBackground(roundedBox(Color.parseColor("#0A0A0A"), Color.parseColor("#202020"), 20));
        LinearLayout.LayoutParams prevLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        prevLp.topMargin = dp(14);
        previewCard.setLayoutParams(prevLp);
        previewCard.setOnClickListener(v -> carouselPager.setCurrentPage(1, true));

        LinearLayout prevHeader = new LinearLayout(this);
        prevHeader.setOrientation(LinearLayout.HORIZONTAL);
        TextView prevTitle = new TextView(this);
        prevTitle.setText("Live Execution Preview");
        prevTitle.setTextColor(Color.WHITE);
        prevTitle.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        prevTitle.setTypeface(Typeface.DEFAULT_BOLD);
        prevTitle.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        TextView prevOpen = new TextView(this);
        prevOpen.setText("Open Log >");
        prevOpen.setTextColor(Color.parseColor("#9E9E9E"));
        prevOpen.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);

        prevHeader.addView(prevTitle);
        prevHeader.addView(prevOpen);
        previewCard.addView(prevHeader);

        previewLogView = new TextView(this);
        previewLogView.setText("Swipe left or tap a tab below to switch views.");
        previewLogView.setTextColor(Color.parseColor("#B0B0B0"));
        previewLogView.setTypeface(Typeface.MONOSPACE);
        previewLogView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        LinearLayout.LayoutParams prevTxtLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        prevTxtLp.topMargin = dp(8);
        previewLogView.setLayoutParams(prevTxtLp);
        previewCard.addView(previewLogView);

        container.addView(previewCard);
        scroll.addView(container);
        return scroll;
    }

    private View buildRootLogPage() {
        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setPadding(dp(16), dp(14), dp(16), dp(14));

        LinearLayout header = new LinearLayout(this);
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setGravity(Gravity.CENTER_VERTICAL);

        TextView title = new TextView(this);
        title.setText("Root Execution Log");
        title.setTextColor(Color.WHITE);
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        title.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        header.addView(title);

        TextView btnCopy = new TextView(this);
        btnCopy.setText("Copy");
        btnCopy.setTextColor(Color.BLACK);
        btnCopy.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        btnCopy.setTypeface(Typeface.DEFAULT_BOLD);
        btnCopy.setPadding(dp(12), dp(6), dp(12), dp(6));
        btnCopy.setBackground(roundedBox(Color.WHITE, Color.TRANSPARENT, 14));
        btnCopy.setOnClickListener(v -> {
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm != null) {
                cm.setPrimaryClip(ClipData.newPlainText("PixelRoot Log", outputView.getText()));
                Toast.makeText(this, "Log copied", Toast.LENGTH_SHORT).show();
            }
        });
        header.addView(btnCopy);

        TextView btnClear = new TextView(this);
        btnClear.setText("Clear");
        btnClear.setTextColor(Color.WHITE);
        btnClear.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        btnClear.setPadding(dp(12), dp(6), dp(12), dp(6));
        btnClear.setBackground(roundedBox(Color.parseColor("#181818"), Color.parseColor("#2E2E2E"), 14));
        LinearLayout.LayoutParams clrLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        clrLp.leftMargin = dp(8);
        btnClear.setLayoutParams(clrLp);
        btnClear.setOnClickListener(v -> outputView.setText(""));
        header.addView(btnClear);

        page.addView(header);

        outputScroll = new ScrollView(this);
        outputScroll.setBackground(roundedBox(Color.parseColor("#0A0A0A"), Color.parseColor("#222222"), 18));
        outputScroll.setPadding(dp(12), dp(12), dp(12), dp(12));
        LinearLayout.LayoutParams scLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f);
        scLp.topMargin = dp(12);
        outputScroll.setLayoutParams(scLp);

        outputView = new TextView(this);
        outputView.setLayoutParams(new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        outputView.setTypeface(Typeface.MONOSPACE);
        outputView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        outputView.setTextColor(Color.parseColor("#EAEAEA"));
        outputView.setTextIsSelectable(true);
        outputView.setText("[PIXELROOT] Ready. Kernel: " + System.getProperty("os.version", "unknown") + "\n");

        outputScroll.addView(outputView);
        page.addView(outputScroll);
        return page;
    }

    private View buildModulesPage() {
        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setPadding(dp(16), dp(14), dp(16), dp(14));

        LinearLayout header = new LinearLayout(this);
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setGravity(Gravity.CENTER_VERTICAL);

        LinearLayout titleCol = new LinearLayout(this);
        titleCol.setOrientation(LinearLayout.VERTICAL);
        titleCol.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        TextView title = new TextView(this);
        title.setText("KernelSU Modules");
        title.setTextColor(Color.WHITE);
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16);
        title.setTypeface(Typeface.DEFAULT_BOLD);

        modulesHeaderSubtitle = new TextView(this);
        modulesHeaderSubtitle.setText("/data/adb/modules");
        modulesHeaderSubtitle.setTextColor(Color.parseColor("#9E9E9E"));
        modulesHeaderSubtitle.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);

        titleCol.addView(title);
        titleCol.addView(modulesHeaderSubtitle);
        header.addView(titleCol);

        TextView btnInstall = new TextView(this);
        btnInstall.setText("+ Install Zip");
        btnInstall.setTextColor(Color.BLACK);
        btnInstall.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        btnInstall.setTypeface(Typeface.DEFAULT_BOLD);
        btnInstall.setPadding(dp(14), dp(8), dp(14), dp(8));
        btnInstall.setBackground(roundedBox(Color.WHITE, Color.TRANSPARENT, 16));
        btnInstall.setOnClickListener(v -> {
            Intent pick = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            pick.addCategory(Intent.CATEGORY_OPENABLE);
            pick.setType("application/zip");
            startActivityForResult(pick, REQ_INSTALL_MODULE);
        });
        header.addView(btnInstall);

        page.addView(header);

        ScrollView modScroll = new ScrollView(this);
        LinearLayout.LayoutParams scLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f);
        scLp.topMargin = dp(12);
        modScroll.setLayoutParams(scLp);

        modulesListContainer = new LinearLayout(this);
        modulesListContainer.setOrientation(LinearLayout.VERTICAL);
        modScroll.addView(modulesListContainer);
        page.addView(modScroll);

        return page;
    }

    private View buildBottomNavBar() {
        FrameLayout barWrapper = new FrameLayout(this);
        barWrapper.setBackgroundColor(Color.parseColor("#0A0A0A"));
        barWrapper.setPadding(dp(12), dp(8), dp(12), dp(10));

        // Sliding monochrome pill indicator
        navPillIndicator = new View(this);
        navPillIndicator.setBackground(roundedBox(Color.WHITE, Color.TRANSPARENT, 20));
        FrameLayout.LayoutParams pillLp = new FrameLayout.LayoutParams(dp(84), dp(34));
        pillLp.gravity = Gravity.TOP | Gravity.START;
        navPillIndicator.setLayoutParams(pillLp);
        barWrapper.addView(navPillIndicator);

        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setWeightSum(3f);
        row.setLayoutParams(new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        String[] titles = {"Launcher", "Root Log", "Modules"};
        for (int i = 0; i < 3; i++) {
            final int index = i;
            LinearLayout tab = new LinearLayout(this);
            tab.setOrientation(LinearLayout.VERTICAL);
            tab.setGravity(Gravity.CENTER);
            tab.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
            tab.setOnClickListener(v -> carouselPager.setCurrentPage(index, true));

            CrosshairTabIcon icon = new CrosshairTabIcon(this, i);
            LinearLayout.LayoutParams iconLp = new LinearLayout.LayoutParams(dp(24), dp(34));
            tab.addView(icon, iconLp);
            navIcons[i] = icon;

            TextView label = new TextView(this);
            label.setText(titles[i]);
            label.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
            label.setGravity(Gravity.CENTER);
            LinearLayout.LayoutParams lblLp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            lblLp.topMargin = dp(4);
            tab.addView(label, lblLp);
            navLabels[i] = label;

            row.addView(tab);
        }

        barWrapper.addView(row);
        barWrapper.post(() -> updateNavPillPosition(carouselPager.getCurrentPage()));
        return barWrapper;
    }

    private void updateNavPillPosition(float pageFloat) {
        if (navPillIndicator == null || navPillIndicator.getParent() == null) return;
        View parent = (View) navPillIndicator.getParent();
        int innerWidth = parent.getWidth() - parent.getPaddingLeft() - parent.getPaddingRight();
        if (innerWidth <= 0) return;
        float tabWidth = innerWidth / 3f;
        float pillWidth = navPillIndicator.getWidth();
        float x = (tabWidth * pageFloat) + (tabWidth - pillWidth) / 2f;
        navPillIndicator.setTranslationX(x);
    }

    private void updateNavSelection(int selected) {
        for (int i = 0; i < 3; i++) {
            boolean active = (i == selected);
            if (navIcons[i] != null) navIcons[i].setSelectedState(active);
            if (navLabels[i] != null) {
                navLabels[i].setTextColor(active ? Color.WHITE : Color.parseColor("#888888"));
                navLabels[i].setTypeface(active ? Typeface.DEFAULT_BOLD : Typeface.DEFAULT);
            }
        }
        updateNavPillPosition(selected);
    }

    private void refreshRootStatusAndModules() {
        mExec.execute(() -> {
            String idOut = runRootCmd("id 2>/dev/null").trim();
            String ksuVer = runRootCmd("/data/adb/ksud -V 2>/dev/null || su -v 2>/dev/null").trim();
            boolean rooted = idOut.contains("uid=0") || !ksuVer.isEmpty() || new File("/dev/df").exists();
            mIsRootActive = rooted;
            String rawMods = runRootCmd("ls -1 /data/adb/modules 2>/dev/null");

            List<ModuleItem> items = new ArrayList<>();
            if (!rawMods.trim().isEmpty()) {
                for (String dirName : rawMods.trim().split("\n")) {
                    String id = dirName.trim();
                    if (id.isEmpty()) continue;
                    String prop = runRootCmd("cat /data/adb/modules/" + id + "/module.prop 2>/dev/null");
                    String flags = runRootCmd("[ -f /data/adb/modules/" + id + "/disable ] && echo disabled; [ -f /data/adb/modules/" + id + "/remove ] && echo removed");
                    items.add(ModuleItem.parse(id, prop, flags));
                }
            }

            mMain.post(() -> {
                if (statusBadgeView != null) {
                    if (rooted) {
                        statusBadgeView.setText("ACTIVE");
                        statusBadgeView.setTextColor(Color.BLACK);
                        statusBadgeView.setBackground(roundedBox(Color.WHITE, Color.TRANSPARENT, 12));
                    } else {
                        statusBadgeView.setText("STANDBY");
                        statusBadgeView.setTextColor(Color.WHITE);
                        statusBadgeView.setBackground(roundedBox(Color.parseColor("#1D1D1D"), Color.parseColor("#333333"), 12));
                    }
                }
                if (modulesHeaderSubtitle != null) {
                    modulesHeaderSubtitle.setText(ksuVer.isEmpty()
                            ? "/data/adb/modules (" + items.size() + ")"
                            : ksuVer + " • " + items.size() + " module(s)");
                }
                renderModules(items);
                updateRunButton();
            });
        });
    }

    private void renderModules(List<ModuleItem> items) {
        if (modulesListContainer == null) return;
        modulesListContainer.removeAllViews();

        if (items.isEmpty()) {
            TextView empty = new TextView(this);
            empty.setText("No KernelSU modules found in /data/adb/modules.\nTap '+ Install Zip' above to flash a module.");
            empty.setTextColor(Color.parseColor("#888888"));
            empty.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
            empty.setPadding(dp(16), dp(24), dp(16), dp(24));
            empty.setGravity(Gravity.CENTER);
            empty.setBackground(roundedBox(Color.parseColor("#0D0D0D"), Color.parseColor("#202020"), 18));
            modulesListContainer.addView(empty);
            return;
        }

        for (ModuleItem mod : items) {
            LinearLayout card = new LinearLayout(this);
            card.setOrientation(LinearLayout.VERTICAL);
            card.setPadding(dp(14), dp(14), dp(14), dp(14));
            card.setBackground(roundedBox(Color.parseColor("#0E0E0E"), Color.parseColor("#242424"), 18));
            LinearLayout.LayoutParams cardLp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            cardLp.bottomMargin = dp(10);
            card.setLayoutParams(cardLp);

            LinearLayout topRow = new LinearLayout(this);
            topRow.setOrientation(LinearLayout.HORIZONTAL);
            topRow.setGravity(Gravity.CENTER_VERTICAL);

            LinearLayout infoCol = new LinearLayout(this);
            infoCol.setOrientation(LinearLayout.VERTICAL);
            infoCol.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

            TextView nameView = new TextView(this);
            nameView.setText(mod.name + "  " + mod.version);
            nameView.setTextColor(Color.WHITE);
            nameView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
            nameView.setTypeface(Typeface.DEFAULT_BOLD);

            TextView authorView = new TextView(this);
            authorView.setText("by " + mod.author + (mod.removed ? " • Will remove on reboot" : ""));
            authorView.setTextColor(Color.parseColor("#9E9E9E"));
            authorView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);

            infoCol.addView(nameView);
            infoCol.addView(authorView);
            topRow.addView(infoCol);

            Switch toggle = new Switch(this);
            toggle.setChecked(!mod.disabled);
            toggle.setOnCheckedChangeListener((buttonView, isChecked) -> mExec.execute(() -> {
                String path = "/data/adb/modules/" + mod.id + "/disable";
                if (isChecked) {
                    runRootCmd("rm -f '" + path + "'");
                } else {
                    runRootCmd("touch '" + path + "'");
                }
                refreshRootStatusAndModules();
            }));
            topRow.addView(toggle);
            card.addView(topRow);

            if (!mod.description.isEmpty()) {
                TextView desc = new TextView(this);
                desc.setText(mod.description);
                desc.setTextColor(Color.parseColor("#BDBDBD"));
                desc.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
                LinearLayout.LayoutParams descLp = new LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
                descLp.topMargin = dp(8);
                desc.setLayoutParams(descLp);
                card.addView(desc);
            }

            modulesListContainer.addView(card);
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_INSTALL_MODULE && resultCode == RESULT_OK && data != null && data.getData() != null) {
            final Uri uri = data.getData();
            carouselPager.setCurrentPage(1, true);
            mExec.execute(() -> {
                try {
                    File tmpZip = new File(getCacheDir(), "pixelroot_mod.zip");
                    try (InputStream in = getContentResolver().openInputStream(uri);
                         FileOutputStream out = new FileOutputStream(tmpZip)) {
                        if (in == null) return;
                        byte[] buf = new byte[8192];
                        int n;
                        while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
                    }
                    report("\n[KSUD] Installing module zip...\n");
                    String res = runRootCmd("/data/adb/ksud module install '" + tmpZip.getAbsolutePath() + "' 2>&1");
                    report(res + "\n[KSUD] Done.\n");
                    tmpZip.delete();
                    refreshRootStatusAndModules();
                } catch (Exception e) {
                    report("[KSUD] Install error: " + e + "\n");
                }
            });
        }
    }

    private String runRootCmd(String cmd) {
        try {
            Process p = new ProcessBuilder("su", "-c", cmd).redirectErrorStream(true).start();
            StringBuilder sb = new StringBuilder();
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = r.readLine()) != null) {
                    sb.append(line).append("\n");
                }
            }
            p.waitFor();
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    private void setupSuManagerSpinner() {
        PackageManager pm = getPackageManager();
        List<SuManagerEntry> entries = new ArrayList<>();
        for (ApplicationInfo ai : pm.getInstalledApplications(0)) {
            if ((ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0) continue;
            if (!ExploitRunner.hasKsud(ai)) continue;
            entries.add(new SuManagerEntry(ai.packageName, pm.getApplicationLabel(ai), pm.getApplicationIcon(ai)));
        }
        entries.sort((a, b) -> a.label.toString().compareToIgnoreCase(b.label.toString()));
        entries.add(0, new SuManagerEntry(null, "Select a SU Manager", null));

        spinnerSuManager.setAdapter(new SuManagerAdapter(this, entries));

        SharedPreferences prefs = mDeCtx.getSharedPreferences(ExploitRunner.PREFS_NAME, Context.MODE_PRIVATE);
        String saved = prefs.getString(ExploitRunner.PREF_SU_MANAGER, null);
        boolean savedFound = false;
        for (int i = 1; i < entries.size(); i++) {
            if (entries.get(i).packageName.equals(saved)) {
                spinnerSuManager.setSelection(i);
                mValidSuManagerPos = i;
                savedFound = true;
                break;
            }
        }
        if (!savedFound && saved != null) {
            prefs.edit().remove(ExploitRunner.PREF_SU_MANAGER).apply();
        }

        spinnerSuManager.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int pos, long id) {
                SuManagerEntry e = entries.get(pos);
                if (e.packageName == null) return;
                mValidSuManagerPos = pos;
                prefs.edit().putString(ExploitRunner.PREF_SU_MANAGER, e.packageName).apply();
                updateRunButton();
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {}
        });
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.main_menu, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == R.id.action_settings) {
            startActivity(new Intent(this, SettingsActivity.class));
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    private void updateRunButton() {
        boolean alreadyHooked = mIsRootActive || new File("/dev/df").exists();
        btnRun.setEnabled(mValidSuManagerPos >= 1 && !alreadyHooked);
        btnRun.setText(alreadyHooked ? "Root Active" : "Launch Root");
    }

    private void runExploit() {
        try {
            String preId = runRootCmd("id 2>/dev/null").trim();
            if (preId.contains("uid=0") || new File("/dev/df").exists()) {
                mIsRootActive = true;
                report("[PIXELROOT] Root already active (" + preId + ") — skipping duplicate patch.\n");
                mMain.post(() -> Toast.makeText(this, "PixelRoot: Root Already Active", Toast.LENGTH_SHORT).show());
                refreshRootStatusAndModules();
                return;
            }
            int rc = ExploitRunner.run(mDeCtx, this);
            String msg = rc == 0 ? "PixelRoot: SUCCESS"
                    : rc == 1 ? "PixelRoot: Error - ksud nonzero exit"
                    : rc == 2 ? "PixelRoot: Error - check logcat & dmesg"
                    : "PixelRoot: Error - failed to patch files";
            mMain.post(() -> Toast.makeText(this, msg, Toast.LENGTH_LONG).show());
            refreshRootStatusAndModules();
        } catch (Exception e) {
            Log.e(TAG, "exploit exception", e);
            report("\n" + e + "\n");
        } finally {
            mMain.post(this::updateRunButton);
        }
    }

    private static class ModuleItem {
        final String id;
        final String name;
        final String version;
        final String author;
        final String description;
        final boolean disabled;
        final boolean removed;

        ModuleItem(String id, String name, String version, String author, String description, boolean disabled, boolean removed) {
            this.id = id;
            this.name = name;
            this.version = version;
            this.author = author;
            this.description = description;
            this.disabled = disabled;
            this.removed = removed;
        }

        static ModuleItem parse(String id, String propText, String flags) {
            Map<String, String> map = new HashMap<>();
            for (String line : propText.split("\n")) {
                int eq = line.indexOf('=');
                if (eq > 0) {
                    map.put(line.substring(0, eq).trim(), line.substring(eq + 1).trim());
                }
            }
            return new ModuleItem(
                    id,
                    map.getOrDefault("name", id),
                    map.getOrDefault("version", ""),
                    map.getOrDefault("author", "unknown"),
                    map.getOrDefault("description", ""),
                    flags.contains("disabled"),
                    flags.contains("removed")
            );
        }
    }

    private static class CrosshairLogoView extends View {
        private final Paint ringPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint barPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint dotPaint = new Paint(Paint.ANTI_ALIAS_FLAG);

        CrosshairLogoView(Context ctx) {
            super(ctx);
            ringPaint.setStyle(Paint.Style.STROKE);
            ringPaint.setColor(Color.WHITE);
            barPaint.setStyle(Paint.Style.STROKE);
            barPaint.setStrokeCap(Paint.Cap.ROUND);
            barPaint.setColor(Color.WHITE);
            dotPaint.setStyle(Paint.Style.FILL);
            dotPaint.setColor(Color.WHITE);
        }

        @Override
        protected void onDraw(Canvas c) {
            float w = getWidth();
            float h = getHeight();
            float cx = w / 2f;
            float cy = h / 2f;
            float r = Math.min(w, h) * 0.34f;
            float sw = Math.max(3f, r * 0.18f);
            ringPaint.setStrokeWidth(sw);
            barPaint.setStrokeWidth(sw);

            c.drawCircle(cx, cy, r, ringPaint);
            c.drawLine(cx, cy - r * 1.35f, cx, cy - r * 0.55f, barPaint);
            c.drawLine(cx, cy + r * 0.55f, cx, cy + r * 1.35f, barPaint);
            c.drawLine(cx - r * 1.35f, cy, cx - r * 0.55f, cy, barPaint);
            c.drawLine(cx + r * 0.55f, cy, cx + r * 1.35f, cy, barPaint);
            c.drawCircle(cx, cy, sw * 1.1f, dotPaint);
        }
    }

    private static class CrosshairTabIcon extends View {
        private final int tabIndex;
        private final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private boolean selected;

        CrosshairTabIcon(Context ctx, int tabIndex) {
            super(ctx);
            this.tabIndex = tabIndex;
            paint.setStrokeCap(Paint.Cap.ROUND);
            paint.setStrokeJoin(Paint.Join.ROUND);
        }

        void setSelectedState(boolean sel) {
            this.selected = sel;
            invalidate();
        }

        @Override
        protected void onDraw(Canvas c) {
            float cx = getWidth() / 2f;
            float cy = getHeight() / 2f;
            int color = selected ? Color.BLACK : Color.parseColor("#9E9E9E");
            paint.setColor(color);
            paint.setStrokeWidth(4.5f);

            if (tabIndex == 0) {
                paint.setStyle(Paint.Style.STROKE);
                c.drawCircle(cx, cy, 14f, paint);
                c.drawLine(cx, cy - 20f, cx, cy - 8f, paint);
                c.drawLine(cx, cy + 8f, cx, cy + 20f, paint);
                c.drawLine(cx - 20f, cy, cx - 8f, cy, paint);
                c.drawLine(cx + 8f, cy, cx + 20f, cy, paint);
            } else if (tabIndex == 1) {
                paint.setStyle(Paint.Style.STROKE);
                c.drawRoundRect(cx - 18f, cy - 14f, cx + 18f, cy + 14f, 6f, 6f, paint);
                c.drawLine(cx - 10f, cy - 5f, cx - 3f, cy, paint);
                c.drawLine(cx - 3f, cy, cx - 10f, cy + 5f, paint);
                c.drawLine(cx + 1f, cy + 5f, cx + 10f, cy + 5f, paint);
            } else {
                paint.setStyle(Paint.Style.STROKE);
                c.drawRoundRect(cx - 16f, cy - 16f, cx - 2f, cy - 2f, 4f, 4f, paint);
                c.drawRoundRect(cx + 2f, cy - 16f, cx + 16f, cy - 2f, 4f, 4f, paint);
                c.drawRoundRect(cx - 16f, cy + 2f, cx - 2f, cy + 16f, 4f, 4f, paint);
                c.drawRoundRect(cx + 2f, cy + 2f, cx + 16f, cy + 16f, 4f, 4f, paint);
            }
        }
    }

    private static class CarouselPager extends FrameLayout {
        interface OnPageChangeListener {
            void onPageScrolled(float positionOffsetTotal);
            void onPageSelected(int page);
        }

        private final int pageSpacing;
        private final OverScroller scroller;
        private final int touchSlop;
        private VelocityTracker velocityTracker;
        private OnPageChangeListener listener;
        private int currentPage = 0;
        private float downX, downY, lastX;
        private boolean dragging = false;

        CarouselPager(Context ctx, int pageSpacingPx) {
            super(ctx);
            this.pageSpacing = pageSpacingPx;
            this.scroller = new OverScroller(ctx);
            this.touchSlop = ViewConfiguration.get(ctx).getScaledTouchSlop();
        }

        void setPageListener(OnPageChangeListener l) {
            this.listener = l;
        }

        int getCurrentPage() {
            return currentPage;
        }

        void setCurrentPage(int page, boolean smooth) {
            int maxPage = Math.max(0, getChildCount() - 1);
            int target = Math.max(0, Math.min(page, maxPage));
            currentPage = target;
            int step = getWidth() + pageSpacing;
            int targetX = target * step;
            if (smooth && getWidth() > 0) {
                int sx = getScrollX();
                scroller.startScroll(sx, 0, targetX - sx, 0, 300);
                postInvalidateOnAnimation();
            } else {
                scrollTo(targetX, 0);
                if (listener != null) listener.onPageScrolled(target);
            }
            if (listener != null) listener.onPageSelected(target);
        }

        @Override
        protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
            int w = right - left;
            int h = bottom - top;
            for (int i = 0; i < getChildCount(); i++) {
                View child = getChildAt(i);
                int childLeft = i * (w + pageSpacing);
                child.layout(childLeft, 0, childLeft + w, h);
            }
            int step = w + pageSpacing;
            if (scroller.isFinished() && !dragging) {
                scrollTo(currentPage * step, 0);
            }
        }

        @Override
        public boolean onInterceptTouchEvent(MotionEvent ev) {
            switch (ev.getActionMasked()) {
                case MotionEvent.ACTION_DOWN:
                    downX = lastX = ev.getX();
                    downY = ev.getY();
                    dragging = false;
                    if (!scroller.isFinished()) {
                        scroller.abortAnimation();
                    }
                    break;
                case MotionEvent.ACTION_MOVE:
                    float dx = ev.getX() - downX;
                    float dy = ev.getY() - downY;
                    if (Math.abs(dx) > touchSlop && Math.abs(dx) > Math.abs(dy) * 1.2f) {
                        dragging = true;
                        lastX = ev.getX();
                        return true;
                    }
                    break;
            }
            return super.onInterceptTouchEvent(ev);
        }

        @Override
        public boolean onTouchEvent(MotionEvent ev) {
            if (velocityTracker == null) velocityTracker = VelocityTracker.obtain();
            velocityTracker.addMovement(ev);

            int step = getWidth() + pageSpacing;
            int maxScroll = Math.max(0, (getChildCount() - 1) * step);

            switch (ev.getActionMasked()) {
                case MotionEvent.ACTION_DOWN:
                    lastX = ev.getX();
                    return true;
                case MotionEvent.ACTION_MOVE:
                    float x = ev.getX();
                    int delta = Math.round(lastX - x);
                    lastX = x;
                    int nextX = Math.max(0, Math.min(getScrollX() + delta, maxScroll));
                    scrollTo(nextX, 0);
                    if (listener != null && step > 0) {
                        listener.onPageScrolled(nextX / (float) step);
                    }
                    return true;
                case MotionEvent.ACTION_UP:
                case MotionEvent.ACTION_CANCEL:
                    dragging = false;
                    velocityTracker.computeCurrentVelocity(1000);
                    float vx = velocityTracker.getXVelocity();
                    velocityTracker.recycle();
                    velocityTracker = null;

                    int targetPage = currentPage;
                    if (step > 0) {
                        if (vx < -650f) {
                            targetPage = currentPage + 1;
                        } else if (vx > 650f) {
                            targetPage = currentPage - 1;
                        } else {
                            targetPage = Math.round(getScrollX() / (float) step);
                        }
                    }
                    setCurrentPage(targetPage, true);
                    return true;
            }
            return super.onTouchEvent(ev);
        }

        @Override
        public void computeScroll() {
            if (scroller.computeScrollOffset()) {
                int cx = scroller.getCurrX();
                scrollTo(cx, 0);
                int step = getWidth() + pageSpacing;
                if (listener != null && step > 0) {
                    listener.onPageScrolled(cx / (float) step);
                }
                postInvalidateOnAnimation();
            }
        }
    }

    private static class SuManagerEntry {
        final String packageName;
        final CharSequence label;
        final Drawable icon;

        SuManagerEntry(String pkg, CharSequence label, Drawable icon) {
            this.packageName = pkg;
            this.label = label;
            this.icon = icon;
        }
    }

    private static class SuManagerAdapter extends ArrayAdapter<SuManagerEntry> {
        SuManagerAdapter(Context ctx, List<SuManagerEntry> items) {
            super(ctx, R.layout.item_su_manager, items);
        }

        @Override
        public View getView(int pos, View v, ViewGroup parent) {
            if (v == null || v.getTag() != Boolean.FALSE) {
                v = LayoutInflater.from(getContext()).inflate(R.layout.item_su_manager_closed, parent, false);
                v.setTag(Boolean.FALSE);
            }
            return bindClosedView(pos, v);
        }

        @Override
        public View getDropDownView(int pos, View v, ViewGroup parent) {
            if (v == null || v.getTag() != Boolean.TRUE) {
                v = LayoutInflater.from(getContext()).inflate(R.layout.item_su_manager, parent, false);
                v.setTag(Boolean.TRUE);
            }
            return bindView(pos, v);
        }

        @Override
        public boolean isEnabled(int pos) {
            return getItem(pos).packageName != null;
        }

        private View bindClosedView(int pos, View v) {
            SuManagerEntry e = getItem(pos);
            android.widget.ImageView icon = v.findViewById(R.id.iconApp);
            TextView label = v.findViewById(R.id.labelApp);
            if (e.packageName == null) {
                icon.setVisibility(View.GONE);
                label.setVisibility(View.VISIBLE);
                label.setText(e.label);
            } else {
                icon.setVisibility(View.VISIBLE);
                label.setVisibility(View.GONE);
                icon.setImageDrawable(e.icon);
            }
            return v;
        }

        private View bindView(int pos, View v) {
            SuManagerEntry e = getItem(pos);
            ((android.widget.ImageView) v.findViewById(R.id.iconApp)).setImageDrawable(e.icon);
            ((TextView) v.findViewById(R.id.labelApp)).setText(e.label);
            return v;
        }
    }
}
