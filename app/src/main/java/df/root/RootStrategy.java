package df.root;

import android.content.Context;

import java.io.File;

enum RootStrategy {
    UNSUPPORTED(0, false) {
        @Override
        int execute(Context context, IReporter reporter, DirtyFragSession session,
                    boolean softReboot) {
            return ExploitRunner.RESULT_UNSUPPORTED;
        }
    },
    MODULE(1, true) {
        @Override
        int execute(Context context, IReporter reporter, DirtyFragSession session,
                    boolean softReboot) throws Exception {
            ExploitRunner.stageKsud(context, reporter);
            return session.runModule(reporter, ExploitRunner.detectKoTarget(reporter), softReboot);
        }
    },
    PATCH_WINDOW(2, false) {
        @Override
        int execute(Context context, IReporter reporter, DirtyFragSession session,
                    boolean softReboot) {
            File state = new File(context.getFilesDir(), "root-state.txt");
            reporter.report("NEXT: while state=armed, trigger the selected daemon from the host\n");
            return session.runPatchWindow(reporter, state.getAbsolutePath(), 30000);
        }
    },
    INIT_SHELL(3, true) {
        @Override
        int execute(Context context, IReporter reporter, DirtyFragSession session,
                    boolean softReboot) {
            return session.runInitShell(reporter);
        }
    };

    final int nativeValue;
    final boolean unattended;

    RootStrategy(int nativeValue, boolean unattended) {
        this.nativeValue = nativeValue;
        this.unattended = unattended;
    }

    abstract int execute(Context context, IReporter reporter, DirtyFragSession session,
                         boolean softReboot) throws Exception;

    static RootStrategy fromNative(int value) {
        for (RootStrategy strategy : values()) {
            if (strategy.nativeValue == value) return strategy;
        }
        return UNSUPPORTED;
    }
}
