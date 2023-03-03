package com.kotcrab.vis.ui.widget.file.internal;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.utils.Array;
import java.io.File;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/* loaded from: classes.dex */
public class DriveCheckerService {
    private static DriveCheckerService instance;
    private Array<File> readableRoots = new Array<>();
    private Array<File> writableRoots = new Array<>();
    private Map<File, ListenerSet> readableListeners = new HashMap();
    private Map<File, ListenerSet> writableListeners = new HashMap();
    private final ExecutorService pool = Executors.newFixedThreadPool(3, new ServiceThreadFactory("DriveStatusChecker"));

    /* loaded from: classes.dex */
    public interface DriveCheckerListener {
        void rootMode(File file, RootMode rootMode);
    }

    /* loaded from: classes.dex */
    public enum RootMode {
        READABLE,
        WRITABLE
    }

    public static synchronized DriveCheckerService getInstance() {
        DriveCheckerService driveCheckerService;
        synchronized (DriveCheckerService.class) {
            if (instance == null) {
                instance = new DriveCheckerService();
            }
            driveCheckerService = instance;
        }
        return driveCheckerService;
    }

    public DriveCheckerService() {
        File[] roots = File.listRoots();
        for (File root : roots) {
            processRoot(root);
        }
    }

    private void processRoot(final File root) {
        this.pool.execute(new Runnable() { // from class: com.kotcrab.vis.ui.widget.file.internal.DriveCheckerService.1
            @Override // java.lang.Runnable
            public void run() {
                DriveCheckerService driveCheckerService = DriveCheckerService.this;
                File file = root;
                driveCheckerService.processResults(file, file.canRead(), root.canWrite());
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void processResults(final File root, final boolean readable, final boolean writable) {
        Gdx.app.postRunnable(new Runnable() { // from class: com.kotcrab.vis.ui.widget.file.internal.DriveCheckerService.2
            @Override // java.lang.Runnable
            public void run() {
                if (readable) {
                    DriveCheckerService.this.readableRoots.add(root);
                    ListenerSet set = (ListenerSet) DriveCheckerService.this.readableListeners.get(root);
                    if (set != null) {
                        set.notifyListeners(root, RootMode.READABLE);
                    }
                }
                if (writable) {
                    DriveCheckerService.this.writableRoots.add(root);
                    ListenerSet set2 = (ListenerSet) DriveCheckerService.this.writableListeners.get(root);
                    if (set2 != null) {
                        set2.notifyListeners(root, RootMode.WRITABLE);
                    }
                }
            }
        });
    }

    /* renamed from: com.kotcrab.vis.ui.widget.file.internal.DriveCheckerService$3  reason: invalid class name */
    /* loaded from: classes.dex */
    static /* synthetic */ class AnonymousClass3 {
        static final /* synthetic */ int[] $SwitchMap$com$kotcrab$vis$ui$widget$file$internal$DriveCheckerService$RootMode = new int[RootMode.values().length];

        static {
            try {
                $SwitchMap$com$kotcrab$vis$ui$widget$file$internal$DriveCheckerService$RootMode[RootMode.READABLE.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$com$kotcrab$vis$ui$widget$file$internal$DriveCheckerService$RootMode[RootMode.WRITABLE.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
        }
    }

    public void addListener(File root, RootMode mode, DriveCheckerListener listener) {
        int i = AnonymousClass3.$SwitchMap$com$kotcrab$vis$ui$widget$file$internal$DriveCheckerService$RootMode[mode.ordinal()];
        if (i == 1) {
            addListener(root, mode, listener, this.readableRoots, this.readableListeners);
        } else if (i == 2) {
            addListener(root, mode, listener, this.writableRoots, this.writableListeners);
        }
    }

    private void addListener(File root, RootMode mode, DriveCheckerListener listener, Array<File> cachedRoots, Map<File, ListenerSet> listeners) {
        if (cachedRoots.contains(root, false)) {
            listener.rootMode(root, mode);
            return;
        }
        ListenerSet set = listeners.get(root);
        if (set == null) {
            set = new ListenerSet();
            listeners.put(root, set);
        }
        set.add(listener);
        processRoot(root);
    }

    /* loaded from: classes.dex */
    public class ListenerSet {
        Array<DriveCheckerListener> list = new Array<>();

        public ListenerSet() {
        }

        public void add(DriveCheckerListener listener) {
            this.list.add(listener);
        }

        public void notifyListeners(File root, RootMode mode) {
            Iterator<DriveCheckerListener> it = this.list.iterator();
            while (it.hasNext()) {
                DriveCheckerListener listener = it.next();
                listener.rootMode(root, mode);
                it.remove();
            }
        }
    }
}