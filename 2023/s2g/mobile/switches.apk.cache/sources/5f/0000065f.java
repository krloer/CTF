package com.kotcrab.vis.ui.widget.file.internal;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.ObjectMap;
import com.kotcrab.vis.ui.util.OsUtils;
import java.io.File;
import java.lang.ref.WeakReference;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/* loaded from: classes.dex */
public class FileChooserWinService {
    private static FileChooserWinService instance;
    private Method getShellFolderDisplayNameMethod;
    private Method getShellFolderMethod;
    private boolean shellFolderSupported;
    private ObjectMap<File, String> nameCache = new ObjectMap<>();
    private Map<File, ListenerSet> listeners = new HashMap();
    private final ExecutorService pool = Executors.newFixedThreadPool(3, new ServiceThreadFactory("SystemDisplayNameGetter"));

    /* loaded from: classes.dex */
    public interface RootNameListener {
        void setRootName(String str);
    }

    public static synchronized FileChooserWinService getInstance() {
        synchronized (FileChooserWinService.class) {
            if (OsUtils.isWindows()) {
                if (instance == null) {
                    instance = new FileChooserWinService();
                }
                return instance;
            }
            return null;
        }
    }

    protected FileChooserWinService() {
        this.shellFolderSupported = false;
        try {
            Class shellFolderClass = Class.forName("sun.awt.shell.ShellFolder");
            this.getShellFolderMethod = shellFolderClass.getMethod("getShellFolder", File.class);
            this.getShellFolderDisplayNameMethod = shellFolderClass.getMethod("getDisplayName", new Class[0]);
            this.shellFolderSupported = true;
        } catch (ClassNotFoundException e) {
        } catch (NoSuchMethodException e2) {
        }
        File[] roots = File.listRoots();
        for (File root : roots) {
            processRoot(root);
        }
    }

    private void processRoot(final File root) {
        this.pool.execute(new Runnable() { // from class: com.kotcrab.vis.ui.widget.file.internal.FileChooserWinService.1
            @Override // java.lang.Runnable
            public void run() {
                FileChooserWinService fileChooserWinService = FileChooserWinService.this;
                File file = root;
                fileChooserWinService.processResult(file, fileChooserWinService.getSystemDisplayName(file));
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void processResult(final File root, final String name) {
        Gdx.app.postRunnable(new Runnable() { // from class: com.kotcrab.vis.ui.widget.file.internal.FileChooserWinService.2
            @Override // java.lang.Runnable
            public void run() {
                if (name != null) {
                    FileChooserWinService.this.nameCache.put(root, name);
                } else {
                    ObjectMap objectMap = FileChooserWinService.this.nameCache;
                    File file = root;
                    objectMap.put(file, file.toString());
                }
                ListenerSet set = (ListenerSet) FileChooserWinService.this.listeners.get(root);
                if (set != null) {
                    set.notifyListeners(name);
                }
            }
        });
    }

    public void addListener(File root, RootNameListener listener) {
        String cachedName = this.nameCache.get(root);
        if (cachedName != null) {
            listener.setRootName(cachedName);
            return;
        }
        ListenerSet set = this.listeners.get(root);
        if (set == null) {
            set = new ListenerSet();
            this.listeners.put(root, set);
        }
        set.add(listener);
        processRoot(root);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public String getSystemDisplayName(File f) {
        if (this.shellFolderSupported) {
            try {
                Object shellFolder = this.getShellFolderMethod.invoke(null, f);
                String name = (String) this.getShellFolderDisplayNameMethod.invoke(shellFolder, new Object[0]);
                return (name == null || name.length() == 0) ? f.getPath() : name;
            } catch (IllegalAccessException e) {
                return null;
            } catch (InvocationTargetException e2) {
                return null;
            }
        }
        return null;
    }

    /* loaded from: classes.dex */
    private static class ListenerSet {
        Array<WeakReference<RootNameListener>> list;

        private ListenerSet() {
            this.list = new Array<>();
        }

        public void add(RootNameListener listener) {
            this.list.add(new WeakReference<>(listener));
        }

        public void notifyListeners(String newName) {
            Iterator<WeakReference<RootNameListener>> it = this.list.iterator();
            while (it.hasNext()) {
                RootNameListener listener = it.next().get();
                if (listener == null) {
                    it.remove();
                } else {
                    listener.setRootName(newName);
                }
            }
        }
    }
}