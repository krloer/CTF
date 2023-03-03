package com.kotcrab.vis.ui.widget.file.internal;

import com.badlogic.gdx.Files;
import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.Preferences;
import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.Json;
import java.util.Iterator;

/* loaded from: classes.dex */
public class PreferencesIO {
    private static final String VIS_DEFAULT_PREFS_NAME = "com.kotcrab.vis.ui.widget.file.filechooser_favorites";
    private static String defaultPrefsName = VIS_DEFAULT_PREFS_NAME;
    private String favoritesKeyName;
    private Json json;
    private String lastDirKeyName;
    private Preferences prefs;
    private String recentDirKeyName;

    public PreferencesIO() {
        this(defaultPrefsName);
    }

    public PreferencesIO(String prefsName) {
        this.favoritesKeyName = "favorites";
        this.recentDirKeyName = "recentDirectories";
        this.lastDirKeyName = "lastDirectory";
        this.json = new Json();
        this.prefs = Gdx.app.getPreferences(prefsName);
        checkIfUsingDefaultName();
    }

    public void checkIfUsingDefaultName() {
        if (defaultPrefsName.equals(VIS_DEFAULT_PREFS_NAME)) {
            Gdx.app.log("VisUI", "Warning, using default preferences file name for file chooser! (see FileChooser.setDefaultPrefsName(String))");
        }
    }

    public static void setDefaultPrefsName(String prefsName) {
        if (prefsName == null) {
            throw new IllegalStateException("prefsName can't be null");
        }
        defaultPrefsName = prefsName;
    }

    public Array<FileHandle> loadFavorites() {
        String data = this.prefs.getString(this.favoritesKeyName, null);
        if (data == null) {
            return new Array<>();
        }
        return ((FileArrayData) this.json.fromJson(FileArrayData.class, data)).toFileHandleArray();
    }

    public void saveFavorites(Array<FileHandle> favorites) {
        this.prefs.putString(this.favoritesKeyName, this.json.toJson(new FileArrayData(favorites)));
        this.prefs.flush();
    }

    public Array<FileHandle> loadRecentDirectories() {
        String data = this.prefs.getString(this.recentDirKeyName, null);
        if (data == null) {
            return new Array<>();
        }
        return ((FileArrayData) this.json.fromJson(FileArrayData.class, data)).toFileHandleArray();
    }

    public void saveRecentDirectories(Array<FileHandle> recentDirs) {
        this.prefs.putString(this.recentDirKeyName, this.json.toJson(new FileArrayData(recentDirs)));
        this.prefs.flush();
    }

    public FileHandle loadLastDirectory() {
        String data = this.prefs.getString(this.lastDirKeyName, null);
        if (data == null) {
            return null;
        }
        return ((FileHandleData) this.json.fromJson(FileHandleData.class, data)).toFileHandle();
    }

    public void saveLastDirectory(FileHandle file) {
        this.prefs.putString(this.lastDirKeyName, this.json.toJson(new FileHandleData(file)));
        this.prefs.flush();
    }

    /* loaded from: classes.dex */
    private static class FileArrayData {
        public Array<FileHandleData> data;

        public FileArrayData() {
        }

        public FileArrayData(Array<FileHandle> favourites) {
            this.data = new Array<>();
            Iterator it = favourites.iterator();
            while (it.hasNext()) {
                FileHandle file = (FileHandle) it.next();
                this.data.add(new FileHandleData(file));
            }
        }

        public Array<FileHandle> toFileHandleArray() {
            Array<FileHandle> files = new Array<>();
            Iterator it = this.data.iterator();
            while (it.hasNext()) {
                FileHandleData fileData = (FileHandleData) it.next();
                files.add(fileData.toFileHandle());
            }
            return files;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class FileHandleData {
        public String path;
        public Files.FileType type;

        public FileHandleData() {
        }

        public FileHandleData(FileHandle file) {
            this.type = file.type();
            this.path = file.path();
        }

        public FileHandle toFileHandle() {
            int i = AnonymousClass1.$SwitchMap$com$badlogic$gdx$Files$FileType[this.type.ordinal()];
            if (i != 1) {
                if (i != 2) {
                    if (i != 3) {
                        if (i != 4) {
                            if (i == 5) {
                                return Gdx.files.local(this.path);
                            }
                            throw new IllegalStateException("Unknown file type!");
                        }
                        return Gdx.files.internal(this.path);
                    }
                    return Gdx.files.external(this.path);
                }
                return Gdx.files.classpath(this.path);
            }
            return Gdx.files.absolute(this.path);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: com.kotcrab.vis.ui.widget.file.internal.PreferencesIO$1  reason: invalid class name */
    /* loaded from: classes.dex */
    public static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$com$badlogic$gdx$Files$FileType = new int[Files.FileType.values().length];

        static {
            try {
                $SwitchMap$com$badlogic$gdx$Files$FileType[Files.FileType.Absolute.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$com$badlogic$gdx$Files$FileType[Files.FileType.Classpath.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            try {
                $SwitchMap$com$badlogic$gdx$Files$FileType[Files.FileType.External.ordinal()] = 3;
            } catch (NoSuchFieldError e3) {
            }
            try {
                $SwitchMap$com$badlogic$gdx$Files$FileType[Files.FileType.Internal.ordinal()] = 4;
            } catch (NoSuchFieldError e4) {
            }
            try {
                $SwitchMap$com$badlogic$gdx$Files$FileType[Files.FileType.Local.ordinal()] = 5;
            } catch (NoSuchFieldError e5) {
            }
        }
    }
}