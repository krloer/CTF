package com.kotcrab.vis.ui;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.scenes.scene2d.ui.Skin;
import com.badlogic.gdx.utils.GdxRuntimeException;

/* loaded from: classes.dex */
public class VisUI {
    private static final String TARGET_GDX_VERSION = "1.9.6";
    public static final String VERSION = "1.3.0";
    private static SkinScale scale;
    private static Skin skin;
    private static boolean skipGdxVersionCheck = false;
    private static int defaultTitleAlign = 8;

    /* loaded from: classes.dex */
    public enum SkinScale {
        X1("com/kotcrab/vis/ui/skin/x1/uiskin.json", "default"),
        X2("com/kotcrab/vis/ui/skin/x2/uiskin.json", "x2");
        
        private final String classpath;
        private final String sizesName;

        SkinScale(String classpath, String sizesName) {
            this.classpath = classpath;
            this.sizesName = sizesName;
        }

        public FileHandle getSkinFile() {
            return Gdx.files.classpath(this.classpath);
        }

        public String getSizesName() {
            return this.sizesName;
        }
    }

    public static void load() {
        load(SkinScale.X1);
    }

    public static void load(SkinScale scale2) {
        scale = scale2;
        load(scale2.getSkinFile());
    }

    public static void load(String internalVisSkinPath) {
        load(Gdx.files.internal(internalVisSkinPath));
    }

    public static void load(FileHandle visSkinFile) {
        checkBeforeLoad();
        skin = new Skin(visSkinFile);
    }

    public static void load(Skin skin2) {
        checkBeforeLoad();
        skin = skin2;
    }

    private static void checkBeforeLoad() {
        if (skin != null) {
            throw new GdxRuntimeException("VisUI cannot be loaded twice");
        }
        if (!skipGdxVersionCheck && !TARGET_GDX_VERSION.equals(TARGET_GDX_VERSION)) {
            Gdx.app.log("VisUI", "Warning, using invalid libGDX version for VisUI 1.3.0.\nYou are using libGDX 1.9.6 but you need 1.9.6. This may cause unexpected problems and runtime exceptions.");
        }
    }

    public static void dispose() {
        dispose(true);
    }

    public static void dispose(boolean disposeSkin) {
        Skin skin2 = skin;
        if (skin2 != null) {
            if (disposeSkin) {
                skin2.dispose();
            }
            skin = null;
        }
    }

    public static Skin getSkin() {
        Skin skin2 = skin;
        if (skin2 == null) {
            throw new IllegalStateException("VisUI is not loaded!");
        }
        return skin2;
    }

    public static boolean isLoaded() {
        return skin != null;
    }

    public static Sizes getSizes() {
        if (scale == null) {
            return (Sizes) getSkin().get(Sizes.class);
        }
        return (Sizes) getSkin().get(scale.getSizesName(), Sizes.class);
    }

    public static int getDefaultTitleAlign() {
        return defaultTitleAlign;
    }

    public static void setDefaultTitleAlign(int defaultTitleAlign2) {
        defaultTitleAlign = defaultTitleAlign2;
    }

    public static void setSkipGdxVersionCheck(boolean setSkipGdxVersionCheck) {
        skipGdxVersionCheck = setSkipGdxVersionCheck;
    }
}