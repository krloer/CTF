package com.kotcrab.vis.ui.util;

import com.badlogic.gdx.Application;
import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.Input;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class OsUtils {
    private static final boolean UNIX;
    private static final String OS = System.getProperty("os.name", BuildConfig.FLAVOR).toLowerCase();
    private static final boolean WINDOWS = OS.contains("win");
    private static final boolean MAC = OS.contains("mac");

    static {
        UNIX = OS.contains("nix") || OS.contains("nux") || OS.contains("aix");
    }

    public static boolean isWindows() {
        return WINDOWS;
    }

    public static boolean isMac() {
        return MAC;
    }

    public static boolean isUnix() {
        return UNIX;
    }

    public static boolean isIos() {
        return Gdx.app.getType() == Application.ApplicationType.iOS;
    }

    public static boolean isAndroid() {
        return Gdx.app.getType() == Application.ApplicationType.Android;
    }

    public static int getAndroidApiLevel() {
        if (isAndroid()) {
            return Gdx.app.getVersion();
        }
        return 0;
    }

    public static String getShortcutFor(int... keycodes) {
        StringBuilder builder = new StringBuilder();
        String separatorString = "+";
        String ctrlKey = "Ctrl";
        String altKey = "Alt";
        String shiftKey = "Shift";
        if (isMac()) {
            separatorString = BuildConfig.FLAVOR;
            ctrlKey = "⌘";
            altKey = "⌥";
            shiftKey = "⇧";
        }
        for (int i = 0; i < keycodes.length; i++) {
            if (keycodes[i] != Integer.MIN_VALUE) {
                if (keycodes[i] == 129 || keycodes[i] == 130 || keycodes[i] == 63) {
                    builder.append(ctrlKey);
                } else if (keycodes[i] == 59 || keycodes[i] == 60) {
                    builder.append(shiftKey);
                } else if (keycodes[i] == 57 || keycodes[i] == 58) {
                    builder.append(altKey);
                } else {
                    builder.append(Input.Keys.toString(keycodes[i]));
                }
                if (i < keycodes.length - 1) {
                    builder.append(separatorString);
                }
            }
        }
        return builder.toString();
    }
}