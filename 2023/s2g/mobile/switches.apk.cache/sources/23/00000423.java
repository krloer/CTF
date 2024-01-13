package com.badlogic.gdx.scenes.scene2d.utils;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.Input;

/* loaded from: classes.dex */
public final class UIUtils {
    public static boolean isAndroid = System.getProperty("java.runtime.name").contains("Android");
    public static boolean isIos;
    public static boolean isLinux;
    public static boolean isMac;
    public static boolean isWindows;

    private UIUtils() {
    }

    static {
        boolean z = true;
        isMac = !isAndroid && System.getProperty("os.name").contains("Mac");
        isWindows = !isAndroid && System.getProperty("os.name").contains("Windows");
        isLinux = !isAndroid && System.getProperty("os.name").contains("Linux");
        isIos = (isAndroid || isWindows || isLinux || isMac) ? false : false;
    }

    public static boolean left() {
        return Gdx.input.isButtonPressed(0);
    }

    public static boolean left(int button) {
        return button == 0;
    }

    public static boolean right() {
        return Gdx.input.isButtonPressed(1);
    }

    public static boolean right(int button) {
        return button == 1;
    }

    public static boolean middle() {
        return Gdx.input.isButtonPressed(2);
    }

    public static boolean middle(int button) {
        return button == 2;
    }

    public static boolean shift() {
        return Gdx.input.isKeyPressed(59) || Gdx.input.isKeyPressed(60);
    }

    public static boolean shift(int keycode) {
        return keycode == 59 || keycode == 60;
    }

    public static boolean ctrl() {
        if (isMac) {
            return Gdx.input.isKeyPressed(63);
        }
        return Gdx.input.isKeyPressed(Input.Keys.CONTROL_LEFT) || Gdx.input.isKeyPressed(130);
    }

    public static boolean ctrl(int keycode) {
        return isMac ? keycode == 63 : keycode == 129 || keycode == 130;
    }

    public static boolean alt() {
        return Gdx.input.isKeyPressed(57) || Gdx.input.isKeyPressed(58);
    }

    public static boolean alt(int keycode) {
        return keycode == 57 || keycode == 58;
    }
}