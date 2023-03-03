package com.kotcrab.vis.ui.util;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.graphics.Cursor;

/* loaded from: classes.dex */
public class CursorManager {
    private static Cursor defaultCursor;
    private static Cursor.SystemCursor defaultSystemCursor = Cursor.SystemCursor.Arrow;
    private static boolean systemCursorAsDefault = true;

    public static void setDefaultCursor(Cursor defaultCursor2) {
        if (defaultCursor2 == null) {
            throw new IllegalArgumentException("defaultCursor can't be null");
        }
        defaultCursor = defaultCursor2;
        systemCursorAsDefault = false;
    }

    public static void setDefaultCursor(Cursor.SystemCursor defaultCursor2) {
        if (defaultCursor2 == null) {
            throw new IllegalArgumentException("defaultCursor can't be null");
        }
        defaultSystemCursor = defaultCursor2;
        systemCursorAsDefault = true;
    }

    public static void restoreDefaultCursor() {
        if (systemCursorAsDefault) {
            Gdx.graphics.setSystemCursor(defaultSystemCursor);
        } else {
            Gdx.graphics.setCursor(defaultCursor);
        }
    }
}