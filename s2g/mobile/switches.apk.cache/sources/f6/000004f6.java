package com.kotcrab.vis.ui;

import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.Stage;

/* loaded from: classes.dex */
public class FocusManager {
    private static Focusable focusedWidget;

    public static void switchFocus(Stage stage, Focusable widget) {
        Focusable focusable = focusedWidget;
        if (focusable == widget) {
            return;
        }
        if (focusable != null) {
            focusable.focusLost();
        }
        focusedWidget = widget;
        if (stage != null) {
            stage.setKeyboardFocus(null);
        }
        focusedWidget.focusGained();
    }

    public static void resetFocus(Stage stage) {
        Focusable focusable = focusedWidget;
        if (focusable != null) {
            focusable.focusLost();
        }
        if (stage != null) {
            stage.setKeyboardFocus(null);
        }
        focusedWidget = null;
    }

    public static void resetFocus(Stage stage, Actor caller) {
        Focusable focusable = focusedWidget;
        if (focusable != null) {
            focusable.focusLost();
        }
        if (stage != null && stage.getKeyboardFocus() == caller) {
            stage.setKeyboardFocus(null);
        }
        focusedWidget = null;
    }

    public static Focusable getFocusedWidget() {
        return focusedWidget;
    }
}