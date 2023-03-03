package com.kotcrab.vis.ui.widget;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.scenes.scene2d.ui.Label;
import com.kotcrab.vis.ui.VisUI;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class VisLabel extends Label {
    public VisLabel() {
        super(BuildConfig.FLAVOR, VisUI.getSkin());
    }

    public VisLabel(CharSequence text, Color textColor) {
        super(text, VisUI.getSkin());
        setColor(textColor);
    }

    public VisLabel(CharSequence text, int alignment) {
        this(text);
        setAlignment(alignment);
    }

    public VisLabel(CharSequence text) {
        super(text, VisUI.getSkin());
    }

    public VisLabel(CharSequence text, Label.LabelStyle style) {
        super(text, style);
    }

    public VisLabel(CharSequence text, String styleName) {
        super(text, VisUI.getSkin(), styleName);
    }

    public VisLabel(CharSequence text, String fontName, Color color) {
        super(text, VisUI.getSkin(), fontName, color);
    }

    public VisLabel(CharSequence text, String fontName, String colorName) {
        super(text, VisUI.getSkin(), fontName, colorName);
    }
}