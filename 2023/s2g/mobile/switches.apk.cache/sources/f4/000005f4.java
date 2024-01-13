package com.kotcrab.vis.ui.widget.color;

import com.badlogic.gdx.scenes.scene2d.utils.Drawable;

/* loaded from: classes.dex */
public class ColorPickerWidgetStyle {
    public Drawable barSelector;
    public Drawable cross;
    public Drawable horizontalSelector;
    public Drawable iconArrowRight;
    public Drawable verticalSelector;

    public ColorPickerWidgetStyle() {
    }

    public ColorPickerWidgetStyle(ColorPickerWidgetStyle other) {
        this.barSelector = other.barSelector;
        this.cross = other.cross;
        this.verticalSelector = other.verticalSelector;
        this.horizontalSelector = other.horizontalSelector;
        this.iconArrowRight = other.iconArrowRight;
    }
}