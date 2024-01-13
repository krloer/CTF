package com.kotcrab.vis.ui.widget.color;

import com.badlogic.gdx.scenes.scene2d.ui.Window;

/* loaded from: classes.dex */
public class ColorPickerStyle extends Window.WindowStyle {
    public ColorPickerWidgetStyle pickerStyle;

    public ColorPickerStyle() {
    }

    public ColorPickerStyle(ColorPickerStyle style) {
        super(style);
        ColorPickerWidgetStyle colorPickerWidgetStyle = style.pickerStyle;
        if (colorPickerWidgetStyle != null) {
            this.pickerStyle = new ColorPickerWidgetStyle(colorPickerWidgetStyle);
        }
    }
}