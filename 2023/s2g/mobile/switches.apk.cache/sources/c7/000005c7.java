package com.kotcrab.vis.ui.widget;

import com.kotcrab.vis.ui.VisUI;
import com.kotcrab.vis.ui.widget.VisCheckBox;

/* loaded from: classes.dex */
public class VisRadioButton extends VisCheckBox {
    public VisRadioButton(String text) {
        this(text, (VisCheckBox.VisCheckBoxStyle) VisUI.getSkin().get("radio", VisCheckBox.VisCheckBoxStyle.class));
    }

    public VisRadioButton(String text, VisCheckBox.VisCheckBoxStyle style) {
        super(text, style);
    }
}