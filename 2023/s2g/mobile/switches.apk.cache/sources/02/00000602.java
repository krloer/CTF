package com.kotcrab.vis.ui.widget.color.internal;

import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.utils.ChangeListener;
import com.kotcrab.vis.ui.Sizes;
import com.kotcrab.vis.ui.widget.VisLabel;
import com.kotcrab.vis.ui.widget.VisTable;
import com.kotcrab.vis.ui.widget.color.ColorPickerWidgetStyle;
import com.kotcrab.vis.ui.widget.color.internal.ChannelBar;
import com.kotcrab.vis.ui.widget.color.internal.ColorInputField;

/* loaded from: classes.dex */
public class ColorChannelWidget extends VisTable {
    private ChannelBar bar;
    private ChangeListener barListener;
    private PickerCommons commons;
    private ColorInputField inputField;
    private int maxValue;
    private int mode;
    private Sizes sizes;
    private ColorPickerWidgetStyle style;
    private int value;

    public ColorChannelWidget(PickerCommons commons, String label, int mode, int maxValue, final ChannelBar.ChannelBarListener listener) {
        super(true);
        this.commons = commons;
        this.style = commons.style;
        this.sizes = commons.sizes;
        this.mode = mode;
        this.maxValue = maxValue;
        this.barListener = new ChangeListener() { // from class: com.kotcrab.vis.ui.widget.color.internal.ColorChannelWidget.1
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
            public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                ColorChannelWidget colorChannelWidget = ColorChannelWidget.this;
                colorChannelWidget.value = colorChannelWidget.bar.getValue();
                listener.updateFields();
                ColorChannelWidget.this.inputField.setValue(ColorChannelWidget.this.value);
            }
        };
        add((ColorChannelWidget) new VisLabel(label)).width(this.sizes.scaleFactor * 10.0f).center();
        ColorInputField colorInputField = new ColorInputField(maxValue, new ColorInputField.ColorInputFieldListener() { // from class: com.kotcrab.vis.ui.widget.color.internal.ColorChannelWidget.2
            @Override // com.kotcrab.vis.ui.widget.color.internal.ColorInputField.ColorInputFieldListener
            public void changed(int newValue) {
                ColorChannelWidget.this.value = newValue;
                listener.updateFields();
                ColorChannelWidget.this.bar.setValue(newValue);
            }
        });
        this.inputField = colorInputField;
        add((ColorChannelWidget) colorInputField).width(this.sizes.scaleFactor * 50.0f);
        ChannelBar createBarImage = createBarImage();
        this.bar = createBarImage;
        add((ColorChannelWidget) createBarImage).size(this.sizes.scaleFactor * 130.0f, this.sizes.scaleFactor * 12.0f);
        this.bar.setChannelBarListener(listener);
        this.inputField.setValue(0);
    }

    public int getValue() {
        return this.value;
    }

    public void setValue(int value) {
        this.value = value;
        this.inputField.setValue(value);
        this.bar.setValue(value);
    }

    private ChannelBar createBarImage() {
        int i = this.mode;
        if (i == 0) {
            return new AlphaChannelBar(this.commons, i, this.maxValue, this.barListener);
        }
        return new ChannelBar(this.commons, i, this.maxValue, this.barListener);
    }

    public ChannelBar getBar() {
        return this.bar;
    }

    public boolean isInputValid() {
        return this.inputField.isInputValid();
    }
}