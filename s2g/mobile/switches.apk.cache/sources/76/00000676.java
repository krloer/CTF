package com.kotcrab.vis.ui.widget.file.internal;

import com.badlogic.gdx.scenes.scene2d.Touchable;
import com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup;
import com.kotcrab.vis.ui.widget.VisCheckBox;
import com.kotcrab.vis.ui.widget.VisImage;

/* loaded from: classes.dex */
public class IconStack extends WidgetGroup {
    private VisCheckBox checkBox;
    private VisImage icon;

    public IconStack(VisImage icon, VisCheckBox checkBox) {
        this.icon = icon;
        this.checkBox = checkBox;
        setTouchable(Touchable.childrenOnly);
        addActor(icon);
        addActor(checkBox);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public void layout() {
        this.icon.setBounds(getWidth() / 2.0f, getHeight() / 2.0f, getPrefWidth(), getPrefHeight());
        float checkHeight = this.checkBox.getStyle().checkBackground.getMinHeight();
        this.checkBox.setBounds(3.0f, (getHeight() - checkHeight) - 3.0f, this.checkBox.getPrefWidth(), this.checkBox.getPrefHeight());
    }
}