package com.kotcrab.vis.ui.widget;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.scenes.scene2d.ui.Widget;
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;
import com.kotcrab.vis.ui.VisUI;

/* loaded from: classes.dex */
public class Separator extends Widget {
    private SeparatorStyle style;

    public Separator() {
        this.style = (SeparatorStyle) VisUI.getSkin().get(SeparatorStyle.class);
    }

    public Separator(String styleName) {
        this.style = (SeparatorStyle) VisUI.getSkin().get(styleName, SeparatorStyle.class);
    }

    public Separator(SeparatorStyle style) {
        this.style = style;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getPrefHeight() {
        return this.style.thickness;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getPrefWidth() {
        return this.style.thickness;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.Actor
    public void draw(Batch batch, float parentAlpha) {
        Color c = getColor();
        batch.setColor(c.r, c.g, c.b, c.a * parentAlpha);
        this.style.background.draw(batch, getX(), getY(), getWidth(), getHeight());
    }

    public SeparatorStyle getStyle() {
        return this.style;
    }

    /* loaded from: classes.dex */
    public static class SeparatorStyle {
        public Drawable background;
        public int thickness;

        public SeparatorStyle() {
        }

        public SeparatorStyle(SeparatorStyle style) {
            this.background = style.background;
            this.thickness = style.thickness;
        }

        public SeparatorStyle(Drawable bg, int thickness) {
            this.background = bg;
            this.thickness = thickness;
        }
    }
}