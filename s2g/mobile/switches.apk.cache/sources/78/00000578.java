package com.kotcrab.vis.ui.widget;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.scenes.scene2d.ui.Widget;
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;
import com.kotcrab.vis.ui.VisUI;

/* loaded from: classes.dex */
public class BusyBar extends Widget {
    private float segmentX;
    private BusyBarStyle style;

    public BusyBar() {
        this.style = (BusyBarStyle) VisUI.getSkin().get(BusyBarStyle.class);
    }

    public BusyBar(String styleName) {
        this.style = (BusyBarStyle) VisUI.getSkin().get(styleName, BusyBarStyle.class);
    }

    public BusyBar(BusyBarStyle style) {
        this.style = style;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getPrefHeight() {
        return this.style.height;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getPrefWidth() {
        return getWidth();
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.Actor
    public void draw(Batch batch, float parentAlpha) {
        batch.flush();
        if (clipBegin()) {
            Color c = getColor();
            batch.setColor(c.r, c.g, c.b, c.a * parentAlpha);
            this.segmentX += getSegmentDeltaX();
            this.style.segment.draw(batch, getX() + this.segmentX, getY(), this.style.segmentWidth, this.style.height);
            if (this.segmentX > getWidth() + this.style.segmentOverflow) {
                resetSegment();
            }
            if (isVisible()) {
                Gdx.graphics.requestRendering();
            }
            batch.flush();
            clipEnd();
        }
    }

    public void resetSegment() {
        this.segmentX = (-this.style.segmentWidth) - this.style.segmentOverflow;
    }

    protected float getSegmentDeltaX() {
        return Gdx.graphics.getDeltaTime() * getWidth();
    }

    public BusyBarStyle getStyle() {
        return this.style;
    }

    /* loaded from: classes.dex */
    public static class BusyBarStyle {
        public int height;
        public Drawable segment;
        public int segmentOverflow;
        public int segmentWidth;

        public BusyBarStyle() {
        }

        public BusyBarStyle(BusyBarStyle style) {
            this.segment = style.segment;
            this.segmentOverflow = style.segmentOverflow;
            this.segmentWidth = style.segmentWidth;
            this.height = style.height;
        }

        public BusyBarStyle(Drawable segment, int segmentOverflow, int segmentWidth, int height) {
            this.segment = segment;
            this.segmentOverflow = segmentOverflow;
            this.segmentWidth = segmentWidth;
            this.height = height;
        }
    }
}