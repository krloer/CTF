package com.kotcrab.vis.ui.layout;

import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.Touchable;
import com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup;
import com.badlogic.gdx.utils.SnapshotArray;

/* loaded from: classes.dex */
public class GridGroup extends WidgetGroup {
    private float itemHeight;
    private float itemWidth;
    private float lastPrefHeight;
    private float prefHeight;
    private float prefWidth;
    private boolean sizeInvalid;
    private float spacing;

    public GridGroup() {
        this.sizeInvalid = true;
        this.itemWidth = 256.0f;
        this.itemHeight = 256.0f;
        this.spacing = 8.0f;
        setTouchable(Touchable.childrenOnly);
    }

    public GridGroup(float itemSize) {
        this.sizeInvalid = true;
        this.itemWidth = 256.0f;
        this.itemHeight = 256.0f;
        this.spacing = 8.0f;
        this.itemWidth = itemSize;
        this.itemHeight = itemSize;
        setTouchable(Touchable.childrenOnly);
    }

    public GridGroup(float itemSize, float spacing) {
        this.sizeInvalid = true;
        this.itemWidth = 256.0f;
        this.itemHeight = 256.0f;
        this.spacing = 8.0f;
        this.spacing = spacing;
        this.itemWidth = itemSize;
        this.itemHeight = itemSize;
        setTouchable(Touchable.childrenOnly);
    }

    private void computeSize() {
        float maxHeight;
        this.prefWidth = getWidth();
        this.prefHeight = 0.0f;
        this.sizeInvalid = false;
        SnapshotArray<Actor> children = getChildren();
        if (children.size == 0) {
            this.prefWidth = 0.0f;
            this.prefHeight = 0.0f;
            return;
        }
        float width = getWidth();
        float maxHeight2 = 0.0f;
        float tempX = this.spacing;
        for (int i = 0; i < children.size; i++) {
            float f = this.spacing;
            if (this.itemWidth + tempX + f > width) {
                tempX = this.spacing;
                maxHeight2 += this.itemHeight + f;
            }
            tempX += this.itemWidth + this.spacing;
        }
        float f2 = this.itemWidth;
        float f3 = this.spacing;
        if (f2 + (f3 * 2.0f) > this.prefWidth) {
            maxHeight = maxHeight2 + f3;
        } else {
            maxHeight = maxHeight2 + this.itemHeight + (f3 * 2.0f);
        }
        this.prefHeight = maxHeight;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public void layout() {
        if (this.sizeInvalid) {
            computeSize();
            float f = this.lastPrefHeight;
            float f2 = this.prefHeight;
            if (f != f2) {
                this.lastPrefHeight = f2;
                invalidateHierarchy();
            }
        }
        SnapshotArray<Actor> children = getChildren();
        float width = getWidth();
        boolean notEnoughSpace = this.itemWidth + (this.spacing * 2.0f) > width;
        float x = this.spacing;
        float y = getHeight();
        if (!notEnoughSpace) {
            y = (y - this.itemHeight) - this.spacing;
        }
        for (int i = 0; i < children.size; i++) {
            Actor child = children.get(i);
            float f3 = this.spacing;
            if (this.itemWidth + x + f3 > width) {
                x = this.spacing;
                y -= this.itemHeight + f3;
            }
            child.setBounds(x, y, this.itemWidth, this.itemHeight);
            x += this.itemWidth + this.spacing;
        }
    }

    public float getSpacing() {
        return this.spacing;
    }

    public void setSpacing(float spacing) {
        this.spacing = spacing;
        invalidateHierarchy();
    }

    public void setItemSize(float itemSize) {
        this.itemWidth = itemSize;
        this.itemHeight = itemSize;
        invalidateHierarchy();
    }

    public void setItemSize(float itemWidth, float itemHeight) {
        this.itemWidth = itemWidth;
        this.itemHeight = itemHeight;
        invalidateHierarchy();
    }

    public float getItemWidth() {
        return this.itemWidth;
    }

    public void setItemWidth(float itemWidth) {
        this.itemWidth = itemWidth;
    }

    public float getItemHeight() {
        return this.itemHeight;
    }

    public void setItemHeight(float itemHeight) {
        this.itemHeight = itemHeight;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public void invalidate() {
        super.invalidate();
        this.sizeInvalid = true;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getPrefWidth() {
        if (this.sizeInvalid) {
            computeSize();
        }
        return this.prefWidth;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getPrefHeight() {
        if (this.sizeInvalid) {
            computeSize();
        }
        return this.prefHeight;
    }
}