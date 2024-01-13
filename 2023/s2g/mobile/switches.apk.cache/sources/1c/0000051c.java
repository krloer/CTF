package com.kotcrab.vis.ui.layout;

import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.Touchable;
import com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup;
import com.badlogic.gdx.scenes.scene2d.utils.Layout;
import com.badlogic.gdx.utils.SnapshotArray;

/* loaded from: classes.dex */
public class VerticalFlowGroup extends WidgetGroup {
    private float lastPrefHeight;
    private float prefHeight;
    private float prefWidth;
    private boolean sizeInvalid;
    private float spacing;

    public VerticalFlowGroup() {
        this.sizeInvalid = true;
        this.spacing = 0.0f;
        setTouchable(Touchable.childrenOnly);
    }

    public VerticalFlowGroup(float spacing) {
        this.sizeInvalid = true;
        this.spacing = 0.0f;
        this.spacing = spacing;
        setTouchable(Touchable.childrenOnly);
    }

    private void computeSize() {
        this.prefWidth = 0.0f;
        this.prefHeight = getHeight();
        this.sizeInvalid = false;
        SnapshotArray<Actor> children = getChildren();
        float y = 0.0f;
        float columnWidth = 0.0f;
        for (int i = 0; i < children.size; i++) {
            Actor child = children.get(i);
            float width = child.getWidth();
            float height = child.getHeight();
            if (child instanceof Layout) {
                Layout layout = (Layout) child;
                width = layout.getPrefWidth();
                height = layout.getPrefHeight();
            }
            if (y + height > getHeight()) {
                y = 0.0f;
                this.prefWidth += this.spacing + columnWidth;
                columnWidth = width;
            } else {
                columnWidth = Math.max(width, columnWidth);
            }
            y += this.spacing + height;
        }
        this.prefWidth += this.spacing + columnWidth;
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
        float x = 0.0f;
        float y = getHeight();
        float columnWidth = 0.0f;
        for (int i = 0; i < children.size; i++) {
            Actor child = children.get(i);
            float width = child.getWidth();
            float height = child.getHeight();
            if (child instanceof Layout) {
                Layout layout = (Layout) child;
                width = layout.getPrefWidth();
                height = layout.getPrefHeight();
            }
            if (y - height < 0.0f) {
                y = getHeight();
                x += this.spacing + columnWidth;
                columnWidth = width;
            } else {
                columnWidth = Math.max(width, columnWidth);
            }
            child.setBounds(x, y - height, width, height);
            y -= this.spacing + height;
        }
    }

    public float getSpacing() {
        return this.spacing;
    }

    public void setSpacing(float spacing) {
        this.spacing = spacing;
        invalidateHierarchy();
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