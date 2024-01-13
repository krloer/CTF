package com.kotcrab.vis.ui.layout;

import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.Touchable;
import com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup;
import com.badlogic.gdx.scenes.scene2d.utils.Layout;
import com.badlogic.gdx.utils.SnapshotArray;

/* loaded from: classes.dex */
public class HorizontalFlowGroup extends WidgetGroup {
    private float lastPrefHeight;
    private float prefHeight;
    private float prefWidth;
    private boolean sizeInvalid;
    private float spacing;

    public HorizontalFlowGroup() {
        this.sizeInvalid = true;
        this.spacing = 0.0f;
        setTouchable(Touchable.childrenOnly);
    }

    public HorizontalFlowGroup(float spacing) {
        this.sizeInvalid = true;
        this.spacing = 0.0f;
        this.spacing = spacing;
        setTouchable(Touchable.childrenOnly);
    }

    private void computeSize() {
        this.prefWidth = getWidth();
        this.prefHeight = 0.0f;
        this.sizeInvalid = false;
        SnapshotArray<Actor> children = getChildren();
        float x = 0.0f;
        float rowHeight = 0.0f;
        for (int i = 0; i < children.size; i++) {
            Actor child = children.get(i);
            float width = child.getWidth();
            float height = child.getHeight();
            if (child instanceof Layout) {
                Layout layout = (Layout) child;
                width = layout.getPrefWidth();
                height = layout.getPrefHeight();
            }
            if (x + width > getWidth()) {
                x = 0.0f;
                this.prefHeight += this.spacing + rowHeight;
                rowHeight = height;
            } else {
                rowHeight = Math.max(height, rowHeight);
            }
            x += this.spacing + width;
        }
        this.prefHeight += this.spacing + rowHeight;
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
        float rowHeight = 0.0f;
        for (int i = 0; i < children.size; i++) {
            Actor child = children.get(i);
            float width = child.getWidth();
            float height = child.getHeight();
            if (child instanceof Layout) {
                Layout layout = (Layout) child;
                width = layout.getPrefWidth();
                height = layout.getPrefHeight();
            }
            if (x + width > getWidth()) {
                x = 0.0f;
                y -= this.spacing + rowHeight;
                rowHeight = height;
            } else {
                rowHeight = Math.max(height, rowHeight);
            }
            child.setBounds(x, y - height, width, height);
            x += this.spacing + width;
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