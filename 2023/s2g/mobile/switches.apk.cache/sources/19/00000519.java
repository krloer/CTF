package com.kotcrab.vis.ui.layout;

import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.Touchable;
import com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup;
import com.badlogic.gdx.scenes.scene2d.utils.Layout;
import com.badlogic.gdx.utils.SnapshotArray;

/* loaded from: classes.dex */
public class FloatingGroup extends WidgetGroup {
    private boolean useChildrenPreferredSize = false;
    private float prefWidth = 0.0f;
    private float prefHeight = 0.0f;

    public FloatingGroup() {
        setTouchable(Touchable.childrenOnly);
    }

    public FloatingGroup(float prefWidth, float prefHeight) {
        setTouchable(Touchable.childrenOnly);
        setPrefWidth(prefWidth);
        setPrefHeight(prefHeight);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public void layout() {
        if (this.useChildrenPreferredSize) {
            SnapshotArray<Actor> children = getChildren();
            for (int i = 0; i < children.size; i++) {
                Actor child = children.get(i);
                float width = child.getWidth();
                float height = child.getHeight();
                if (child instanceof Layout) {
                    Layout layout = (Layout) child;
                    width = layout.getPrefWidth();
                    height = layout.getPrefHeight();
                }
                child.setBounds(child.getX(), child.getY(), width, height);
            }
        }
    }

    public boolean isUseChildrenPreferredSize() {
        return this.useChildrenPreferredSize;
    }

    public void setUseChildrenPreferredSize(boolean useChildrenPreferredSize) {
        this.useChildrenPreferredSize = useChildrenPreferredSize;
        invalidate();
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getPrefWidth() {
        float f = this.prefWidth;
        return f < 0.0f ? getWidth() : f;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getPrefHeight() {
        float f = this.prefHeight;
        return f < 0.0f ? getHeight() : f;
    }

    public void setPrefWidth(float prefWidth) {
        this.prefWidth = prefWidth;
        invalidate();
    }

    public void setPrefHeight(float prefHeight) {
        this.prefHeight = prefHeight;
        invalidate();
    }
}