package com.badlogic.gdx.scenes.scene2d.ui;

import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.Group;
import com.badlogic.gdx.scenes.scene2d.Stage;
import com.badlogic.gdx.scenes.scene2d.utils.Layout;
import com.badlogic.gdx.utils.SnapshotArray;

/* loaded from: classes.dex */
public class WidgetGroup extends Group implements Layout {
    private boolean fillParent;
    private boolean needsLayout = true;
    private boolean layoutEnabled = true;

    public WidgetGroup() {
    }

    public WidgetGroup(Actor... actors) {
        for (Actor actor : actors) {
            addActor(actor);
        }
    }

    public float getMinWidth() {
        return getPrefWidth();
    }

    public float getMinHeight() {
        return getPrefHeight();
    }

    public float getPrefWidth() {
        return 0.0f;
    }

    public float getPrefHeight() {
        return 0.0f;
    }

    public float getMaxWidth() {
        return 0.0f;
    }

    public float getMaxHeight() {
        return 0.0f;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.utils.Layout
    public void setLayoutEnabled(boolean enabled) {
        this.layoutEnabled = enabled;
        setLayoutEnabled(this, enabled);
    }

    private void setLayoutEnabled(Group parent, boolean enabled) {
        SnapshotArray<Actor> children = parent.getChildren();
        int n = children.size;
        for (int i = 0; i < n; i++) {
            Actor actor = children.get(i);
            if (actor instanceof Layout) {
                ((Layout) actor).setLayoutEnabled(enabled);
            } else if (actor instanceof Group) {
                setLayoutEnabled((Group) actor, enabled);
            }
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.utils.Layout
    public void validate() {
        float parentWidth;
        float parentHeight;
        if (this.layoutEnabled) {
            Group parent = getParent();
            if (this.fillParent && parent != null) {
                Stage stage = getStage();
                if (stage != null && parent == stage.getRoot()) {
                    parentWidth = stage.getWidth();
                    parentHeight = stage.getHeight();
                } else {
                    parentWidth = parent.getWidth();
                    parentHeight = parent.getHeight();
                }
                if (getWidth() != parentWidth || getHeight() != parentHeight) {
                    setWidth(parentWidth);
                    setHeight(parentHeight);
                    invalidate();
                }
            }
            if (this.needsLayout) {
                this.needsLayout = false;
                layout();
                if (!this.needsLayout || (parent instanceof WidgetGroup)) {
                    return;
                }
                for (int i = 0; i < 5; i++) {
                    this.needsLayout = false;
                    layout();
                    if (!this.needsLayout) {
                        return;
                    }
                }
            }
        }
    }

    public boolean needsLayout() {
        return this.needsLayout;
    }

    public void invalidate() {
        this.needsLayout = true;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.utils.Layout
    public void invalidateHierarchy() {
        invalidate();
        Group parent = getParent();
        if (parent instanceof Layout) {
            ((Layout) parent).invalidateHierarchy();
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.badlogic.gdx.scenes.scene2d.Group
    public void childrenChanged() {
        invalidateHierarchy();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.badlogic.gdx.scenes.scene2d.Actor
    public void sizeChanged() {
        invalidate();
    }

    @Override // com.badlogic.gdx.scenes.scene2d.utils.Layout
    public void pack() {
        setSize(getPrefWidth(), getPrefHeight());
        validate();
        setSize(getPrefWidth(), getPrefHeight());
        validate();
    }

    @Override // com.badlogic.gdx.scenes.scene2d.utils.Layout
    public void setFillParent(boolean fillParent) {
        this.fillParent = fillParent;
    }

    public void layout() {
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
    public void draw(Batch batch, float parentAlpha) {
        validate();
        super.draw(batch, parentAlpha);
    }
}