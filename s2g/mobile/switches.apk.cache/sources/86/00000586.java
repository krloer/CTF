package com.kotcrab.vis.ui.widget;

import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.scenes.scene2d.Action;
import com.badlogic.gdx.scenes.scene2d.Touchable;
import com.badlogic.gdx.scenes.scene2d.ui.Table;
import com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup;
import com.badlogic.gdx.utils.GdxRuntimeException;

/* loaded from: classes.dex */
public class HorizontalCollapsibleWidget extends WidgetGroup {
    private boolean actionRunning;
    private CollapseAction collapseAction;
    private boolean collapsed;
    private float currentWidth;
    private Table table;

    public HorizontalCollapsibleWidget() {
        this.collapseAction = new CollapseAction();
    }

    public HorizontalCollapsibleWidget(Table table) {
        this(table, false);
    }

    public HorizontalCollapsibleWidget(Table table, boolean collapsed) {
        this.collapseAction = new CollapseAction();
        this.collapsed = collapsed;
        this.table = table;
        updateTouchable();
        if (table != null) {
            addActor(table);
        }
    }

    public void setCollapsed(boolean collapse, boolean withAnimation) {
        this.collapsed = collapse;
        updateTouchable();
        Table table = this.table;
        if (table == null) {
            return;
        }
        this.actionRunning = true;
        if (withAnimation) {
            addAction(this.collapseAction);
            return;
        }
        if (collapse) {
            this.currentWidth = 0.0f;
            this.collapsed = true;
        } else {
            this.currentWidth = table.getPrefWidth();
            this.collapsed = false;
        }
        this.actionRunning = false;
        invalidateHierarchy();
    }

    public void setCollapsed(boolean collapse) {
        setCollapsed(collapse, true);
    }

    public boolean isCollapsed() {
        return this.collapsed;
    }

    private void updateTouchable() {
        if (this.collapsed) {
            setTouchable(Touchable.disabled);
        } else {
            setTouchable(Touchable.enabled);
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
    public void draw(Batch batch, float parentAlpha) {
        if (this.currentWidth > 1.0f) {
            batch.flush();
            boolean clipEnabled = clipBegin(getX(), getY(), this.currentWidth, getHeight());
            super.draw(batch, parentAlpha);
            batch.flush();
            if (clipEnabled) {
                clipEnd();
            }
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public void layout() {
        Table table = this.table;
        if (table == null) {
            return;
        }
        table.setBounds(0.0f, 0.0f, table.getPrefWidth(), this.table.getPrefHeight());
        if (!this.actionRunning) {
            if (this.collapsed) {
                this.currentWidth = 0.0f;
            } else {
                this.currentWidth = this.table.getPrefWidth();
            }
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getPrefHeight() {
        Table table = this.table;
        if (table == null) {
            return 0.0f;
        }
        return table.getPrefHeight();
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getPrefWidth() {
        Table table = this.table;
        if (table == null) {
            return 0.0f;
        }
        if (!this.actionRunning) {
            if (this.collapsed) {
                return 0.0f;
            }
            return table.getPrefWidth();
        }
        return this.currentWidth;
    }

    public void setTable(Table table) {
        this.table = table;
        clearChildren();
        addActor(table);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.Group
    public void childrenChanged() {
        super.childrenChanged();
        if (getChildren().size > 1) {
            throw new GdxRuntimeException("Only one actor can be added to CollapsibleWidget");
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public class CollapseAction extends Action {
        private CollapseAction() {
        }

        @Override // com.badlogic.gdx.scenes.scene2d.Action
        public boolean act(float delta) {
            if (HorizontalCollapsibleWidget.this.collapsed) {
                HorizontalCollapsibleWidget.this.currentWidth -= 1000.0f * delta;
                if (HorizontalCollapsibleWidget.this.currentWidth <= 0.0f) {
                    HorizontalCollapsibleWidget.this.currentWidth = 0.0f;
                    HorizontalCollapsibleWidget.this.collapsed = true;
                    HorizontalCollapsibleWidget.this.actionRunning = false;
                }
            } else {
                HorizontalCollapsibleWidget.this.currentWidth += 1000.0f * delta;
                if (HorizontalCollapsibleWidget.this.currentWidth > HorizontalCollapsibleWidget.this.table.getPrefWidth()) {
                    HorizontalCollapsibleWidget horizontalCollapsibleWidget = HorizontalCollapsibleWidget.this;
                    horizontalCollapsibleWidget.currentWidth = horizontalCollapsibleWidget.table.getPrefWidth();
                    HorizontalCollapsibleWidget.this.collapsed = false;
                    HorizontalCollapsibleWidget.this.actionRunning = false;
                }
            }
            HorizontalCollapsibleWidget.this.invalidateHierarchy();
            return !HorizontalCollapsibleWidget.this.actionRunning;
        }
    }
}