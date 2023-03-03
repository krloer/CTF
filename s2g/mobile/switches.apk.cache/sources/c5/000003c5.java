package com.badlogic.gdx.scenes.scene2d.ui;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.math.Rectangle;
import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.InputListener;
import com.badlogic.gdx.scenes.scene2d.Stage;
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;
import com.badlogic.gdx.scenes.scene2d.utils.Layout;
import com.badlogic.gdx.scenes.scene2d.utils.ScissorStack;
import com.badlogic.gdx.utils.GdxRuntimeException;

/* loaded from: classes.dex */
public class SplitPane extends WidgetGroup {
    boolean cursorOverHandle;
    private Actor firstWidget;
    private final Rectangle firstWidgetBounds;
    final Rectangle handleBounds;
    Vector2 handlePosition;
    Vector2 lastPoint;
    float maxAmount;
    float minAmount;
    private Actor secondWidget;
    private final Rectangle secondWidgetBounds;
    float splitAmount;
    SplitPaneStyle style;
    private final Rectangle tempScissors;
    boolean vertical;

    /* JADX WARN: Illegal instructions before constructor call */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public SplitPane(com.badlogic.gdx.scenes.scene2d.Actor r9, com.badlogic.gdx.scenes.scene2d.Actor r10, boolean r11, com.badlogic.gdx.scenes.scene2d.ui.Skin r12) {
        /*
            r8 = this;
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            r0.<init>()
            java.lang.String r1 = "default-"
            r0.append(r1)
            if (r11 == 0) goto Lf
            java.lang.String r1 = "vertical"
            goto L11
        Lf:
            java.lang.String r1 = "horizontal"
        L11:
            r0.append(r1)
            java.lang.String r7 = r0.toString()
            r2 = r8
            r3 = r9
            r4 = r10
            r5 = r11
            r6 = r12
            r2.<init>(r3, r4, r5, r6, r7)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.badlogic.gdx.scenes.scene2d.ui.SplitPane.<init>(com.badlogic.gdx.scenes.scene2d.Actor, com.badlogic.gdx.scenes.scene2d.Actor, boolean, com.badlogic.gdx.scenes.scene2d.ui.Skin):void");
    }

    public SplitPane(Actor firstWidget, Actor secondWidget, boolean vertical, Skin skin, String styleName) {
        this(firstWidget, secondWidget, vertical, (SplitPaneStyle) skin.get(styleName, SplitPaneStyle.class));
    }

    public SplitPane(Actor firstWidget, Actor secondWidget, boolean vertical, SplitPaneStyle style) {
        this.splitAmount = 0.5f;
        this.maxAmount = 1.0f;
        this.firstWidgetBounds = new Rectangle();
        this.secondWidgetBounds = new Rectangle();
        this.handleBounds = new Rectangle();
        this.tempScissors = new Rectangle();
        this.lastPoint = new Vector2();
        this.handlePosition = new Vector2();
        this.vertical = vertical;
        setStyle(style);
        setFirstWidget(firstWidget);
        setSecondWidget(secondWidget);
        setSize(getPrefWidth(), getPrefHeight());
        initialize();
    }

    private void initialize() {
        addListener(new InputListener() { // from class: com.badlogic.gdx.scenes.scene2d.ui.SplitPane.1
            int draggingPointer = -1;

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                if (this.draggingPointer != -1) {
                    return false;
                }
                if ((pointer != 0 || button == 0) && SplitPane.this.handleBounds.contains(x, y)) {
                    this.draggingPointer = pointer;
                    SplitPane.this.lastPoint.set(x, y);
                    SplitPane.this.handlePosition.set(SplitPane.this.handleBounds.x, SplitPane.this.handleBounds.y);
                    return true;
                }
                return false;
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public void touchUp(InputEvent event, float x, float y, int pointer, int button) {
                if (pointer == this.draggingPointer) {
                    this.draggingPointer = -1;
                }
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public void touchDragged(InputEvent event, float x, float y, int pointer) {
                if (pointer != this.draggingPointer) {
                    return;
                }
                Drawable handle = SplitPane.this.style.handle;
                if (!SplitPane.this.vertical) {
                    float delta = x - SplitPane.this.lastPoint.x;
                    float availWidth = SplitPane.this.getWidth() - handle.getMinWidth();
                    float dragX = SplitPane.this.handlePosition.x + delta;
                    SplitPane.this.handlePosition.x = dragX;
                    float dragX2 = Math.min(availWidth, Math.max(0.0f, dragX));
                    SplitPane splitPane = SplitPane.this;
                    splitPane.splitAmount = dragX2 / availWidth;
                    splitPane.lastPoint.set(x, y);
                } else {
                    float delta2 = y - SplitPane.this.lastPoint.y;
                    float availHeight = SplitPane.this.getHeight() - handle.getMinHeight();
                    float dragY = SplitPane.this.handlePosition.y + delta2;
                    SplitPane.this.handlePosition.y = dragY;
                    float dragY2 = Math.min(availHeight, Math.max(0.0f, dragY));
                    SplitPane splitPane2 = SplitPane.this;
                    splitPane2.splitAmount = 1.0f - (dragY2 / availHeight);
                    splitPane2.lastPoint.set(x, y);
                }
                SplitPane.this.invalidate();
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean mouseMoved(InputEvent event, float x, float y) {
                SplitPane splitPane = SplitPane.this;
                splitPane.cursorOverHandle = splitPane.handleBounds.contains(x, y);
                return false;
            }
        });
    }

    public void setStyle(SplitPaneStyle style) {
        this.style = style;
        invalidateHierarchy();
    }

    public SplitPaneStyle getStyle() {
        return this.style;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public void layout() {
        clampSplitAmount();
        if (!this.vertical) {
            calculateHorizBoundsAndPositions();
        } else {
            calculateVertBoundsAndPositions();
        }
        Actor firstWidget = this.firstWidget;
        if (firstWidget != null) {
            Rectangle firstWidgetBounds = this.firstWidgetBounds;
            firstWidget.setBounds(firstWidgetBounds.x, firstWidgetBounds.y, firstWidgetBounds.width, firstWidgetBounds.height);
            if (firstWidget instanceof Layout) {
                ((Layout) firstWidget).validate();
            }
        }
        Actor secondWidget = this.secondWidget;
        if (secondWidget != null) {
            Rectangle secondWidgetBounds = this.secondWidgetBounds;
            secondWidget.setBounds(secondWidgetBounds.x, secondWidgetBounds.y, secondWidgetBounds.width, secondWidgetBounds.height);
            if (secondWidget instanceof Layout) {
                ((Layout) secondWidget).validate();
            }
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getPrefWidth() {
        float first;
        Actor actor = this.firstWidget;
        float second = 0.0f;
        if (actor == null) {
            first = 0.0f;
        } else {
            first = actor instanceof Layout ? ((Layout) actor).getPrefWidth() : actor.getWidth();
        }
        Actor actor2 = this.secondWidget;
        if (actor2 != null) {
            second = actor2 instanceof Layout ? ((Layout) actor2).getPrefWidth() : actor2.getWidth();
        }
        return this.vertical ? Math.max(first, second) : this.style.handle.getMinWidth() + first + second;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getPrefHeight() {
        float first;
        Actor actor = this.firstWidget;
        float second = 0.0f;
        if (actor == null) {
            first = 0.0f;
        } else {
            first = actor instanceof Layout ? ((Layout) actor).getPrefHeight() : actor.getHeight();
        }
        Actor actor2 = this.secondWidget;
        if (actor2 != null) {
            second = actor2 instanceof Layout ? ((Layout) actor2).getPrefHeight() : actor2.getHeight();
        }
        return !this.vertical ? Math.max(first, second) : this.style.handle.getMinHeight() + first + second;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getMinWidth() {
        Actor actor = this.firstWidget;
        float first = actor instanceof Layout ? ((Layout) actor).getMinWidth() : 0.0f;
        Actor actor2 = this.secondWidget;
        float second = actor2 instanceof Layout ? ((Layout) actor2).getMinWidth() : 0.0f;
        return this.vertical ? Math.max(first, second) : this.style.handle.getMinWidth() + first + second;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getMinHeight() {
        Actor actor = this.firstWidget;
        float first = actor instanceof Layout ? ((Layout) actor).getMinHeight() : 0.0f;
        Actor actor2 = this.secondWidget;
        float second = actor2 instanceof Layout ? ((Layout) actor2).getMinHeight() : 0.0f;
        return !this.vertical ? Math.max(first, second) : this.style.handle.getMinHeight() + first + second;
    }

    public void setVertical(boolean vertical) {
        if (this.vertical == vertical) {
            return;
        }
        this.vertical = vertical;
        invalidateHierarchy();
    }

    public boolean isVertical() {
        return this.vertical;
    }

    private void calculateHorizBoundsAndPositions() {
        Drawable handle = this.style.handle;
        float height = getHeight();
        float availWidth = getWidth() - handle.getMinWidth();
        float leftAreaWidth = (int) (this.splitAmount * availWidth);
        float rightAreaWidth = availWidth - leftAreaWidth;
        float handleWidth = handle.getMinWidth();
        this.firstWidgetBounds.set(0.0f, 0.0f, leftAreaWidth, height);
        this.secondWidgetBounds.set(leftAreaWidth + handleWidth, 0.0f, rightAreaWidth, height);
        this.handleBounds.set(leftAreaWidth, 0.0f, handleWidth, height);
    }

    private void calculateVertBoundsAndPositions() {
        Drawable handle = this.style.handle;
        float width = getWidth();
        float height = getHeight();
        float availHeight = height - handle.getMinHeight();
        float topAreaHeight = (int) (this.splitAmount * availHeight);
        float bottomAreaHeight = availHeight - topAreaHeight;
        float handleHeight = handle.getMinHeight();
        this.firstWidgetBounds.set(0.0f, height - topAreaHeight, width, topAreaHeight);
        this.secondWidgetBounds.set(0.0f, 0.0f, width, bottomAreaHeight);
        this.handleBounds.set(0.0f, bottomAreaHeight, width, handleHeight);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
    public void draw(Batch batch, float parentAlpha) {
        Stage stage = getStage();
        if (stage == null) {
            return;
        }
        validate();
        Color color = getColor();
        float alpha = color.a * parentAlpha;
        applyTransform(batch, computeTransform());
        Actor actor = this.firstWidget;
        if (actor != null && actor.isVisible()) {
            batch.flush();
            stage.calculateScissors(this.firstWidgetBounds, this.tempScissors);
            if (ScissorStack.pushScissors(this.tempScissors)) {
                this.firstWidget.draw(batch, alpha);
                batch.flush();
                ScissorStack.popScissors();
            }
        }
        Actor actor2 = this.secondWidget;
        if (actor2 != null && actor2.isVisible()) {
            batch.flush();
            stage.calculateScissors(this.secondWidgetBounds, this.tempScissors);
            if (ScissorStack.pushScissors(this.tempScissors)) {
                this.secondWidget.draw(batch, alpha);
                batch.flush();
                ScissorStack.popScissors();
            }
        }
        batch.setColor(color.r, color.g, color.b, alpha);
        this.style.handle.draw(batch, this.handleBounds.x, this.handleBounds.y, this.handleBounds.width, this.handleBounds.height);
        resetTransform(batch);
    }

    public void setSplitAmount(float splitAmount) {
        this.splitAmount = splitAmount;
        invalidate();
    }

    public float getSplitAmount() {
        return this.splitAmount;
    }

    protected void clampSplitAmount() {
        float effectiveMinAmount = this.minAmount;
        float effectiveMaxAmount = this.maxAmount;
        if (this.vertical) {
            float availableHeight = getHeight() - this.style.handle.getMinHeight();
            Actor actor = this.firstWidget;
            if (actor instanceof Layout) {
                effectiveMinAmount = Math.max(effectiveMinAmount, Math.min(((Layout) actor).getMinHeight() / availableHeight, 1.0f));
            }
            Actor actor2 = this.secondWidget;
            if (actor2 instanceof Layout) {
                effectiveMaxAmount = Math.min(effectiveMaxAmount, 1.0f - Math.min(((Layout) actor2).getMinHeight() / availableHeight, 1.0f));
            }
        } else {
            float availableWidth = getWidth() - this.style.handle.getMinWidth();
            Actor actor3 = this.firstWidget;
            if (actor3 instanceof Layout) {
                effectiveMinAmount = Math.max(effectiveMinAmount, Math.min(((Layout) actor3).getMinWidth() / availableWidth, 1.0f));
            }
            Actor actor4 = this.secondWidget;
            if (actor4 instanceof Layout) {
                effectiveMaxAmount = Math.min(effectiveMaxAmount, 1.0f - Math.min(((Layout) actor4).getMinWidth() / availableWidth, 1.0f));
            }
        }
        if (effectiveMinAmount > effectiveMaxAmount) {
            this.splitAmount = (effectiveMinAmount + effectiveMaxAmount) * 0.5f;
        } else {
            this.splitAmount = Math.max(Math.min(this.splitAmount, effectiveMaxAmount), effectiveMinAmount);
        }
    }

    public float getMinSplitAmount() {
        return this.minAmount;
    }

    public void setMinSplitAmount(float minAmount) {
        if (minAmount < 0.0f || minAmount > 1.0f) {
            throw new GdxRuntimeException("minAmount has to be >= 0 and <= 1");
        }
        this.minAmount = minAmount;
    }

    public float getMaxSplitAmount() {
        return this.maxAmount;
    }

    public void setMaxSplitAmount(float maxAmount) {
        if (maxAmount < 0.0f || maxAmount > 1.0f) {
            throw new GdxRuntimeException("maxAmount has to be >= 0 and <= 1");
        }
        this.maxAmount = maxAmount;
    }

    public void setFirstWidget(Actor widget) {
        Actor actor = this.firstWidget;
        if (actor != null) {
            super.removeActor(actor);
        }
        this.firstWidget = widget;
        if (widget != null) {
            super.addActor(widget);
        }
        invalidate();
    }

    public void setSecondWidget(Actor widget) {
        Actor actor = this.secondWidget;
        if (actor != null) {
            super.removeActor(actor);
        }
        this.secondWidget = widget;
        if (widget != null) {
            super.addActor(widget);
        }
        invalidate();
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group
    public void addActor(Actor actor) {
        throw new UnsupportedOperationException("Use SplitPane#setWidget.");
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group
    public void addActorAt(int index, Actor actor) {
        throw new UnsupportedOperationException("Use SplitPane#setWidget.");
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group
    public void addActorBefore(Actor actorBefore, Actor actor) {
        throw new UnsupportedOperationException("Use SplitPane#setWidget.");
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group
    public boolean removeActor(Actor actor) {
        if (actor == null) {
            throw new IllegalArgumentException("actor cannot be null.");
        }
        if (actor == this.firstWidget) {
            setFirstWidget(null);
            return true;
        } else if (actor == this.secondWidget) {
            setSecondWidget(null);
            return true;
        } else {
            return true;
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group
    public boolean removeActor(Actor actor, boolean unfocus) {
        if (actor == null) {
            throw new IllegalArgumentException("actor cannot be null.");
        }
        if (actor == this.firstWidget) {
            super.removeActor(actor, unfocus);
            this.firstWidget = null;
            invalidate();
            return true;
        } else if (actor == this.secondWidget) {
            super.removeActor(actor, unfocus);
            this.secondWidget = null;
            invalidate();
            return true;
        } else {
            return false;
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group
    public Actor removeActorAt(int index, boolean unfocus) {
        Actor actor = super.removeActorAt(index, unfocus);
        if (actor == this.firstWidget) {
            super.removeActor(actor, unfocus);
            this.firstWidget = null;
            invalidate();
        } else if (actor == this.secondWidget) {
            super.removeActor(actor, unfocus);
            this.secondWidget = null;
            invalidate();
        }
        return actor;
    }

    public boolean isCursorOverHandle() {
        return this.cursorOverHandle;
    }

    /* loaded from: classes.dex */
    public static class SplitPaneStyle {
        public Drawable handle;

        public SplitPaneStyle() {
        }

        public SplitPaneStyle(Drawable handle) {
            this.handle = handle;
        }

        public SplitPaneStyle(SplitPaneStyle style) {
            this.handle = style.handle;
        }
    }
}