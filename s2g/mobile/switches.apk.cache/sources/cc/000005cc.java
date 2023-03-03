package com.kotcrab.vis.ui.widget;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.Cursor;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.math.Rectangle;
import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.InputListener;
import com.badlogic.gdx.scenes.scene2d.Touchable;
import com.badlogic.gdx.scenes.scene2d.ui.SplitPane;
import com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup;
import com.badlogic.gdx.scenes.scene2d.utils.ClickListener;
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;
import com.badlogic.gdx.scenes.scene2d.utils.Layout;
import com.badlogic.gdx.scenes.scene2d.utils.ScissorStack;
import com.badlogic.gdx.utils.GdxRuntimeException;
import com.kotcrab.vis.ui.FocusManager;
import com.kotcrab.vis.ui.VisUI;
import com.kotcrab.vis.ui.util.CursorManager;

/* loaded from: classes.dex */
public class VisSplitPane extends WidgetGroup {
    private Rectangle firstScissors;
    private Actor firstWidget;
    private Rectangle firstWidgetBounds;
    Rectangle handleBounds;
    Vector2 handlePosition;
    Vector2 lastPoint;
    float maxAmount;
    float minAmount;
    private boolean mouseOnHandle;
    private Rectangle secondScissors;
    private Actor secondWidget;
    private Rectangle secondWidgetBounds;
    float splitAmount;
    VisSplitPaneStyle style;
    boolean vertical;

    /* JADX WARN: Illegal instructions before constructor call */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public VisSplitPane(com.badlogic.gdx.scenes.scene2d.Actor r3, com.badlogic.gdx.scenes.scene2d.Actor r4, boolean r5) {
        /*
            r2 = this;
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            r0.<init>()
            java.lang.String r1 = "default-"
            r0.append(r1)
            if (r5 == 0) goto Lf
            java.lang.String r1 = "vertical"
            goto L11
        Lf:
            java.lang.String r1 = "horizontal"
        L11:
            r0.append(r1)
            java.lang.String r0 = r0.toString()
            r2.<init>(r3, r4, r5, r0)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.kotcrab.vis.ui.widget.VisSplitPane.<init>(com.badlogic.gdx.scenes.scene2d.Actor, com.badlogic.gdx.scenes.scene2d.Actor, boolean):void");
    }

    public VisSplitPane(Actor firstWidget, Actor secondWidget, boolean vertical, String styleName) {
        this(firstWidget, secondWidget, vertical, (VisSplitPaneStyle) VisUI.getSkin().get(styleName, VisSplitPaneStyle.class));
    }

    public VisSplitPane(Actor firstWidget, Actor secondWidget, boolean vertical, VisSplitPaneStyle style) {
        this.splitAmount = 0.5f;
        this.maxAmount = 1.0f;
        this.firstWidgetBounds = new Rectangle();
        this.secondWidgetBounds = new Rectangle();
        this.handleBounds = new Rectangle();
        this.firstScissors = new Rectangle();
        this.secondScissors = new Rectangle();
        this.lastPoint = new Vector2();
        this.handlePosition = new Vector2();
        this.firstWidget = firstWidget;
        this.secondWidget = secondWidget;
        this.vertical = vertical;
        setStyle(style);
        setFirstWidget(firstWidget);
        setSecondWidget(secondWidget);
        setSize(getPrefWidth(), getPrefHeight());
        initialize();
    }

    private void initialize() {
        addListener(new ClickListener() { // from class: com.kotcrab.vis.ui.widget.VisSplitPane.1
            Cursor.SystemCursor currentCursor;
            Cursor.SystemCursor targetCursor;

            @Override // com.badlogic.gdx.scenes.scene2d.utils.ClickListener, com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                return true;
            }

            @Override // com.badlogic.gdx.scenes.scene2d.utils.ClickListener, com.badlogic.gdx.scenes.scene2d.InputListener
            public void touchUp(InputEvent event, float x, float y, int pointer, int button) {
                CursorManager.restoreDefaultCursor();
                this.currentCursor = null;
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean mouseMoved(InputEvent event, float x, float y) {
                if (VisSplitPane.this.handleBounds.contains(x, y)) {
                    if (VisSplitPane.this.vertical) {
                        this.targetCursor = Cursor.SystemCursor.VerticalResize;
                    } else {
                        this.targetCursor = Cursor.SystemCursor.HorizontalResize;
                    }
                    if (this.currentCursor != this.targetCursor) {
                        Gdx.graphics.setSystemCursor(this.targetCursor);
                        this.currentCursor = this.targetCursor;
                        return false;
                    }
                    return false;
                }
                clearCustomCursor();
                return false;
            }

            @Override // com.badlogic.gdx.scenes.scene2d.utils.ClickListener, com.badlogic.gdx.scenes.scene2d.InputListener
            public void exit(InputEvent event, float x, float y, int pointer, Actor toActor) {
                super.exit(event, x, y, pointer, toActor);
                if (pointer == -1) {
                    clearCustomCursor();
                }
            }

            private void clearCustomCursor() {
                if (this.currentCursor != null) {
                    CursorManager.restoreDefaultCursor();
                    this.currentCursor = null;
                }
            }
        });
        addListener(new InputListener() { // from class: com.kotcrab.vis.ui.widget.VisSplitPane.2
            int draggingPointer = -1;

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                if (VisSplitPane.this.isTouchable() && this.draggingPointer == -1) {
                    if ((pointer != 0 || button == 0) && VisSplitPane.this.handleBounds.contains(x, y)) {
                        FocusManager.resetFocus(VisSplitPane.this.getStage());
                        this.draggingPointer = pointer;
                        VisSplitPane.this.lastPoint.set(x, y);
                        VisSplitPane.this.handlePosition.set(VisSplitPane.this.handleBounds.x, VisSplitPane.this.handleBounds.y);
                        return true;
                    }
                    return false;
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
            public boolean mouseMoved(InputEvent event, float x, float y) {
                VisSplitPane visSplitPane = VisSplitPane.this;
                visSplitPane.mouseOnHandle = visSplitPane.handleBounds.contains(x, y);
                return false;
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public void touchDragged(InputEvent event, float x, float y, int pointer) {
                if (pointer != this.draggingPointer) {
                    return;
                }
                Drawable handle = VisSplitPane.this.style.handle;
                if (!VisSplitPane.this.vertical) {
                    float delta = x - VisSplitPane.this.lastPoint.x;
                    float availWidth = VisSplitPane.this.getWidth() - handle.getMinWidth();
                    float dragX = VisSplitPane.this.handlePosition.x + delta;
                    VisSplitPane.this.handlePosition.x = dragX;
                    float dragX2 = Math.min(availWidth, Math.max(0.0f, dragX));
                    VisSplitPane visSplitPane = VisSplitPane.this;
                    visSplitPane.splitAmount = dragX2 / availWidth;
                    if (visSplitPane.splitAmount < VisSplitPane.this.minAmount) {
                        VisSplitPane visSplitPane2 = VisSplitPane.this;
                        visSplitPane2.splitAmount = visSplitPane2.minAmount;
                    }
                    if (VisSplitPane.this.splitAmount > VisSplitPane.this.maxAmount) {
                        VisSplitPane visSplitPane3 = VisSplitPane.this;
                        visSplitPane3.splitAmount = visSplitPane3.maxAmount;
                    }
                    VisSplitPane.this.lastPoint.set(x, y);
                } else {
                    float delta2 = y - VisSplitPane.this.lastPoint.y;
                    float availHeight = VisSplitPane.this.getHeight() - handle.getMinHeight();
                    float dragY = VisSplitPane.this.handlePosition.y + delta2;
                    VisSplitPane.this.handlePosition.y = dragY;
                    float dragY2 = Math.min(availHeight, Math.max(0.0f, dragY));
                    VisSplitPane visSplitPane4 = VisSplitPane.this;
                    visSplitPane4.splitAmount = 1.0f - (dragY2 / availHeight);
                    if (visSplitPane4.splitAmount < VisSplitPane.this.minAmount) {
                        VisSplitPane visSplitPane5 = VisSplitPane.this;
                        visSplitPane5.splitAmount = visSplitPane5.minAmount;
                    }
                    if (VisSplitPane.this.splitAmount > VisSplitPane.this.maxAmount) {
                        VisSplitPane visSplitPane6 = VisSplitPane.this;
                        visSplitPane6.splitAmount = visSplitPane6.maxAmount;
                    }
                    VisSplitPane.this.lastPoint.set(x, y);
                }
                VisSplitPane.this.invalidate();
            }
        });
    }

    public VisSplitPaneStyle getStyle() {
        return this.style;
    }

    public void setStyle(VisSplitPaneStyle style) {
        this.style = style;
        invalidateHierarchy();
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public void layout() {
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
        float width = 0.0f;
        Actor actor = this.firstWidget;
        if (actor != null) {
            width = actor instanceof Layout ? ((Layout) actor).getPrefWidth() : actor.getWidth();
        }
        Actor actor2 = this.secondWidget;
        if (actor2 != null) {
            width += actor2 instanceof Layout ? ((Layout) actor2).getPrefWidth() : actor2.getWidth();
        }
        return !this.vertical ? width + this.style.handle.getMinWidth() : width;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getPrefHeight() {
        float height = 0.0f;
        Actor actor = this.firstWidget;
        if (actor != null) {
            height = actor instanceof Layout ? ((Layout) actor).getPrefHeight() : actor.getHeight();
        }
        Actor actor2 = this.secondWidget;
        if (actor2 != null) {
            height += actor2 instanceof Layout ? ((Layout) actor2).getPrefHeight() : actor2.getHeight();
        }
        return this.vertical ? height + this.style.handle.getMinHeight() : height;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getMinWidth() {
        return 0.0f;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getMinHeight() {
        return 0.0f;
    }

    public Rectangle getFirstWidgetBounds() {
        return new Rectangle(this.firstWidgetBounds);
    }

    public Rectangle getSecondWidgetBounds() {
        return new Rectangle(this.secondWidgetBounds);
    }

    public void setVertical(boolean vertical) {
        this.vertical = vertical;
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
        validate();
        Color color = getColor();
        applyTransform(batch, computeTransform());
        if (this.firstWidget != null) {
            getStage().calculateScissors(this.firstWidgetBounds, this.firstScissors);
            if (ScissorStack.pushScissors(this.firstScissors)) {
                if (this.firstWidget.isVisible()) {
                    this.firstWidget.draw(batch, color.a * parentAlpha);
                }
                batch.flush();
                ScissorStack.popScissors();
            }
        }
        if (this.secondWidget != null) {
            getStage().calculateScissors(this.secondWidgetBounds, this.secondScissors);
            if (ScissorStack.pushScissors(this.secondScissors)) {
                if (this.secondWidget.isVisible()) {
                    this.secondWidget.draw(batch, color.a * parentAlpha);
                }
                batch.flush();
                ScissorStack.popScissors();
            }
        }
        Drawable handle = this.style.handle;
        if (this.mouseOnHandle && isTouchable() && this.style.handleOver != null) {
            handle = this.style.handleOver;
        }
        batch.setColor(color.r, color.g, color.b, color.a * parentAlpha);
        handle.draw(batch, this.handleBounds.x, this.handleBounds.y, this.handleBounds.width, this.handleBounds.height);
        resetTransform(batch);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
    public Actor hit(float x, float y, boolean touchable) {
        if (touchable && getTouchable() == Touchable.disabled) {
            return null;
        }
        if (this.handleBounds.contains(x, y)) {
            return this;
        }
        return super.hit(x, y, touchable);
    }

    public void setSplitAmount(float split) {
        this.splitAmount = Math.max(Math.min(this.maxAmount, split), this.minAmount);
        invalidate();
    }

    public float getSplit() {
        return this.splitAmount;
    }

    public void setMinSplitAmount(float minAmount) {
        if (minAmount < 0.0f) {
            throw new GdxRuntimeException("minAmount has to be >= 0");
        }
        if (minAmount >= this.maxAmount) {
            throw new GdxRuntimeException("minAmount has to be < maxAmount");
        }
        this.minAmount = minAmount;
    }

    public void setMaxSplitAmount(float maxAmount) {
        if (maxAmount > 1.0f) {
            throw new GdxRuntimeException("maxAmount has to be >= 0");
        }
        if (maxAmount <= this.minAmount) {
            throw new GdxRuntimeException("maxAmount has to be > minAmount");
        }
        this.maxAmount = maxAmount;
    }

    public void setWidgets(Actor firstWidget, Actor secondWidget) {
        setFirstWidget(firstWidget);
        setSecondWidget(secondWidget);
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
        throw new UnsupportedOperationException("Use ScrollPane#setWidget.");
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group
    public void addActorAt(int index, Actor actor) {
        throw new UnsupportedOperationException("Use ScrollPane#setWidget.");
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group
    public void addActorBefore(Actor actorBefore, Actor actor) {
        throw new UnsupportedOperationException("Use ScrollPane#setWidget.");
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

    /* loaded from: classes.dex */
    public static class VisSplitPaneStyle extends SplitPane.SplitPaneStyle {
        public Drawable handleOver;

        public VisSplitPaneStyle() {
        }

        public VisSplitPaneStyle(VisSplitPaneStyle style) {
            super(style);
            this.handleOver = style.handleOver;
        }

        public VisSplitPaneStyle(Drawable handle, Drawable handleOver) {
            super(handle);
            this.handleOver = handleOver;
        }
    }
}