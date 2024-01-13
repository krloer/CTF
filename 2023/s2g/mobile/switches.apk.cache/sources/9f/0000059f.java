package com.kotcrab.vis.ui.widget;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.Cursor;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.math.MathUtils;
import com.badlogic.gdx.math.Rectangle;
import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.InputListener;
import com.badlogic.gdx.scenes.scene2d.Touchable;
import com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup;
import com.badlogic.gdx.scenes.scene2d.utils.ClickListener;
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;
import com.badlogic.gdx.scenes.scene2d.utils.Layout;
import com.badlogic.gdx.scenes.scene2d.utils.ScissorStack;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.FloatArray;
import com.badlogic.gdx.utils.SnapshotArray;
import com.kotcrab.vis.ui.FocusManager;
import com.kotcrab.vis.ui.VisUI;
import com.kotcrab.vis.ui.util.CursorManager;
import com.kotcrab.vis.ui.widget.VisSplitPane;
import java.util.Arrays;
import java.util.Iterator;

/* loaded from: classes.dex */
public class MultiSplitPane extends WidgetGroup {
    private Array<Rectangle> handleBounds;
    private Rectangle handleOver;
    private int handleOverIndex;
    private Vector2 handlePosition;
    private Vector2 lastPoint;
    private Array<Rectangle> scissors;
    private FloatArray splits;
    private MultiSplitPaneStyle style;
    private boolean vertical;
    private Array<Rectangle> widgetBounds;

    /* JADX WARN: Illegal instructions before constructor call */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public MultiSplitPane(boolean r3) {
        /*
            r2 = this;
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            r0.<init>()
            java.lang.String r1 = "default-"
            r0.append(r1)
            if (r3 == 0) goto Lf
            java.lang.String r1 = "vertical"
            goto L11
        Lf:
            java.lang.String r1 = "horizontal"
        L11:
            r0.append(r1)
            java.lang.String r0 = r0.toString()
            r2.<init>(r3, r0)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.kotcrab.vis.ui.widget.MultiSplitPane.<init>(boolean):void");
    }

    public MultiSplitPane(boolean vertical, String styleName) {
        this(vertical, (MultiSplitPaneStyle) VisUI.getSkin().get(styleName, MultiSplitPaneStyle.class));
    }

    public MultiSplitPane(boolean vertical, MultiSplitPaneStyle style) {
        this.widgetBounds = new Array<>();
        this.scissors = new Array<>();
        this.handleBounds = new Array<>();
        this.splits = new FloatArray();
        this.handlePosition = new Vector2();
        this.lastPoint = new Vector2();
        this.vertical = vertical;
        setStyle(style);
        setSize(getPrefWidth(), getPrefHeight());
        initialize();
    }

    private void initialize() {
        addListener(new ClickListener() { // from class: com.kotcrab.vis.ui.widget.MultiSplitPane.1
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
                if (MultiSplitPane.this.getHandleContaining(x, y) != null) {
                    if (MultiSplitPane.this.vertical) {
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
        addListener(new InputListener() { // from class: com.kotcrab.vis.ui.widget.MultiSplitPane.2
            int draggingPointer = -1;

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                Rectangle containingHandle;
                if (MultiSplitPane.this.isTouchable() && this.draggingPointer == -1) {
                    if ((pointer != 0 || button == 0) && (containingHandle = MultiSplitPane.this.getHandleContaining(x, y)) != null) {
                        MultiSplitPane multiSplitPane = MultiSplitPane.this;
                        multiSplitPane.handleOverIndex = multiSplitPane.handleBounds.indexOf(containingHandle, true);
                        FocusManager.resetFocus(MultiSplitPane.this.getStage());
                        this.draggingPointer = pointer;
                        MultiSplitPane.this.lastPoint.set(x, y);
                        MultiSplitPane.this.handlePosition.set(containingHandle.x, containingHandle.y);
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
                MultiSplitPane multiSplitPane = MultiSplitPane.this;
                multiSplitPane.handleOver = multiSplitPane.getHandleContaining(x, y);
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean mouseMoved(InputEvent event, float x, float y) {
                MultiSplitPane multiSplitPane = MultiSplitPane.this;
                multiSplitPane.handleOver = multiSplitPane.getHandleContaining(x, y);
                return false;
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public void touchDragged(InputEvent event, float x, float y, int pointer) {
                if (pointer != this.draggingPointer) {
                    return;
                }
                Drawable handle = MultiSplitPane.this.style.handle;
                if (!MultiSplitPane.this.vertical) {
                    float delta = x - MultiSplitPane.this.lastPoint.x;
                    float availWidth = MultiSplitPane.this.getWidth() - handle.getMinWidth();
                    float dragX = MultiSplitPane.this.handlePosition.x + delta;
                    MultiSplitPane.this.handlePosition.x = dragX;
                    float targetSplit = Math.min(availWidth, Math.max(0.0f, dragX)) / availWidth;
                    MultiSplitPane multiSplitPane = MultiSplitPane.this;
                    multiSplitPane.setSplit(multiSplitPane.handleOverIndex, targetSplit);
                    MultiSplitPane.this.lastPoint.set(x, y);
                } else {
                    float delta2 = y - MultiSplitPane.this.lastPoint.y;
                    float availHeight = MultiSplitPane.this.getHeight() - handle.getMinHeight();
                    float dragY = MultiSplitPane.this.handlePosition.y + delta2;
                    MultiSplitPane.this.handlePosition.y = dragY;
                    float targetSplit2 = 1.0f - (Math.min(availHeight, Math.max(0.0f, dragY)) / availHeight);
                    MultiSplitPane multiSplitPane2 = MultiSplitPane.this;
                    multiSplitPane2.setSplit(multiSplitPane2.handleOverIndex, targetSplit2);
                    MultiSplitPane.this.lastPoint.set(x, y);
                }
                MultiSplitPane.this.invalidate();
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public Rectangle getHandleContaining(float x, float y) {
        Iterator it = this.handleBounds.iterator();
        while (it.hasNext()) {
            Rectangle rect = (Rectangle) it.next();
            if (rect.contains(x, y)) {
                return rect;
            }
        }
        return null;
    }

    public MultiSplitPaneStyle getStyle() {
        return this.style;
    }

    public void setStyle(MultiSplitPaneStyle style) {
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
        SnapshotArray<Actor> actors = getChildren();
        for (int i = 0; i < actors.size; i++) {
            Actor actor = actors.get(i);
            Rectangle bounds = this.widgetBounds.get(i);
            actor.setBounds(bounds.x, bounds.y, bounds.width, bounds.height);
            if (actor instanceof Layout) {
                ((Layout) actor).validate();
            }
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getPrefWidth() {
        float width = 0.0f;
        Array.ArrayIterator<Actor> it = getChildren().iterator();
        while (it.hasNext()) {
            Actor actor = it.next();
            width = actor instanceof Layout ? ((Layout) actor).getPrefWidth() : actor.getWidth();
        }
        return !this.vertical ? width + (this.handleBounds.size * this.style.handle.getMinWidth()) : width;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getPrefHeight() {
        float height = 0.0f;
        Array.ArrayIterator<Actor> it = getChildren().iterator();
        while (it.hasNext()) {
            Actor actor = it.next();
            height = actor instanceof Layout ? ((Layout) actor).getPrefHeight() : actor.getHeight();
        }
        return this.vertical ? height + (this.handleBounds.size * this.style.handle.getMinHeight()) : height;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getMinWidth() {
        return 0.0f;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getMinHeight() {
        return 0.0f;
    }

    public void setVertical(boolean vertical) {
        this.vertical = vertical;
    }

    private void calculateHorizBoundsAndPositions() {
        float height = getHeight();
        float width = getWidth();
        float handleWidth = this.style.handle.getMinWidth();
        float availWidth = width - (this.handleBounds.size * handleWidth);
        float areaUsed = 0.0f;
        float currentX = 0.0f;
        for (int i = 0; i < this.splits.size; i++) {
            float areaWidthFromLeft = (int) (this.splits.get(i) * availWidth);
            float areaWidth = areaWidthFromLeft - areaUsed;
            areaUsed += areaWidth;
            this.widgetBounds.get(i).set(currentX, 0.0f, areaWidth, height);
            float currentX2 = currentX + areaWidth;
            this.handleBounds.get(i).set(currentX2, 0.0f, handleWidth, height);
            currentX = currentX2 + handleWidth;
        }
        if (this.widgetBounds.size != 0) {
            this.widgetBounds.peek().set(currentX, 0.0f, availWidth - areaUsed, height);
        }
    }

    private void calculateVertBoundsAndPositions() {
        float width = getWidth();
        float height = getHeight();
        float handleHeight = this.style.handle.getMinHeight();
        float availHeight = height - (this.handleBounds.size * handleHeight);
        float areaUsed = 0.0f;
        float currentY = height;
        for (int i = 0; i < this.splits.size; i++) {
            float areaHeightFromTop = (int) (this.splits.get(i) * availHeight);
            float areaHeight = areaHeightFromTop - areaUsed;
            areaUsed += areaHeight;
            this.widgetBounds.get(i).set(0.0f, currentY - areaHeight, width, areaHeight);
            float currentY2 = currentY - areaHeight;
            this.handleBounds.get(i).set(0.0f, currentY2 - handleHeight, width, handleHeight);
            currentY = currentY2 - handleHeight;
        }
        if (this.widgetBounds.size != 0) {
            this.widgetBounds.peek().set(0.0f, 0.0f, width, availHeight - areaUsed);
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
    public void draw(Batch batch, float parentAlpha) {
        Drawable handleOver;
        validate();
        Color color = getColor();
        applyTransform(batch, computeTransform());
        SnapshotArray<Actor> actors = getChildren();
        for (int i = 0; i < actors.size; i++) {
            Actor actor = actors.get(i);
            Rectangle bounds = this.widgetBounds.get(i);
            Rectangle scissor = this.scissors.get(i);
            getStage().calculateScissors(bounds, scissor);
            if (ScissorStack.pushScissors(scissor)) {
                if (actor.isVisible()) {
                    actor.draw(batch, color.a * parentAlpha);
                }
                batch.flush();
                ScissorStack.popScissors();
            }
        }
        batch.setColor(color.r, color.g, color.b, color.a * parentAlpha);
        Drawable handle = this.style.handle;
        Drawable handleOver2 = this.style.handle;
        if (!isTouchable() || this.style.handleOver == null) {
            handleOver = handleOver2;
        } else {
            Drawable handleOver3 = this.style.handleOver;
            handleOver = handleOver3;
        }
        Iterator it = this.handleBounds.iterator();
        while (it.hasNext()) {
            Rectangle rect = (Rectangle) it.next();
            if (this.handleOver == rect) {
                handleOver.draw(batch, rect.x, rect.y, rect.width, rect.height);
            } else {
                handle.draw(batch, rect.x, rect.y, rect.width, rect.height);
            }
        }
        resetTransform(batch);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
    public Actor hit(float x, float y, boolean touchable) {
        if (touchable && getTouchable() == Touchable.disabled) {
            return null;
        }
        if (getHandleContaining(x, y) != null) {
            return this;
        }
        return super.hit(x, y, touchable);
    }

    public void setWidgets(Actor... actors) {
        setWidgets(Arrays.asList(actors));
    }

    public void setWidgets(Iterable<Actor> actors) {
        clearChildren();
        this.widgetBounds.clear();
        this.scissors.clear();
        this.handleBounds.clear();
        this.splits.clear();
        for (Actor actor : actors) {
            super.addActor(actor);
            this.widgetBounds.add(new Rectangle());
            this.scissors.add(new Rectangle());
        }
        float currentSplit = 0.0f;
        float splitAdvance = 1.0f / getChildren().size;
        for (int i = 0; i < getChildren().size - 1; i++) {
            this.handleBounds.add(new Rectangle());
            currentSplit += splitAdvance;
            this.splits.add(currentSplit);
        }
        invalidate();
    }

    public void setSplit(int handleBarIndex, float split) {
        if (handleBarIndex < 0) {
            throw new IllegalStateException("handleBarIndex can't be < 0");
        }
        if (handleBarIndex >= this.splits.size) {
            throw new IllegalStateException("handleBarIndex can't be >= splits size");
        }
        float minSplit = handleBarIndex == 0 ? 0.0f : this.splits.get(handleBarIndex - 1);
        float maxSplit = handleBarIndex == this.splits.size + (-1) ? 1.0f : this.splits.get(handleBarIndex + 1);
        this.splits.set(handleBarIndex, MathUtils.clamp(split, minSplit, maxSplit));
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group
    public void addActorAfter(Actor actorAfter, Actor actor) {
        throw new UnsupportedOperationException("Use MultiSplitPane#setWidgets");
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group
    public void addActor(Actor actor) {
        throw new UnsupportedOperationException("Use MultiSplitPane#setWidgets");
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group
    public void addActorAt(int index, Actor actor) {
        throw new UnsupportedOperationException("Use MultiSplitPane#setWidgets");
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group
    public void addActorBefore(Actor actorBefore, Actor actor) {
        throw new UnsupportedOperationException("Use MultiSplitPane#setWidgets");
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group
    public boolean removeActor(Actor actor) {
        throw new UnsupportedOperationException("Use MultiSplitPane#setWidgets");
    }

    /* loaded from: classes.dex */
    public static class MultiSplitPaneStyle extends VisSplitPane.VisSplitPaneStyle {
        public MultiSplitPaneStyle() {
        }

        public MultiSplitPaneStyle(VisSplitPane.VisSplitPaneStyle style) {
            super(style);
        }

        public MultiSplitPaneStyle(Drawable handle, Drawable handleOver) {
            super(handle, handleOver);
        }
    }
}