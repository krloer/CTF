package com.badlogic.gdx.scenes.scene2d.ui;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.graphics.glutils.ShapeRenderer;
import com.badlogic.gdx.math.Rectangle;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.Touchable;
import com.badlogic.gdx.scenes.scene2d.ui.Value;
import com.badlogic.gdx.scenes.scene2d.utils.Cullable;
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;
import com.badlogic.gdx.scenes.scene2d.utils.Layout;

/* loaded from: classes.dex */
public class Container<T extends Actor> extends WidgetGroup {
    private T actor;
    private int align;
    private Drawable background;
    private boolean clip;
    private float fillX;
    private float fillY;
    private Value maxHeight;
    private Value maxWidth;
    private Value minHeight;
    private Value minWidth;
    private Value padBottom;
    private Value padLeft;
    private Value padRight;
    private Value padTop;
    private Value prefHeight;
    private Value prefWidth;
    private boolean round;

    public Container() {
        this.minWidth = Value.minWidth;
        this.minHeight = Value.minHeight;
        this.prefWidth = Value.prefWidth;
        this.prefHeight = Value.prefHeight;
        this.maxWidth = Value.zero;
        this.maxHeight = Value.zero;
        this.padTop = Value.zero;
        this.padLeft = Value.zero;
        this.padBottom = Value.zero;
        this.padRight = Value.zero;
        this.round = true;
        setTouchable(Touchable.childrenOnly);
        setTransform(false);
    }

    public Container(T actor) {
        this();
        setActor(actor);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
    public void draw(Batch batch, float parentAlpha) {
        validate();
        if (isTransform()) {
            applyTransform(batch, computeTransform());
            drawBackground(batch, parentAlpha, 0.0f, 0.0f);
            if (this.clip) {
                batch.flush();
                float padLeft = this.padLeft.get(this);
                float padBottom = this.padBottom.get(this);
                if (clipBegin(padLeft, padBottom, (getWidth() - padLeft) - this.padRight.get(this), (getHeight() - padBottom) - this.padTop.get(this))) {
                    drawChildren(batch, parentAlpha);
                    batch.flush();
                    clipEnd();
                }
            } else {
                drawChildren(batch, parentAlpha);
            }
            resetTransform(batch);
            return;
        }
        drawBackground(batch, parentAlpha, getX(), getY());
        super.draw(batch, parentAlpha);
    }

    protected void drawBackground(Batch batch, float parentAlpha, float x, float y) {
        if (this.background == null) {
            return;
        }
        Color color = getColor();
        batch.setColor(color.r, color.g, color.b, color.a * parentAlpha);
        this.background.draw(batch, x, y, getWidth(), getHeight());
    }

    public void setBackground(Drawable background) {
        setBackground(background, true);
    }

    public void setBackground(Drawable background, boolean adjustPadding) {
        if (this.background == background) {
            return;
        }
        this.background = background;
        if (adjustPadding) {
            if (background == null) {
                pad(Value.zero);
            } else {
                pad(background.getTopHeight(), background.getLeftWidth(), background.getBottomHeight(), background.getRightWidth());
            }
            invalidate();
        }
    }

    public Container<T> background(Drawable background) {
        setBackground(background);
        return this;
    }

    public Drawable getBackground() {
        return this.background;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public void layout() {
        float width;
        float height;
        if (this.actor == null) {
            return;
        }
        float padLeft = this.padLeft.get(this);
        float padBottom = this.padBottom.get(this);
        float containerWidth = (getWidth() - padLeft) - this.padRight.get(this);
        float containerHeight = (getHeight() - padBottom) - this.padTop.get(this);
        float minWidth = this.minWidth.get(this.actor);
        float minHeight = this.minHeight.get(this.actor);
        float prefWidth = this.prefWidth.get(this.actor);
        float prefHeight = this.prefHeight.get(this.actor);
        float maxWidth = this.maxWidth.get(this.actor);
        float maxHeight = this.maxHeight.get(this.actor);
        float f = this.fillX;
        if (f > 0.0f) {
            width = f * containerWidth;
        } else {
            width = Math.min(prefWidth, containerWidth);
        }
        if (width < minWidth) {
            width = minWidth;
        }
        if (maxWidth > 0.0f && width > maxWidth) {
            width = maxWidth;
        }
        float f2 = this.fillY;
        if (f2 > 0.0f) {
            height = f2 * containerHeight;
        } else {
            height = Math.min(prefHeight, containerHeight);
        }
        if (height < minHeight) {
            height = minHeight;
        }
        if (maxHeight > 0.0f && height > maxHeight) {
            height = maxHeight;
        }
        float x = padLeft;
        int i = this.align;
        if ((i & 16) != 0) {
            x += containerWidth - width;
        } else if ((i & 8) == 0) {
            x += (containerWidth - width) / 2.0f;
        }
        float y = padBottom;
        int i2 = this.align;
        if ((i2 & 2) != 0) {
            y += containerHeight - height;
        } else if ((i2 & 4) == 0) {
            y += (containerHeight - height) / 2.0f;
        }
        if (this.round) {
            x = Math.round(x);
            y = Math.round(y);
            width = Math.round(width);
            height = Math.round(height);
        }
        this.actor.setBounds(x, y, width, height);
        T t = this.actor;
        if (t instanceof Layout) {
            ((Layout) t).validate();
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.utils.Cullable
    public void setCullingArea(Rectangle cullingArea) {
        super.setCullingArea(cullingArea);
        if (this.fillX == 1.0f && this.fillY == 1.0f) {
            T t = this.actor;
            if (t instanceof Cullable) {
                ((Cullable) t).setCullingArea(cullingArea);
            }
        }
    }

    public void setActor(T actor) {
        if (actor == this) {
            throw new IllegalArgumentException("actor cannot be the Container.");
        }
        T t = this.actor;
        if (actor == t) {
            return;
        }
        if (t != null) {
            super.removeActor(t);
        }
        this.actor = actor;
        if (actor != null) {
            super.addActor(actor);
        }
    }

    public T getActor() {
        return this.actor;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group
    @Deprecated
    public void addActor(Actor actor) {
        throw new UnsupportedOperationException("Use Container#setActor.");
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group
    @Deprecated
    public void addActorAt(int index, Actor actor) {
        throw new UnsupportedOperationException("Use Container#setActor.");
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group
    @Deprecated
    public void addActorBefore(Actor actorBefore, Actor actor) {
        throw new UnsupportedOperationException("Use Container#setActor.");
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group
    @Deprecated
    public void addActorAfter(Actor actorAfter, Actor actor) {
        throw new UnsupportedOperationException("Use Container#setActor.");
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group
    public boolean removeActor(Actor actor) {
        if (actor == null) {
            throw new IllegalArgumentException("actor cannot be null.");
        }
        if (actor != this.actor) {
            return false;
        }
        setActor(null);
        return true;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group
    public boolean removeActor(Actor actor, boolean unfocus) {
        if (actor == null) {
            throw new IllegalArgumentException("actor cannot be null.");
        }
        if (actor != this.actor) {
            return false;
        }
        this.actor = null;
        return super.removeActor(actor, unfocus);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group
    public Actor removeActorAt(int index, boolean unfocus) {
        Actor actor = super.removeActorAt(index, unfocus);
        if (actor == this.actor) {
            this.actor = null;
        }
        return actor;
    }

    public Container<T> size(Value size) {
        if (size == null) {
            throw new IllegalArgumentException("size cannot be null.");
        }
        this.minWidth = size;
        this.minHeight = size;
        this.prefWidth = size;
        this.prefHeight = size;
        this.maxWidth = size;
        this.maxHeight = size;
        return this;
    }

    public Container<T> size(Value width, Value height) {
        if (width == null) {
            throw new IllegalArgumentException("width cannot be null.");
        }
        if (height == null) {
            throw new IllegalArgumentException("height cannot be null.");
        }
        this.minWidth = width;
        this.minHeight = height;
        this.prefWidth = width;
        this.prefHeight = height;
        this.maxWidth = width;
        this.maxHeight = height;
        return this;
    }

    public Container<T> size(float size) {
        size(Value.Fixed.valueOf(size));
        return this;
    }

    public Container<T> size(float width, float height) {
        size(Value.Fixed.valueOf(width), Value.Fixed.valueOf(height));
        return this;
    }

    public Container<T> width(Value width) {
        if (width == null) {
            throw new IllegalArgumentException("width cannot be null.");
        }
        this.minWidth = width;
        this.prefWidth = width;
        this.maxWidth = width;
        return this;
    }

    public Container<T> width(float width) {
        width(Value.Fixed.valueOf(width));
        return this;
    }

    public Container<T> height(Value height) {
        if (height == null) {
            throw new IllegalArgumentException("height cannot be null.");
        }
        this.minHeight = height;
        this.prefHeight = height;
        this.maxHeight = height;
        return this;
    }

    public Container<T> height(float height) {
        height(Value.Fixed.valueOf(height));
        return this;
    }

    public Container<T> minSize(Value size) {
        if (size == null) {
            throw new IllegalArgumentException("size cannot be null.");
        }
        this.minWidth = size;
        this.minHeight = size;
        return this;
    }

    public Container<T> minSize(Value width, Value height) {
        if (width == null) {
            throw new IllegalArgumentException("width cannot be null.");
        }
        if (height == null) {
            throw new IllegalArgumentException("height cannot be null.");
        }
        this.minWidth = width;
        this.minHeight = height;
        return this;
    }

    public Container<T> minWidth(Value minWidth) {
        if (minWidth == null) {
            throw new IllegalArgumentException("minWidth cannot be null.");
        }
        this.minWidth = minWidth;
        return this;
    }

    public Container<T> minHeight(Value minHeight) {
        if (minHeight == null) {
            throw new IllegalArgumentException("minHeight cannot be null.");
        }
        this.minHeight = minHeight;
        return this;
    }

    public Container<T> minSize(float size) {
        minSize(Value.Fixed.valueOf(size));
        return this;
    }

    public Container<T> minSize(float width, float height) {
        minSize(Value.Fixed.valueOf(width), Value.Fixed.valueOf(height));
        return this;
    }

    public Container<T> minWidth(float minWidth) {
        this.minWidth = Value.Fixed.valueOf(minWidth);
        return this;
    }

    public Container<T> minHeight(float minHeight) {
        this.minHeight = Value.Fixed.valueOf(minHeight);
        return this;
    }

    public Container<T> prefSize(Value size) {
        if (size == null) {
            throw new IllegalArgumentException("size cannot be null.");
        }
        this.prefWidth = size;
        this.prefHeight = size;
        return this;
    }

    public Container<T> prefSize(Value width, Value height) {
        if (width == null) {
            throw new IllegalArgumentException("width cannot be null.");
        }
        if (height == null) {
            throw new IllegalArgumentException("height cannot be null.");
        }
        this.prefWidth = width;
        this.prefHeight = height;
        return this;
    }

    public Container<T> prefWidth(Value prefWidth) {
        if (prefWidth == null) {
            throw new IllegalArgumentException("prefWidth cannot be null.");
        }
        this.prefWidth = prefWidth;
        return this;
    }

    public Container<T> prefHeight(Value prefHeight) {
        if (prefHeight == null) {
            throw new IllegalArgumentException("prefHeight cannot be null.");
        }
        this.prefHeight = prefHeight;
        return this;
    }

    public Container<T> prefSize(float width, float height) {
        prefSize(Value.Fixed.valueOf(width), Value.Fixed.valueOf(height));
        return this;
    }

    public Container<T> prefSize(float size) {
        prefSize(Value.Fixed.valueOf(size));
        return this;
    }

    public Container<T> prefWidth(float prefWidth) {
        this.prefWidth = Value.Fixed.valueOf(prefWidth);
        return this;
    }

    public Container<T> prefHeight(float prefHeight) {
        this.prefHeight = Value.Fixed.valueOf(prefHeight);
        return this;
    }

    public Container<T> maxSize(Value size) {
        if (size == null) {
            throw new IllegalArgumentException("size cannot be null.");
        }
        this.maxWidth = size;
        this.maxHeight = size;
        return this;
    }

    public Container<T> maxSize(Value width, Value height) {
        if (width == null) {
            throw new IllegalArgumentException("width cannot be null.");
        }
        if (height == null) {
            throw new IllegalArgumentException("height cannot be null.");
        }
        this.maxWidth = width;
        this.maxHeight = height;
        return this;
    }

    public Container<T> maxWidth(Value maxWidth) {
        if (maxWidth == null) {
            throw new IllegalArgumentException("maxWidth cannot be null.");
        }
        this.maxWidth = maxWidth;
        return this;
    }

    public Container<T> maxHeight(Value maxHeight) {
        if (maxHeight == null) {
            throw new IllegalArgumentException("maxHeight cannot be null.");
        }
        this.maxHeight = maxHeight;
        return this;
    }

    public Container<T> maxSize(float size) {
        maxSize(Value.Fixed.valueOf(size));
        return this;
    }

    public Container<T> maxSize(float width, float height) {
        maxSize(Value.Fixed.valueOf(width), Value.Fixed.valueOf(height));
        return this;
    }

    public Container<T> maxWidth(float maxWidth) {
        this.maxWidth = Value.Fixed.valueOf(maxWidth);
        return this;
    }

    public Container<T> maxHeight(float maxHeight) {
        this.maxHeight = Value.Fixed.valueOf(maxHeight);
        return this;
    }

    public Container<T> pad(Value pad) {
        if (pad == null) {
            throw new IllegalArgumentException("pad cannot be null.");
        }
        this.padTop = pad;
        this.padLeft = pad;
        this.padBottom = pad;
        this.padRight = pad;
        return this;
    }

    public Container<T> pad(Value top, Value left, Value bottom, Value right) {
        if (top == null) {
            throw new IllegalArgumentException("top cannot be null.");
        }
        if (left == null) {
            throw new IllegalArgumentException("left cannot be null.");
        }
        if (bottom == null) {
            throw new IllegalArgumentException("bottom cannot be null.");
        }
        if (right == null) {
            throw new IllegalArgumentException("right cannot be null.");
        }
        this.padTop = top;
        this.padLeft = left;
        this.padBottom = bottom;
        this.padRight = right;
        return this;
    }

    public Container<T> padTop(Value padTop) {
        if (padTop == null) {
            throw new IllegalArgumentException("padTop cannot be null.");
        }
        this.padTop = padTop;
        return this;
    }

    public Container<T> padLeft(Value padLeft) {
        if (padLeft == null) {
            throw new IllegalArgumentException("padLeft cannot be null.");
        }
        this.padLeft = padLeft;
        return this;
    }

    public Container<T> padBottom(Value padBottom) {
        if (padBottom == null) {
            throw new IllegalArgumentException("padBottom cannot be null.");
        }
        this.padBottom = padBottom;
        return this;
    }

    public Container<T> padRight(Value padRight) {
        if (padRight == null) {
            throw new IllegalArgumentException("padRight cannot be null.");
        }
        this.padRight = padRight;
        return this;
    }

    public Container<T> pad(float pad) {
        Value value = Value.Fixed.valueOf(pad);
        this.padTop = value;
        this.padLeft = value;
        this.padBottom = value;
        this.padRight = value;
        return this;
    }

    public Container<T> pad(float top, float left, float bottom, float right) {
        this.padTop = Value.Fixed.valueOf(top);
        this.padLeft = Value.Fixed.valueOf(left);
        this.padBottom = Value.Fixed.valueOf(bottom);
        this.padRight = Value.Fixed.valueOf(right);
        return this;
    }

    public Container<T> padTop(float padTop) {
        this.padTop = Value.Fixed.valueOf(padTop);
        return this;
    }

    public Container<T> padLeft(float padLeft) {
        this.padLeft = Value.Fixed.valueOf(padLeft);
        return this;
    }

    public Container<T> padBottom(float padBottom) {
        this.padBottom = Value.Fixed.valueOf(padBottom);
        return this;
    }

    public Container<T> padRight(float padRight) {
        this.padRight = Value.Fixed.valueOf(padRight);
        return this;
    }

    public Container<T> fill() {
        this.fillX = 1.0f;
        this.fillY = 1.0f;
        return this;
    }

    public Container<T> fillX() {
        this.fillX = 1.0f;
        return this;
    }

    public Container<T> fillY() {
        this.fillY = 1.0f;
        return this;
    }

    public Container<T> fill(float x, float y) {
        this.fillX = x;
        this.fillY = y;
        return this;
    }

    public Container<T> fill(boolean x, boolean y) {
        this.fillX = x ? 1.0f : 0.0f;
        this.fillY = y ? 1.0f : 0.0f;
        return this;
    }

    public Container<T> fill(boolean fill) {
        this.fillX = fill ? 1.0f : 0.0f;
        this.fillY = fill ? 1.0f : 0.0f;
        return this;
    }

    public Container<T> align(int align) {
        this.align = align;
        return this;
    }

    public Container<T> center() {
        this.align = 1;
        return this;
    }

    public Container<T> top() {
        this.align |= 2;
        this.align &= -5;
        return this;
    }

    public Container<T> left() {
        this.align |= 8;
        this.align &= -17;
        return this;
    }

    public Container<T> bottom() {
        this.align |= 4;
        this.align &= -3;
        return this;
    }

    public Container<T> right() {
        this.align |= 16;
        this.align &= -9;
        return this;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getMinWidth() {
        return this.minWidth.get(this.actor) + this.padLeft.get(this) + this.padRight.get(this);
    }

    public Value getMinHeightValue() {
        return this.minHeight;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getMinHeight() {
        return this.minHeight.get(this.actor) + this.padTop.get(this) + this.padBottom.get(this);
    }

    public Value getPrefWidthValue() {
        return this.prefWidth;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getPrefWidth() {
        float v = this.prefWidth.get(this.actor);
        Drawable drawable = this.background;
        if (drawable != null) {
            v = Math.max(v, drawable.getMinWidth());
        }
        return Math.max(getMinWidth(), this.padLeft.get(this) + v + this.padRight.get(this));
    }

    public Value getPrefHeightValue() {
        return this.prefHeight;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getPrefHeight() {
        float v = this.prefHeight.get(this.actor);
        Drawable drawable = this.background;
        if (drawable != null) {
            v = Math.max(v, drawable.getMinHeight());
        }
        return Math.max(getMinHeight(), this.padTop.get(this) + v + this.padBottom.get(this));
    }

    public Value getMaxWidthValue() {
        return this.maxWidth;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getMaxWidth() {
        float v = this.maxWidth.get(this.actor);
        return v > 0.0f ? v + this.padLeft.get(this) + this.padRight.get(this) : v;
    }

    public Value getMaxHeightValue() {
        return this.maxHeight;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getMaxHeight() {
        float v = this.maxHeight.get(this.actor);
        return v > 0.0f ? v + this.padTop.get(this) + this.padBottom.get(this) : v;
    }

    public Value getPadTopValue() {
        return this.padTop;
    }

    public float getPadTop() {
        return this.padTop.get(this);
    }

    public Value getPadLeftValue() {
        return this.padLeft;
    }

    public float getPadLeft() {
        return this.padLeft.get(this);
    }

    public Value getPadBottomValue() {
        return this.padBottom;
    }

    public float getPadBottom() {
        return this.padBottom.get(this);
    }

    public Value getPadRightValue() {
        return this.padRight;
    }

    public float getPadRight() {
        return this.padRight.get(this);
    }

    public float getPadX() {
        return this.padLeft.get(this) + this.padRight.get(this);
    }

    public float getPadY() {
        return this.padTop.get(this) + this.padBottom.get(this);
    }

    public float getFillX() {
        return this.fillX;
    }

    public float getFillY() {
        return this.fillY;
    }

    public int getAlign() {
        return this.align;
    }

    public void setRound(boolean round) {
        this.round = round;
    }

    public Container<T> clip() {
        setClip(true);
        return this;
    }

    public Container<T> clip(boolean enabled) {
        setClip(enabled);
        return this;
    }

    public void setClip(boolean enabled) {
        this.clip = enabled;
        setTransform(enabled);
        invalidate();
    }

    public boolean getClip() {
        return this.clip;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
    public Actor hit(float x, float y, boolean touchable) {
        if (this.clip && ((touchable && getTouchable() == Touchable.disabled) || x < 0.0f || x >= getWidth() || y < 0.0f || y >= getHeight())) {
            return null;
        }
        return super.hit(x, y, touchable);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
    public void drawDebug(ShapeRenderer shapes) {
        validate();
        if (isTransform()) {
            applyTransform(shapes, computeTransform());
            if (this.clip) {
                shapes.flush();
                float padLeft = this.padLeft.get(this);
                float padBottom = this.padBottom.get(this);
                boolean draw = this.background == null ? clipBegin(0.0f, 0.0f, getWidth(), getHeight()) : clipBegin(padLeft, padBottom, (getWidth() - padLeft) - this.padRight.get(this), (getHeight() - padBottom) - this.padTop.get(this));
                if (draw) {
                    drawDebugChildren(shapes);
                    clipEnd();
                }
            } else {
                drawDebugChildren(shapes);
            }
            resetTransform(shapes);
            return;
        }
        super.drawDebug(shapes);
    }
}