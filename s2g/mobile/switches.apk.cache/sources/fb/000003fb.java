package com.badlogic.gdx.scenes.scene2d.ui;

import com.badlogic.gdx.graphics.glutils.ShapeRenderer;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.Touchable;
import com.badlogic.gdx.scenes.scene2d.utils.Layout;
import com.badlogic.gdx.utils.FloatArray;
import com.badlogic.gdx.utils.SnapshotArray;

/* loaded from: classes.dex */
public class VerticalGroup extends WidgetGroup {
    private int columnAlign;
    private FloatArray columnSizes;
    private boolean expand;
    private float fill;
    private float lastPrefWidth;
    private float padBottom;
    private float padLeft;
    private float padRight;
    private float padTop;
    private float prefHeight;
    private float prefWidth;
    private boolean reverse;
    private float space;
    private boolean wrap;
    private float wrapSpace;
    private boolean sizeInvalid = true;
    private int align = 2;
    private boolean round = true;

    public VerticalGroup() {
        setTouchable(Touchable.childrenOnly);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public void invalidate() {
        super.invalidate();
        this.sizeInvalid = true;
    }

    private void computeSize() {
        float height;
        float width;
        int n;
        float space;
        this.sizeInvalid = false;
        SnapshotArray<Actor> children = getChildren();
        int n2 = children.size;
        this.prefWidth = 0.0f;
        if (!this.wrap) {
            this.prefHeight = this.padTop + this.padBottom + (this.space * (n2 - 1));
            for (int i = 0; i < n2; i++) {
                Actor child = children.get(i);
                if (!(child instanceof Layout)) {
                    this.prefWidth = Math.max(this.prefWidth, child.getWidth());
                    this.prefHeight += child.getHeight();
                } else {
                    Layout layout = (Layout) child;
                    this.prefWidth = Math.max(this.prefWidth, layout.getPrefWidth());
                    this.prefHeight += layout.getPrefHeight();
                }
            }
        } else {
            this.prefHeight = 0.0f;
            FloatArray floatArray = this.columnSizes;
            if (floatArray == null) {
                this.columnSizes = new FloatArray();
            } else {
                floatArray.clear();
            }
            FloatArray columnSizes = this.columnSizes;
            float space2 = this.space;
            float wrapSpace = this.wrapSpace;
            float pad = this.padTop + this.padBottom;
            float groupHeight = getHeight() - pad;
            float x = 0.0f;
            float y = 0.0f;
            float columnWidth = 0.0f;
            int i2 = 0;
            int incr = 1;
            if (this.reverse) {
                i2 = n2 - 1;
                n2 = -1;
                incr = -1;
            }
            while (i2 != n2) {
                Actor child2 = children.get(i2);
                if (child2 instanceof Layout) {
                    Layout layout2 = (Layout) child2;
                    float width2 = layout2.getPrefWidth();
                    height = layout2.getPrefHeight();
                    if (height > groupHeight) {
                        height = Math.max(groupHeight, layout2.getMinHeight());
                    }
                    width = width2;
                } else {
                    float width3 = child2.getWidth();
                    height = child2.getHeight();
                    width = width3;
                }
                float incrY = height + (y > 0.0f ? space2 : 0.0f);
                if (y + incrY <= groupHeight || y <= 0.0f) {
                    n = n2;
                    space = space2;
                } else {
                    columnSizes.add(y);
                    columnSizes.add(columnWidth);
                    n = n2;
                    space = space2;
                    float space3 = y + pad;
                    this.prefHeight = Math.max(this.prefHeight, space3);
                    if (x > 0.0f) {
                        x += wrapSpace;
                    }
                    x += columnWidth;
                    columnWidth = 0.0f;
                    y = 0.0f;
                    incrY = height;
                }
                y += incrY;
                columnWidth = Math.max(columnWidth, width);
                i2 += incr;
                n2 = n;
                space2 = space;
            }
            columnSizes.add(y);
            columnSizes.add(columnWidth);
            this.prefHeight = Math.max(this.prefHeight, y + pad);
            if (x > 0.0f) {
                x += wrapSpace;
            }
            this.prefWidth = Math.max(this.prefWidth, x + columnWidth);
        }
        this.prefWidth += this.padLeft + this.padRight;
        if (this.round) {
            this.prefWidth = Math.round(this.prefWidth);
            this.prefHeight = Math.round(this.prefHeight);
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public void layout() {
        float startX;
        float width;
        float height;
        float padLeft;
        boolean round;
        int align;
        float space;
        float fill;
        if (this.sizeInvalid) {
            computeSize();
        }
        if (this.wrap) {
            layoutWrapped();
            return;
        }
        boolean round2 = this.round;
        int align2 = this.align;
        float space2 = this.space;
        float padLeft2 = this.padLeft;
        float fill2 = this.fill;
        float columnWidth = ((this.expand ? getWidth() : this.prefWidth) - padLeft2) - this.padRight;
        float y = (this.prefHeight - this.padTop) + space2;
        if ((align2 & 2) != 0) {
            y += getHeight() - this.prefHeight;
        } else if ((align2 & 4) == 0) {
            y += (getHeight() - this.prefHeight) / 2.0f;
        }
        if ((align2 & 8) != 0) {
            startX = padLeft2;
        } else if ((align2 & 16) != 0) {
            startX = (getWidth() - this.padRight) - columnWidth;
        } else {
            float startX2 = getWidth();
            startX = ((((startX2 - padLeft2) - this.padRight) - columnWidth) / 2.0f) + padLeft2;
        }
        int align3 = this.columnAlign;
        SnapshotArray<Actor> children = getChildren();
        int i = 0;
        int n = children.size;
        int incr = 1;
        if (this.reverse) {
            i = n - 1;
            n = -1;
            incr = -1;
        }
        while (i != n) {
            Actor child = children.get(i);
            Layout layout = null;
            if (child instanceof Layout) {
                layout = (Layout) child;
                width = layout.getPrefWidth();
                height = layout.getPrefHeight();
            } else {
                width = child.getWidth();
                height = child.getHeight();
            }
            if (fill2 > 0.0f) {
                width = columnWidth * fill2;
            }
            if (layout == null) {
                padLeft = padLeft2;
            } else {
                padLeft = padLeft2;
                width = Math.max(width, layout.getMinWidth());
                float maxWidth = layout.getMaxWidth();
                if (maxWidth > 0.0f && width > maxWidth) {
                    width = maxWidth;
                }
            }
            float x = startX;
            if ((align3 & 16) != 0) {
                x += columnWidth - width;
            } else if ((align3 & 8) == 0) {
                x += (columnWidth - width) / 2.0f;
            }
            y -= height + space2;
            if (round2) {
                round = round2;
                align = align3;
                space = space2;
                fill = fill2;
                child.setBounds(Math.round(x), Math.round(y), Math.round(width), Math.round(height));
            } else {
                round = round2;
                align = align3;
                space = space2;
                fill = fill2;
                child.setBounds(x, y, width, height);
            }
            if (layout != null) {
                layout.validate();
            }
            i += incr;
            round2 = round;
            padLeft2 = padLeft;
            align3 = align;
            space2 = space;
            fill2 = fill;
        }
    }

    private void layoutWrapped() {
        float width;
        float width2;
        int align;
        boolean round;
        float space;
        float fill;
        VerticalGroup verticalGroup = this;
        float prefWidth = getPrefWidth();
        if (prefWidth != verticalGroup.lastPrefWidth) {
            verticalGroup.lastPrefWidth = prefWidth;
            invalidateHierarchy();
        }
        int align2 = verticalGroup.align;
        boolean round2 = verticalGroup.round;
        float space2 = verticalGroup.space;
        float padLeft = verticalGroup.padLeft;
        float fill2 = verticalGroup.fill;
        float wrapSpace = verticalGroup.wrapSpace;
        float maxHeight = (verticalGroup.prefHeight - verticalGroup.padTop) - verticalGroup.padBottom;
        float columnX = padLeft;
        float groupHeight = getHeight();
        float yStart = (verticalGroup.prefHeight - verticalGroup.padTop) + space2;
        if ((align2 & 16) != 0) {
            columnX += getWidth() - prefWidth;
        } else if ((align2 & 8) == 0) {
            columnX += (getWidth() - prefWidth) / 2.0f;
        }
        if ((align2 & 2) != 0) {
            yStart += groupHeight - verticalGroup.prefHeight;
        } else if ((align2 & 4) == 0) {
            yStart += (groupHeight - verticalGroup.prefHeight) / 2.0f;
        }
        float groupHeight2 = groupHeight - verticalGroup.padTop;
        int align3 = verticalGroup.columnAlign;
        FloatArray columnSizes = verticalGroup.columnSizes;
        SnapshotArray<Actor> children = getChildren();
        int i = 0;
        int n = children.size;
        int incr = 1;
        if (verticalGroup.reverse) {
            i = n - 1;
            n = -1;
            incr = -1;
        }
        float f = columnX;
        int r = 0;
        int i2 = i;
        float columnWidth = 0.0f;
        float y = 0.0f;
        float columnX2 = f;
        while (i2 != n) {
            int n2 = n;
            Actor child = children.get(i2);
            Layout layout = null;
            SnapshotArray<Actor> children2 = children;
            if (child instanceof Layout) {
                layout = (Layout) child;
                float width3 = layout.getPrefWidth();
                float height = layout.getPrefHeight();
                if (height > groupHeight2) {
                    width = width3;
                    float width4 = layout.getMinHeight();
                    height = Math.max(groupHeight2, width4);
                } else {
                    width = width3;
                }
                width2 = height;
            } else {
                float width5 = child.getWidth();
                width = width5;
                width2 = child.getHeight();
            }
            float groupHeight3 = groupHeight2;
            if ((y - width2) - space2 < verticalGroup.padBottom || r == 0) {
                int r2 = Math.min(r, columnSizes.size - 2);
                float y2 = yStart;
                if ((align3 & 4) != 0) {
                    y = y2 - (maxHeight - columnSizes.get(r2));
                } else if ((align3 & 2) != 0) {
                    y = y2;
                } else {
                    y = y2 - ((maxHeight - columnSizes.get(r2)) / 2.0f);
                }
                if (r2 > 0) {
                    columnX2 = columnX2 + wrapSpace + columnWidth;
                }
                float columnWidth2 = columnSizes.get(r2 + 1);
                r = r2 + 2;
                columnWidth = columnWidth2;
            }
            if (fill2 > 0.0f) {
                width = columnWidth * fill2;
            }
            float width6 = width;
            if (layout != null) {
                width6 = Math.max(width6, layout.getMinWidth());
                float maxWidth = layout.getMaxWidth();
                if (maxWidth > 0.0f && width6 > maxWidth) {
                    width6 = maxWidth;
                }
            }
            float x = columnX2;
            if ((align3 & 16) != 0) {
                x += columnWidth - width6;
            } else if ((align3 & 8) == 0) {
                x += (columnWidth - width6) / 2.0f;
            }
            y -= width2 + space2;
            if (round2) {
                align = align3;
                round = round2;
                space = space2;
                fill = fill2;
                child.setBounds(Math.round(x), Math.round(y), Math.round(width6), Math.round(width2));
            } else {
                align = align3;
                round = round2;
                space = space2;
                fill = fill2;
                child.setBounds(x, y, width6, width2);
            }
            if (layout != null) {
                layout.validate();
            }
            i2 += incr;
            verticalGroup = this;
            n = n2;
            children = children2;
            align3 = align;
            round2 = round;
            groupHeight2 = groupHeight3;
            space2 = space;
            fill2 = fill;
        }
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
        if (this.wrap) {
            return 0.0f;
        }
        if (this.sizeInvalid) {
            computeSize();
        }
        return this.prefHeight;
    }

    public void setRound(boolean round) {
        this.round = round;
    }

    public VerticalGroup reverse() {
        this.reverse = true;
        return this;
    }

    public VerticalGroup reverse(boolean reverse) {
        this.reverse = reverse;
        return this;
    }

    public boolean getReverse() {
        return this.reverse;
    }

    public VerticalGroup space(float space) {
        this.space = space;
        return this;
    }

    public float getSpace() {
        return this.space;
    }

    public VerticalGroup wrapSpace(float wrapSpace) {
        this.wrapSpace = wrapSpace;
        return this;
    }

    public float getWrapSpace() {
        return this.wrapSpace;
    }

    public VerticalGroup pad(float pad) {
        this.padTop = pad;
        this.padLeft = pad;
        this.padBottom = pad;
        this.padRight = pad;
        return this;
    }

    public VerticalGroup pad(float top, float left, float bottom, float right) {
        this.padTop = top;
        this.padLeft = left;
        this.padBottom = bottom;
        this.padRight = right;
        return this;
    }

    public VerticalGroup padTop(float padTop) {
        this.padTop = padTop;
        return this;
    }

    public VerticalGroup padLeft(float padLeft) {
        this.padLeft = padLeft;
        return this;
    }

    public VerticalGroup padBottom(float padBottom) {
        this.padBottom = padBottom;
        return this;
    }

    public VerticalGroup padRight(float padRight) {
        this.padRight = padRight;
        return this;
    }

    public float getPadTop() {
        return this.padTop;
    }

    public float getPadLeft() {
        return this.padLeft;
    }

    public float getPadBottom() {
        return this.padBottom;
    }

    public float getPadRight() {
        return this.padRight;
    }

    public VerticalGroup align(int align) {
        this.align = align;
        return this;
    }

    public VerticalGroup center() {
        this.align = 1;
        return this;
    }

    public VerticalGroup top() {
        this.align |= 2;
        this.align &= -5;
        return this;
    }

    public VerticalGroup left() {
        this.align |= 8;
        this.align &= -17;
        return this;
    }

    public VerticalGroup bottom() {
        this.align |= 4;
        this.align &= -3;
        return this;
    }

    public VerticalGroup right() {
        this.align |= 16;
        this.align &= -9;
        return this;
    }

    public int getAlign() {
        return this.align;
    }

    public VerticalGroup fill() {
        this.fill = 1.0f;
        return this;
    }

    public VerticalGroup fill(float fill) {
        this.fill = fill;
        return this;
    }

    public float getFill() {
        return this.fill;
    }

    public VerticalGroup expand() {
        this.expand = true;
        return this;
    }

    public VerticalGroup expand(boolean expand) {
        this.expand = expand;
        return this;
    }

    public boolean getExpand() {
        return this.expand;
    }

    public VerticalGroup grow() {
        this.expand = true;
        this.fill = 1.0f;
        return this;
    }

    public VerticalGroup wrap() {
        this.wrap = true;
        return this;
    }

    public VerticalGroup wrap(boolean wrap) {
        this.wrap = wrap;
        return this;
    }

    public boolean getWrap() {
        return this.wrap;
    }

    public VerticalGroup columnAlign(int columnAlign) {
        this.columnAlign = columnAlign;
        return this;
    }

    public VerticalGroup columnCenter() {
        this.columnAlign = 1;
        return this;
    }

    public VerticalGroup columnTop() {
        this.columnAlign |= 2;
        this.columnAlign &= -5;
        return this;
    }

    public VerticalGroup columnLeft() {
        this.columnAlign |= 8;
        this.columnAlign &= -17;
        return this;
    }

    public VerticalGroup columnBottom() {
        this.columnAlign |= 4;
        this.columnAlign &= -3;
        return this;
    }

    public VerticalGroup columnRight() {
        this.columnAlign |= 16;
        this.columnAlign &= -9;
        return this;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.badlogic.gdx.scenes.scene2d.Actor
    public void drawDebugBounds(ShapeRenderer shapes) {
        super.drawDebugBounds(shapes);
        if (getDebug()) {
            shapes.set(ShapeRenderer.ShapeType.Line);
            if (getStage() != null) {
                shapes.setColor(getStage().getDebugColor());
            }
            shapes.rect(getX() + this.padLeft, getY() + this.padBottom, getOriginX(), getOriginY(), (getWidth() - this.padLeft) - this.padRight, (getHeight() - this.padBottom) - this.padTop, getScaleX(), getScaleY(), getRotation());
        }
    }
}