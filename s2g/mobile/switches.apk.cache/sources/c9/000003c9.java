package com.badlogic.gdx.scenes.scene2d.ui;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.graphics.glutils.ShapeRenderer;
import com.badlogic.gdx.math.Rectangle;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.Touchable;
import com.badlogic.gdx.scenes.scene2d.ui.Label;
import com.badlogic.gdx.scenes.scene2d.ui.Value;
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;
import com.badlogic.gdx.scenes.scene2d.utils.Layout;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.Pool;
import com.badlogic.gdx.utils.Pools;
import java.util.Arrays;

/* loaded from: classes.dex */
public class Table extends WidgetGroup {
    private static float[] columnWeightedWidth;
    private static float[] rowWeightedHeight;
    int align;
    Drawable background;
    private final Cell cellDefaults;
    private final Array<Cell> cells;
    private boolean clip;
    private final Array<Cell> columnDefaults;
    private float[] columnMinWidth;
    private float[] columnPrefWidth;
    private float[] columnWidth;
    private int columns;
    Debug debug;
    Array<DebugRect> debugRects;
    private float[] expandHeight;
    private float[] expandWidth;
    private boolean implicitEndRow;
    Value padBottom;
    Value padLeft;
    Value padRight;
    Value padTop;
    boolean round;
    private Cell rowDefaults;
    private float[] rowHeight;
    private float[] rowMinHeight;
    private float[] rowPrefHeight;
    private int rows;
    private boolean sizeInvalid;
    private Skin skin;
    private float tableMinHeight;
    private float tableMinWidth;
    private float tablePrefHeight;
    private float tablePrefWidth;
    public static Color debugTableColor = new Color(0.0f, 0.0f, 1.0f, 1.0f);
    public static Color debugCellColor = new Color(1.0f, 0.0f, 0.0f, 1.0f);
    public static Color debugActorColor = new Color(0.0f, 1.0f, 0.0f, 1.0f);
    static final Pool<Cell> cellPool = new Pool<Cell>() { // from class: com.badlogic.gdx.scenes.scene2d.ui.Table.1
        /* JADX INFO: Access modifiers changed from: protected */
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // com.badlogic.gdx.utils.Pool
        public Cell newObject() {
            return new Cell();
        }
    };
    public static Value backgroundTop = new Value() { // from class: com.badlogic.gdx.scenes.scene2d.ui.Table.2
        @Override // com.badlogic.gdx.scenes.scene2d.ui.Value
        public float get(Actor context) {
            Drawable background = ((Table) context).background;
            if (background == null) {
                return 0.0f;
            }
            return background.getTopHeight();
        }
    };
    public static Value backgroundLeft = new Value() { // from class: com.badlogic.gdx.scenes.scene2d.ui.Table.3
        @Override // com.badlogic.gdx.scenes.scene2d.ui.Value
        public float get(Actor context) {
            Drawable background = ((Table) context).background;
            if (background == null) {
                return 0.0f;
            }
            return background.getLeftWidth();
        }
    };
    public static Value backgroundBottom = new Value() { // from class: com.badlogic.gdx.scenes.scene2d.ui.Table.4
        @Override // com.badlogic.gdx.scenes.scene2d.ui.Value
        public float get(Actor context) {
            Drawable background = ((Table) context).background;
            if (background == null) {
                return 0.0f;
            }
            return background.getBottomHeight();
        }
    };
    public static Value backgroundRight = new Value() { // from class: com.badlogic.gdx.scenes.scene2d.ui.Table.5
        @Override // com.badlogic.gdx.scenes.scene2d.ui.Value
        public float get(Actor context) {
            Drawable background = ((Table) context).background;
            if (background == null) {
                return 0.0f;
            }
            return background.getRightWidth();
        }
    };

    /* loaded from: classes.dex */
    public enum Debug {
        none,
        all,
        table,
        cell,
        actor
    }

    /* loaded from: classes.dex */
    public static class DebugRect extends Rectangle {
        static Pool<DebugRect> pool = Pools.get(DebugRect.class);
        Color color;
    }

    public Table() {
        this(null);
    }

    public Table(Skin skin) {
        this.cells = new Array<>(4);
        this.columnDefaults = new Array<>(2);
        this.sizeInvalid = true;
        this.padTop = backgroundTop;
        this.padLeft = backgroundLeft;
        this.padBottom = backgroundBottom;
        this.padRight = backgroundRight;
        this.align = 1;
        this.debug = Debug.none;
        this.round = true;
        this.skin = skin;
        this.cellDefaults = obtainCell();
        setTransform(false);
        setTouchable(Touchable.childrenOnly);
    }

    private Cell obtainCell() {
        Cell cell = cellPool.obtain();
        cell.setTable(this);
        return cell;
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

    /* JADX INFO: Access modifiers changed from: protected */
    public void drawBackground(Batch batch, float parentAlpha, float x, float y) {
        if (this.background == null) {
            return;
        }
        Color color = getColor();
        batch.setColor(color.r, color.g, color.b, color.a * parentAlpha);
        this.background.draw(batch, x, y, getWidth(), getHeight());
    }

    public void setBackground(String drawableName) {
        Skin skin = this.skin;
        if (skin == null) {
            throw new IllegalStateException("Table must have a skin set to use this method.");
        }
        setBackground(skin.getDrawable(drawableName));
    }

    public void setBackground(Drawable background) {
        if (this.background == background) {
            return;
        }
        float padTopOld = getPadTop();
        float padLeftOld = getPadLeft();
        float padBottomOld = getPadBottom();
        float padRightOld = getPadRight();
        this.background = background;
        float padTopNew = getPadTop();
        float padLeftNew = getPadLeft();
        float padBottomNew = getPadBottom();
        float padRightNew = getPadRight();
        if (padTopOld + padBottomOld != padTopNew + padBottomNew || padLeftOld + padRightOld != padLeftNew + padRightNew) {
            invalidateHierarchy();
        } else if (padTopOld != padTopNew || padLeftOld != padLeftNew || padBottomOld != padBottomNew || padRightOld != padRightNew) {
            invalidate();
        }
    }

    public Table background(Drawable background) {
        setBackground(background);
        return this;
    }

    public Table background(String drawableName) {
        setBackground(drawableName);
        return this;
    }

    public Drawable getBackground() {
        return this.background;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
    public Actor hit(float x, float y, boolean touchable) {
        if (this.clip && ((touchable && getTouchable() == Touchable.disabled) || x < 0.0f || x >= getWidth() || y < 0.0f || y >= getHeight())) {
            return null;
        }
        return super.hit(x, y, touchable);
    }

    public Table clip() {
        setClip(true);
        return this;
    }

    public Table clip(boolean enabled) {
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

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public void invalidate() {
        this.sizeInvalid = true;
        super.invalidate();
    }

    public <T extends Actor> Cell<T> add(T actor) {
        Cell<T> cell = obtainCell();
        cell.actor = actor;
        if (this.implicitEndRow) {
            this.implicitEndRow = false;
            this.rows--;
            this.cells.peek().endRow = false;
        }
        int cellCount = this.cells.size;
        if (cellCount > 0) {
            Cell lastCell = this.cells.peek();
            if (!lastCell.endRow) {
                cell.column = lastCell.column + lastCell.colspan.intValue();
                cell.row = lastCell.row;
            } else {
                cell.column = 0;
                cell.row = lastCell.row + 1;
            }
            if (cell.row > 0) {
                Object[] cells = this.cells.items;
                int i = cellCount - 1;
                loop0: while (true) {
                    if (i < 0) {
                        break;
                    }
                    Cell other = (Cell) cells[i];
                    int column = other.column;
                    int nn = other.colspan.intValue() + column;
                    while (column < nn) {
                        if (column != cell.column) {
                            column++;
                        } else {
                            cell.cellAboveIndex = i;
                            break loop0;
                        }
                    }
                    i--;
                }
            }
        } else {
            cell.column = 0;
            cell.row = 0;
        }
        this.cells.add(cell);
        cell.set(this.cellDefaults);
        if (cell.column < this.columnDefaults.size) {
            cell.merge(this.columnDefaults.get(cell.column));
        }
        cell.merge(this.rowDefaults);
        if (actor != null) {
            addActor(actor);
        }
        return cell;
    }

    public Table add(Actor... actors) {
        for (Actor actor : actors) {
            add((Table) actor);
        }
        return this;
    }

    public Cell<Label> add(CharSequence text) {
        Skin skin = this.skin;
        if (skin == null) {
            throw new IllegalStateException("Table must have a skin set to use this method.");
        }
        return add((Table) new Label(text, skin));
    }

    public Cell<Label> add(CharSequence text, String labelStyleName) {
        Skin skin = this.skin;
        if (skin == null) {
            throw new IllegalStateException("Table must have a skin set to use this method.");
        }
        return add((Table) new Label(text, (Label.LabelStyle) skin.get(labelStyleName, Label.LabelStyle.class)));
    }

    public Cell<Label> add(CharSequence text, String fontName, Color color) {
        Skin skin = this.skin;
        if (skin == null) {
            throw new IllegalStateException("Table must have a skin set to use this method.");
        }
        return add((Table) new Label(text, new Label.LabelStyle(skin.getFont(fontName), color)));
    }

    public Cell<Label> add(CharSequence text, String fontName, String colorName) {
        Skin skin = this.skin;
        if (skin == null) {
            throw new IllegalStateException("Table must have a skin set to use this method.");
        }
        return add((Table) new Label(text, new Label.LabelStyle(skin.getFont(fontName), this.skin.getColor(colorName))));
    }

    public Cell add() {
        return add((Table) null);
    }

    public Cell<Stack> stack(Actor... actors) {
        Stack stack = new Stack();
        if (actors != null) {
            for (Actor actor : actors) {
                stack.addActor(actor);
            }
        }
        return add((Table) stack);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group
    public boolean removeActor(Actor actor) {
        return removeActor(actor, true);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group
    public boolean removeActor(Actor actor, boolean unfocus) {
        if (super.removeActor(actor, unfocus)) {
            Cell cell = getCell(actor);
            if (cell != null) {
                cell.actor = null;
                return true;
            }
            return true;
        }
        return false;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group
    public Actor removeActorAt(int index, boolean unfocus) {
        Actor actor = super.removeActorAt(index, unfocus);
        Cell cell = getCell(actor);
        if (cell != null) {
            cell.actor = null;
        }
        return actor;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group
    public void clearChildren(boolean unfocus) {
        Object[] cells = this.cells.items;
        for (int i = this.cells.size - 1; i >= 0; i--) {
            Cell cell = (Cell) cells[i];
            Actor actor = cell.actor;
            if (actor != null) {
                actor.remove();
            }
        }
        cellPool.freeAll(this.cells);
        this.cells.clear();
        this.rows = 0;
        this.columns = 0;
        Cell cell2 = this.rowDefaults;
        if (cell2 != null) {
            cellPool.free(cell2);
        }
        this.rowDefaults = null;
        this.implicitEndRow = false;
        super.clearChildren(unfocus);
    }

    public void reset() {
        clearChildren();
        this.padTop = backgroundTop;
        this.padLeft = backgroundLeft;
        this.padBottom = backgroundBottom;
        this.padRight = backgroundRight;
        this.align = 1;
        debug(Debug.none);
        this.cellDefaults.reset();
        int n = this.columnDefaults.size;
        for (int i = 0; i < n; i++) {
            Cell columnCell = this.columnDefaults.get(i);
            if (columnCell != null) {
                cellPool.free(columnCell);
            }
        }
        this.columnDefaults.clear();
    }

    public Cell row() {
        if (this.cells.size > 0) {
            if (!this.implicitEndRow) {
                if (this.cells.peek().endRow) {
                    return this.rowDefaults;
                }
                endRow();
            }
            invalidate();
        }
        this.implicitEndRow = false;
        Cell cell = this.rowDefaults;
        if (cell != null) {
            cellPool.free(cell);
        }
        this.rowDefaults = obtainCell();
        this.rowDefaults.clear();
        return this.rowDefaults;
    }

    private void endRow() {
        Object[] cells = this.cells.items;
        int rowColumns = 0;
        for (int i = this.cells.size - 1; i >= 0; i--) {
            Cell cell = (Cell) cells[i];
            if (cell.endRow) {
                break;
            }
            rowColumns += cell.colspan.intValue();
        }
        int i2 = this.columns;
        this.columns = Math.max(i2, rowColumns);
        this.rows++;
        this.cells.peek().endRow = true;
    }

    public Cell columnDefaults(int column) {
        Cell cell = this.columnDefaults.size > column ? this.columnDefaults.get(column) : null;
        if (cell == null) {
            cell = obtainCell();
            cell.clear();
            if (column >= this.columnDefaults.size) {
                for (int i = this.columnDefaults.size; i < column; i++) {
                    this.columnDefaults.add(null);
                }
                this.columnDefaults.add(cell);
            } else {
                this.columnDefaults.set(column, cell);
            }
        }
        return cell;
    }

    public <T extends Actor> Cell<T> getCell(T actor) {
        if (actor == null) {
            throw new IllegalArgumentException("actor cannot be null.");
        }
        Cell[] cells = this.cells.items;
        int n = this.cells.size;
        for (int i = 0; i < n; i++) {
            Cell c = cells[i];
            if (c.actor == actor) {
                return c;
            }
        }
        return null;
    }

    public Array<Cell> getCells() {
        return this.cells;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getPrefWidth() {
        if (this.sizeInvalid) {
            computeSize();
        }
        float width = this.tablePrefWidth;
        Drawable drawable = this.background;
        return drawable != null ? Math.max(width, drawable.getMinWidth()) : width;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getPrefHeight() {
        if (this.sizeInvalid) {
            computeSize();
        }
        float height = this.tablePrefHeight;
        Drawable drawable = this.background;
        return drawable != null ? Math.max(height, drawable.getMinHeight()) : height;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getMinWidth() {
        if (this.sizeInvalid) {
            computeSize();
        }
        return this.tableMinWidth;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getMinHeight() {
        if (this.sizeInvalid) {
            computeSize();
        }
        return this.tableMinHeight;
    }

    public Cell defaults() {
        return this.cellDefaults;
    }

    public Table pad(Value pad) {
        if (pad == null) {
            throw new IllegalArgumentException("pad cannot be null.");
        }
        this.padTop = pad;
        this.padLeft = pad;
        this.padBottom = pad;
        this.padRight = pad;
        this.sizeInvalid = true;
        return this;
    }

    public Table pad(Value top, Value left, Value bottom, Value right) {
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
        this.sizeInvalid = true;
        return this;
    }

    public Table padTop(Value padTop) {
        if (padTop == null) {
            throw new IllegalArgumentException("padTop cannot be null.");
        }
        this.padTop = padTop;
        this.sizeInvalid = true;
        return this;
    }

    public Table padLeft(Value padLeft) {
        if (padLeft == null) {
            throw new IllegalArgumentException("padLeft cannot be null.");
        }
        this.padLeft = padLeft;
        this.sizeInvalid = true;
        return this;
    }

    public Table padBottom(Value padBottom) {
        if (padBottom == null) {
            throw new IllegalArgumentException("padBottom cannot be null.");
        }
        this.padBottom = padBottom;
        this.sizeInvalid = true;
        return this;
    }

    public Table padRight(Value padRight) {
        if (padRight == null) {
            throw new IllegalArgumentException("padRight cannot be null.");
        }
        this.padRight = padRight;
        this.sizeInvalid = true;
        return this;
    }

    public Table pad(float pad) {
        pad(Value.Fixed.valueOf(pad));
        return this;
    }

    public Table pad(float top, float left, float bottom, float right) {
        this.padTop = Value.Fixed.valueOf(top);
        this.padLeft = Value.Fixed.valueOf(left);
        this.padBottom = Value.Fixed.valueOf(bottom);
        this.padRight = Value.Fixed.valueOf(right);
        this.sizeInvalid = true;
        return this;
    }

    public Table padTop(float padTop) {
        this.padTop = Value.Fixed.valueOf(padTop);
        this.sizeInvalid = true;
        return this;
    }

    public Table padLeft(float padLeft) {
        this.padLeft = Value.Fixed.valueOf(padLeft);
        this.sizeInvalid = true;
        return this;
    }

    public Table padBottom(float padBottom) {
        this.padBottom = Value.Fixed.valueOf(padBottom);
        this.sizeInvalid = true;
        return this;
    }

    public Table padRight(float padRight) {
        this.padRight = Value.Fixed.valueOf(padRight);
        this.sizeInvalid = true;
        return this;
    }

    public Table align(int align) {
        this.align = align;
        return this;
    }

    public Table center() {
        this.align = 1;
        return this;
    }

    public Table top() {
        this.align |= 2;
        this.align &= -5;
        return this;
    }

    public Table left() {
        this.align |= 8;
        this.align &= -17;
        return this;
    }

    public Table bottom() {
        this.align |= 4;
        this.align &= -3;
        return this;
    }

    public Table right() {
        this.align |= 16;
        this.align &= -9;
        return this;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Actor
    public void setDebug(boolean enabled) {
        debug(enabled ? Debug.all : Debug.none);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Actor
    public Table debug() {
        super.debug();
        return this;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group
    public Table debugAll() {
        super.debugAll();
        return this;
    }

    public Table debugTable() {
        super.setDebug(true);
        if (this.debug != Debug.table) {
            this.debug = Debug.table;
            invalidate();
        }
        return this;
    }

    public Table debugCell() {
        super.setDebug(true);
        if (this.debug != Debug.cell) {
            this.debug = Debug.cell;
            invalidate();
        }
        return this;
    }

    public Table debugActor() {
        super.setDebug(true);
        if (this.debug != Debug.actor) {
            this.debug = Debug.actor;
            invalidate();
        }
        return this;
    }

    public Table debug(Debug debug) {
        super.setDebug(debug != Debug.none);
        if (this.debug != debug) {
            this.debug = debug;
            if (debug == Debug.none) {
                clearDebugRects();
            } else {
                invalidate();
            }
        }
        return this;
    }

    public Debug getTableDebug() {
        return this.debug;
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

    public int getAlign() {
        return this.align;
    }

    public int getRow(float y) {
        int n = this.cells.size;
        if (n == 0) {
            return -1;
        }
        float y2 = y + getPadTop();
        Object[] cells = this.cells.items;
        int i = 0;
        int row = 0;
        while (i < n) {
            int i2 = i + 1;
            Cell c = (Cell) cells[i];
            if (c.actorY + c.computedPadTop < y2) {
                return row;
            }
            if (c.endRow) {
                row++;
            }
            i = i2;
        }
        return -1;
    }

    public void setSkin(Skin skin) {
        this.skin = skin;
    }

    public void setRound(boolean round) {
        this.round = round;
    }

    public int getRows() {
        return this.rows;
    }

    public int getColumns() {
        return this.columns;
    }

    public float getRowHeight(int rowIndex) {
        float[] fArr = this.rowHeight;
        if (fArr == null) {
            return 0.0f;
        }
        return fArr[rowIndex];
    }

    public float getRowMinHeight(int rowIndex) {
        if (this.sizeInvalid) {
            computeSize();
        }
        return this.rowMinHeight[rowIndex];
    }

    public float getRowPrefHeight(int rowIndex) {
        if (this.sizeInvalid) {
            computeSize();
        }
        return this.rowPrefHeight[rowIndex];
    }

    public float getColumnWidth(int columnIndex) {
        float[] fArr = this.columnWidth;
        if (fArr == null) {
            return 0.0f;
        }
        return fArr[columnIndex];
    }

    public float getColumnMinWidth(int columnIndex) {
        if (this.sizeInvalid) {
            computeSize();
        }
        return this.columnMinWidth[columnIndex];
    }

    public float getColumnPrefWidth(int columnIndex) {
        if (this.sizeInvalid) {
            computeSize();
        }
        return this.columnPrefWidth[columnIndex];
    }

    private float[] ensureSize(float[] array, int size) {
        if (array == null || array.length < size) {
            return new float[size];
        }
        Arrays.fill(array, 0, size, 0.0f);
        return array;
    }

    private void computeSize() {
        int cellCount;
        Object[] cells;
        float uniformMinWidth;
        float uniformMinHeight;
        float uniformPrefWidth;
        int nn;
        float f;
        float[] expandWidth;
        this.sizeInvalid = false;
        Object[] cells2 = this.cells.items;
        int cellCount2 = this.cells.size;
        if (cellCount2 > 0 && !cells2[cellCount2 - 1].endRow) {
            endRow();
            this.implicitEndRow = true;
        }
        int columns = this.columns;
        int rows = this.rows;
        float[] columnMinWidth = ensureSize(this.columnMinWidth, columns);
        this.columnMinWidth = columnMinWidth;
        float[] rowMinHeight = ensureSize(this.rowMinHeight, rows);
        this.rowMinHeight = rowMinHeight;
        float[] columnPrefWidth = ensureSize(this.columnPrefWidth, columns);
        this.columnPrefWidth = columnPrefWidth;
        float[] rowPrefHeight = ensureSize(this.rowPrefHeight, rows);
        this.rowPrefHeight = rowPrefHeight;
        float[] columnWidth = ensureSize(this.columnWidth, columns);
        this.columnWidth = columnWidth;
        float[] rowHeight = ensureSize(this.rowHeight, rows);
        this.rowHeight = rowHeight;
        float[] expandWidth2 = ensureSize(this.expandWidth, columns);
        this.expandWidth = expandWidth2;
        float[] expandHeight = ensureSize(this.expandHeight, rows);
        this.expandHeight = expandHeight;
        float spaceRightLast = 0.0f;
        int i = 0;
        while (i < cellCount2) {
            Cell c = cells2[i];
            float[] columnWidth2 = columnWidth;
            int column = c.column;
            float[] rowHeight2 = rowHeight;
            int row = c.row;
            int cellCount3 = cellCount2;
            int colspan = c.colspan.intValue();
            int i2 = i;
            Actor a = c.actor;
            float[] rowMinHeight2 = rowMinHeight;
            if (c.expandY.intValue() != 0 && expandHeight[row] == 0.0f) {
                expandHeight[row] = c.expandY.intValue();
            }
            if (colspan == 1 && c.expandX.intValue() != 0 && expandWidth2[column] == 0.0f) {
                expandWidth2[column] = c.expandX.intValue();
            }
            float[] expandHeight2 = expandHeight;
            c.computedPadLeft = c.padLeft.get(a) + (column == 0 ? 0.0f : Math.max(0.0f, c.spaceLeft.get(a) - spaceRightLast));
            c.computedPadTop = c.padTop.get(a);
            if (c.cellAboveIndex == -1) {
                expandWidth = expandWidth2;
            } else {
                Cell above = cells2[c.cellAboveIndex];
                expandWidth = expandWidth2;
                c.computedPadTop += Math.max(0.0f, c.spaceTop.get(a) - above.spaceBottom.get(a));
            }
            float spaceRight = c.spaceRight.get(a);
            c.computedPadRight = c.padRight.get(a) + (column + colspan == columns ? 0.0f : spaceRight);
            c.computedPadBottom = c.padBottom.get(a) + (row == rows + (-1) ? 0.0f : c.spaceBottom.get(a));
            float prefWidth = c.prefWidth.get(a);
            float prefHeight = c.prefHeight.get(a);
            float minWidth = c.minWidth.get(a);
            float minHeight = c.minHeight.get(a);
            int rows2 = rows;
            float maxWidth = c.maxWidth.get(a);
            int columns2 = columns;
            float maxHeight = c.maxHeight.get(a);
            if (prefWidth < minWidth) {
                prefWidth = minWidth;
            }
            if (prefHeight < minHeight) {
                prefHeight = minHeight;
            }
            if (maxWidth > 0.0f && prefWidth > maxWidth) {
                prefWidth = maxWidth;
            }
            if (maxHeight > 0.0f && prefHeight > maxHeight) {
                prefHeight = maxHeight;
            }
            if (this.round) {
                minWidth = (float) Math.ceil(minWidth);
                minHeight = (float) Math.ceil(minHeight);
                prefWidth = (float) Math.ceil(prefWidth);
                prefHeight = (float) Math.ceil(prefHeight);
            }
            if (colspan == 1) {
                float hpadding = c.computedPadLeft + c.computedPadRight;
                columnPrefWidth[column] = Math.max(columnPrefWidth[column], prefWidth + hpadding);
                columnMinWidth[column] = Math.max(columnMinWidth[column], minWidth + hpadding);
            }
            float vpadding = c.computedPadTop + c.computedPadBottom;
            rowPrefHeight[row] = Math.max(rowPrefHeight[row], prefHeight + vpadding);
            rowMinHeight2[row] = Math.max(rowMinHeight2[row], minHeight + vpadding);
            i = i2 + 1;
            columnWidth = columnWidth2;
            rowHeight = rowHeight2;
            cellCount2 = cellCount3;
            rowMinHeight = rowMinHeight2;
            expandHeight = expandHeight2;
            spaceRightLast = spaceRight;
            expandWidth2 = expandWidth;
            rows = rows2;
            columns = columns2;
        }
        int cellCount4 = cellCount2;
        int columns3 = columns;
        int rows3 = rows;
        float[] rowMinHeight3 = rowMinHeight;
        float[] expandWidth3 = expandWidth2;
        float uniformMinWidth2 = 0.0f;
        float uniformMinHeight2 = 0.0f;
        float uniformPrefWidth2 = 0.0f;
        float uniformPrefHeight = 0.0f;
        int i3 = 0;
        while (true) {
            cellCount = cellCount4;
            if (i3 >= cellCount) {
                break;
            }
            Cell c2 = cells2[i3];
            int column2 = c2.column;
            int expandX = c2.expandX.intValue();
            if (expandX != 0) {
                int nn2 = c2.colspan.intValue() + column2;
                int ii = column2;
                while (true) {
                    if (ii < nn2) {
                        if (expandWidth3[ii] != 0.0f) {
                            break;
                        }
                        ii++;
                    } else {
                        int ii2 = column2;
                        while (ii2 < nn2) {
                            expandWidth3[ii2] = expandX;
                            ii2++;
                            nn2 = nn2;
                        }
                    }
                }
            }
            if (c2.uniformX == Boolean.TRUE && c2.colspan.intValue() == 1) {
                float hpadding2 = c2.computedPadLeft + c2.computedPadRight;
                uniformMinWidth2 = Math.max(uniformMinWidth2, columnMinWidth[column2] - hpadding2);
                uniformPrefWidth2 = Math.max(uniformPrefWidth2, columnPrefWidth[column2] - hpadding2);
            }
            if (c2.uniformY == Boolean.TRUE) {
                float vpadding2 = c2.computedPadTop + c2.computedPadBottom;
                uniformMinHeight2 = Math.max(uniformMinHeight2, rowMinHeight3[c2.row] - vpadding2);
                uniformPrefHeight = Math.max(uniformPrefHeight, rowPrefHeight[c2.row] - vpadding2);
            }
            i3++;
            cellCount4 = cellCount;
        }
        if (uniformPrefWidth2 > 0.0f || uniformPrefHeight > 0.0f) {
            for (int i4 = 0; i4 < cellCount; i4++) {
                Cell c3 = cells2[i4];
                if (uniformPrefWidth2 > 0.0f && c3.uniformX == Boolean.TRUE && c3.colspan.intValue() == 1) {
                    float hpadding3 = c3.computedPadLeft + c3.computedPadRight;
                    columnMinWidth[c3.column] = uniformMinWidth2 + hpadding3;
                    columnPrefWidth[c3.column] = uniformPrefWidth2 + hpadding3;
                }
                if (uniformPrefHeight > 0.0f && c3.uniformY == Boolean.TRUE) {
                    float vpadding3 = c3.computedPadTop + c3.computedPadBottom;
                    rowMinHeight3[c3.row] = uniformMinHeight2 + vpadding3;
                    rowPrefHeight[c3.row] = uniformPrefHeight + vpadding3;
                }
            }
        }
        int i5 = 0;
        while (i5 < cellCount) {
            Cell c4 = (Cell) cells2[i5];
            int colspan2 = c4.colspan.intValue();
            if (colspan2 == 1) {
                cells = cells2;
                uniformMinWidth = uniformMinWidth2;
                uniformMinHeight = uniformMinHeight2;
                uniformPrefWidth = uniformPrefWidth2;
            } else {
                int column3 = c4.column;
                Actor a2 = c4.actor;
                float minWidth2 = c4.minWidth.get(a2);
                cells = cells2;
                float prefWidth2 = c4.prefWidth.get(a2);
                uniformMinWidth = uniformMinWidth2;
                float maxWidth2 = c4.maxWidth.get(a2);
                if (prefWidth2 < minWidth2) {
                    prefWidth2 = minWidth2;
                }
                if (maxWidth2 > 0.0f && prefWidth2 > maxWidth2) {
                    prefWidth2 = maxWidth2;
                }
                if (!this.round) {
                    uniformMinHeight = uniformMinHeight2;
                } else {
                    uniformMinHeight = uniformMinHeight2;
                    minWidth2 = (float) Math.ceil(minWidth2);
                    prefWidth2 = (float) Math.ceil(prefWidth2);
                }
                float spannedMinWidth = -(c4.computedPadLeft + c4.computedPadRight);
                float spannedMinWidth2 = spannedMinWidth;
                int nn3 = column3 + colspan2;
                float totalExpandWidth = spannedMinWidth;
                float totalExpandWidth2 = 0.0f;
                for (int ii3 = column3; ii3 < nn3; ii3++) {
                    spannedMinWidth2 += columnMinWidth[ii3];
                    totalExpandWidth += columnPrefWidth[ii3];
                    totalExpandWidth2 += expandWidth3[ii3];
                }
                float extraMinWidth = Math.max(0.0f, minWidth2 - spannedMinWidth2);
                uniformPrefWidth = uniformPrefWidth2;
                float uniformPrefWidth3 = prefWidth2 - totalExpandWidth;
                float extraPrefWidth = Math.max(0.0f, uniformPrefWidth3);
                int nn4 = column3 + colspan2;
                int ii4 = column3;
                while (ii4 < nn4) {
                    if (totalExpandWidth2 == 0.0f) {
                        nn = nn4;
                        f = 1.0f / colspan2;
                    } else {
                        nn = nn4;
                        f = expandWidth3[ii4] / totalExpandWidth2;
                    }
                    float ratio = f;
                    columnMinWidth[ii4] = columnMinWidth[ii4] + (extraMinWidth * ratio);
                    columnPrefWidth[ii4] = columnPrefWidth[ii4] + (extraPrefWidth * ratio);
                    ii4++;
                    nn4 = nn;
                }
            }
            i5++;
            uniformPrefWidth2 = uniformPrefWidth;
            cells2 = cells;
            uniformMinWidth2 = uniformMinWidth;
            uniformMinHeight2 = uniformMinHeight;
        }
        float hpadding4 = this.padLeft.get(this) + this.padRight.get(this);
        float vpadding4 = this.padTop.get(this) + this.padBottom.get(this);
        this.tableMinWidth = hpadding4;
        this.tablePrefWidth = hpadding4;
        int i6 = 0;
        while (true) {
            int columns4 = columns3;
            if (i6 >= columns4) {
                break;
            }
            this.tableMinWidth += columnMinWidth[i6];
            this.tablePrefWidth += columnPrefWidth[i6];
            i6++;
            columns3 = columns4;
        }
        this.tableMinHeight = vpadding4;
        this.tablePrefHeight = vpadding4;
        int i7 = 0;
        while (true) {
            int rows4 = rows3;
            if (i7 >= rows4) {
                this.tablePrefWidth = Math.max(this.tableMinWidth, this.tablePrefWidth);
                this.tablePrefHeight = Math.max(this.tableMinHeight, this.tablePrefHeight);
                return;
            }
            this.tableMinHeight += rowMinHeight3[i7];
            this.tablePrefHeight += Math.max(rowMinHeight3[i7], rowPrefHeight[i7]);
            i7++;
            rows3 = rows4;
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public void layout() {
        float padTop;
        float[] columnWeightedWidth2;
        float[] rowWeightedHeight2;
        float padLeft;
        int columns;
        int rows;
        int cellCount;
        float totalExpand;
        float[] columnWidth;
        float[] rowHeight;
        int columns2;
        if (this.sizeInvalid) {
            computeSize();
        }
        float layoutWidth = getWidth();
        float layoutHeight = getHeight();
        int columns3 = this.columns;
        int rows2 = this.rows;
        float[] columnWidth2 = this.columnWidth;
        float[] rowHeight2 = this.rowHeight;
        float padLeft2 = this.padLeft.get(this);
        float hpadding = this.padRight.get(this) + padLeft2;
        float padTop2 = this.padTop.get(this);
        float vpadding = this.padBottom.get(this) + padTop2;
        float f = this.tablePrefWidth;
        float f2 = this.tableMinWidth;
        float totalGrowWidth = f - f2;
        if (totalGrowWidth != 0.0f) {
            float extraWidth = Math.min(totalGrowWidth, Math.max(0.0f, layoutWidth - f2));
            float[] columnWeightedWidth3 = ensureSize(columnWeightedWidth, columns3);
            columnWeightedWidth = columnWeightedWidth3;
            float[] columnMinWidth = this.columnMinWidth;
            float[] columnPrefWidth = this.columnPrefWidth;
            padTop = padTop2;
            for (int i = 0; i < columns3; i++) {
                float growWidth = columnPrefWidth[i] - columnMinWidth[i];
                float growRatio = growWidth / totalGrowWidth;
                columnWeightedWidth3[i] = columnMinWidth[i] + (extraWidth * growRatio);
            }
            columnWeightedWidth2 = columnWeightedWidth3;
        } else {
            columnWeightedWidth2 = this.columnMinWidth;
            padTop = padTop2;
        }
        float totalGrowHeight = this.tablePrefHeight - this.tableMinHeight;
        if (totalGrowHeight != 0.0f) {
            rowWeightedHeight2 = ensureSize(rowWeightedHeight, rows2);
            rowWeightedHeight = rowWeightedHeight2;
            float extraHeight = Math.min(totalGrowHeight, Math.max(0.0f, layoutHeight - this.tableMinHeight));
            float[] rowMinHeight = this.rowMinHeight;
            float[] rowPrefHeight = this.rowPrefHeight;
            padLeft = padLeft2;
            for (int i2 = 0; i2 < rows2; i2++) {
                float growHeight = rowPrefHeight[i2] - rowMinHeight[i2];
                float growRatio2 = growHeight / totalGrowHeight;
                rowWeightedHeight2[i2] = rowMinHeight[i2] + (extraHeight * growRatio2);
            }
        } else {
            rowWeightedHeight2 = this.rowMinHeight;
            padLeft = padLeft2;
        }
        Object[] cells = this.cells.items;
        int cellCount2 = this.cells.size;
        int i3 = 0;
        while (i3 < cellCount2) {
            Cell c = (Cell) cells[i3];
            float totalGrowHeight2 = totalGrowHeight;
            int column = c.column;
            Object[] cells2 = cells;
            int row = c.row;
            int cellCount3 = cellCount2;
            Actor a = c.actor;
            float layoutHeight2 = layoutHeight;
            int colspan = c.colspan.intValue();
            float vpadding2 = vpadding;
            int nn = column + colspan;
            int rows3 = rows2;
            float spannedWeightedWidth = layoutWidth;
            float layoutWidth2 = 0.0f;
            for (int rows4 = column; rows4 < nn; rows4++) {
                layoutWidth2 += columnWeightedWidth2[rows4];
            }
            float weightedHeight = rowWeightedHeight2[row];
            float prefWidth = c.prefWidth.get(a);
            float[] rowWeightedHeight3 = rowWeightedHeight2;
            float prefHeight = c.prefHeight.get(a);
            float[] columnWeightedWidth4 = columnWeightedWidth2;
            float minWidth = c.minWidth.get(a);
            float hpadding2 = hpadding;
            float minHeight = c.minHeight.get(a);
            int columns4 = columns3;
            float maxWidth = c.maxWidth.get(a);
            float maxHeight = c.maxHeight.get(a);
            if (prefWidth < minWidth) {
                prefWidth = minWidth;
            }
            if (prefHeight < minHeight) {
                prefHeight = minHeight;
            }
            if (maxWidth > 0.0f && prefWidth > maxWidth) {
                prefWidth = maxWidth;
            }
            if (maxHeight > 0.0f && prefHeight > maxHeight) {
                prefHeight = maxHeight;
            }
            c.actorWidth = Math.min((layoutWidth2 - c.computedPadLeft) - c.computedPadRight, prefWidth);
            c.actorHeight = Math.min((weightedHeight - c.computedPadTop) - c.computedPadBottom, prefHeight);
            if (colspan == 1) {
                columnWidth2[column] = Math.max(columnWidth2[column], layoutWidth2);
            }
            rowHeight2[row] = Math.max(rowHeight2[row], weightedHeight);
            i3++;
            totalGrowHeight = totalGrowHeight2;
            cells = cells2;
            cellCount2 = cellCount3;
            layoutWidth = spannedWeightedWidth;
            layoutHeight = layoutHeight2;
            rowWeightedHeight2 = rowWeightedHeight3;
            vpadding = vpadding2;
            rows2 = rows3;
            columnWeightedWidth2 = columnWeightedWidth4;
            hpadding = hpadding2;
            columns3 = columns4;
        }
        float layoutWidth3 = layoutWidth;
        float layoutHeight3 = layoutHeight;
        int columns5 = columns3;
        int rows5 = rows2;
        Object[] cells3 = cells;
        float hpadding3 = hpadding;
        float vpadding3 = vpadding;
        int cellCount4 = cellCount2;
        float[] columnWeightedWidth5 = columnWeightedWidth2;
        float[] expandWidth = this.expandWidth;
        float[] expandHeight = this.expandHeight;
        float totalExpand2 = 0.0f;
        int i4 = 0;
        while (true) {
            columns = columns5;
            if (i4 >= columns) {
                break;
            }
            totalExpand2 += expandWidth[i4];
            i4++;
            columns5 = columns;
        }
        if (totalExpand2 > 0.0f) {
            float extra = layoutWidth3 - hpadding3;
            for (int i5 = 0; i5 < columns; i5++) {
                extra -= columnWidth2[i5];
            }
            if (extra > 0.0f) {
                float used = 0.0f;
                int lastIndex = 0;
                for (int i6 = 0; i6 < columns; i6++) {
                    if (expandWidth[i6] != 0.0f) {
                        float amount = (expandWidth[i6] * extra) / totalExpand2;
                        columnWidth2[i6] = columnWidth2[i6] + amount;
                        used += amount;
                        lastIndex = i6;
                    }
                }
                columnWidth2[lastIndex] = columnWidth2[lastIndex] + (extra - used);
            }
        }
        float totalExpand3 = 0.0f;
        int i7 = 0;
        while (true) {
            rows = rows5;
            if (i7 >= rows) {
                break;
            }
            totalExpand3 += expandHeight[i7];
            i7++;
            rows5 = rows;
        }
        if (totalExpand3 > 0.0f) {
            float extra2 = layoutHeight3 - vpadding3;
            for (int i8 = 0; i8 < rows; i8++) {
                extra2 -= rowHeight2[i8];
            }
            if (extra2 > 0.0f) {
                float used2 = 0.0f;
                int lastIndex2 = 0;
                for (int i9 = 0; i9 < rows; i9++) {
                    if (expandHeight[i9] != 0.0f) {
                        float amount2 = (expandHeight[i9] * extra2) / totalExpand3;
                        rowHeight2[i9] = rowHeight2[i9] + amount2;
                        used2 += amount2;
                        lastIndex2 = i9;
                    }
                }
                rowHeight2[lastIndex2] = rowHeight2[lastIndex2] + (extra2 - used2);
            }
        }
        int i10 = 0;
        while (true) {
            cellCount = cellCount4;
            if (i10 >= cellCount) {
                break;
            }
            Cell c2 = (Cell) cells3[i10];
            int colspan2 = c2.colspan.intValue();
            if (colspan2 != 1) {
                float extraWidth2 = 0.0f;
                int column2 = c2.column;
                int nn2 = column2 + colspan2;
                while (column2 < nn2) {
                    extraWidth2 += columnWeightedWidth5[column2] - columnWidth2[column2];
                    column2++;
                }
                float extraWidth3 = (extraWidth2 - Math.max(0.0f, c2.computedPadLeft + c2.computedPadRight)) / colspan2;
                if (extraWidth3 > 0.0f) {
                    int column3 = c2.column;
                    int nn3 = column3 + colspan2;
                    while (column3 < nn3) {
                        columnWidth2[column3] = columnWidth2[column3] + extraWidth3;
                        column3++;
                    }
                }
            }
            i10++;
            cellCount4 = cellCount;
        }
        float tableWidth = hpadding3;
        float tableHeight = vpadding3;
        for (int i11 = 0; i11 < columns; i11++) {
            tableWidth += columnWidth2[i11];
        }
        for (int i12 = 0; i12 < rows; i12++) {
            tableHeight += rowHeight2[i12];
        }
        int i13 = this.align;
        float x = padLeft;
        if ((i13 & 16) != 0) {
            x += layoutWidth3 - tableWidth;
        } else if ((i13 & 8) == 0) {
            x += (layoutWidth3 - tableWidth) / 2.0f;
        }
        float y = padTop;
        if ((i13 & 4) != 0) {
            y += layoutHeight3 - tableHeight;
        } else if ((i13 & 2) == 0) {
            y += (layoutHeight3 - tableHeight) / 2.0f;
        }
        float currentX = x;
        float currentY = y;
        int align = 0;
        float currentY2 = currentY;
        while (align < cellCount) {
            Cell c3 = (Cell) cells3[align];
            float spannedCellWidth = 0.0f;
            float[] expandWidth2 = expandWidth;
            int column4 = c3.column;
            float[] expandHeight2 = expandHeight;
            int nn4 = c3.colspan.intValue() + column4;
            while (column4 < nn4) {
                spannedCellWidth += columnWidth2[column4];
                column4++;
            }
            float spannedCellWidth2 = spannedCellWidth - (c3.computedPadLeft + c3.computedPadRight);
            float currentX2 = currentX + c3.computedPadLeft;
            float fillX = c3.fillX.floatValue();
            float fillY = c3.fillY.floatValue();
            if (fillX > 0.0f) {
                totalExpand = totalExpand3;
                float totalExpand4 = spannedCellWidth2 * fillX;
                columnWidth = columnWidth2;
                c3.actorWidth = Math.max(totalExpand4, c3.minWidth.get(c3.actor));
                float maxWidth2 = c3.maxWidth.get(c3.actor);
                if (maxWidth2 > 0.0f) {
                    c3.actorWidth = Math.min(c3.actorWidth, maxWidth2);
                }
            } else {
                totalExpand = totalExpand3;
                columnWidth = columnWidth2;
            }
            if (fillY > 0.0f) {
                c3.actorHeight = Math.max(((rowHeight2[c3.row] * fillY) - c3.computedPadTop) - c3.computedPadBottom, c3.minHeight.get(c3.actor));
                float maxHeight2 = c3.maxHeight.get(c3.actor);
                if (maxHeight2 > 0.0f) {
                    c3.actorHeight = Math.min(c3.actorHeight, maxHeight2);
                }
            }
            int align2 = c3.align.intValue();
            if ((align2 & 8) != 0) {
                c3.actorX = currentX2;
            } else if ((align2 & 16) != 0) {
                c3.actorX = (currentX2 + spannedCellWidth2) - c3.actorWidth;
            } else {
                c3.actorX = ((spannedCellWidth2 - c3.actorWidth) / 2.0f) + currentX2;
            }
            if ((align2 & 2) != 0) {
                c3.actorY = c3.computedPadTop;
            } else if ((align2 & 4) != 0) {
                c3.actorY = (rowHeight2[c3.row] - c3.actorHeight) - c3.computedPadBottom;
            } else {
                c3.actorY = (((rowHeight2[c3.row] - c3.actorHeight) + c3.computedPadTop) - c3.computedPadBottom) / 2.0f;
            }
            c3.actorY = ((layoutHeight3 - currentY2) - c3.actorY) - c3.actorHeight;
            if (!this.round) {
                rowHeight = rowHeight2;
            } else {
                rowHeight = rowHeight2;
                c3.actorWidth = (float) Math.ceil(c3.actorWidth);
                c3.actorHeight = (float) Math.ceil(c3.actorHeight);
                c3.actorX = (float) Math.floor(c3.actorX);
                c3.actorY = (float) Math.floor(c3.actorY);
            }
            if (c3.actor != null) {
                columns2 = columns;
                c3.actor.setBounds(c3.actorX, c3.actorY, c3.actorWidth, c3.actorHeight);
            } else {
                columns2 = columns;
            }
            if (c3.endRow) {
                float currentX3 = x;
                currentY2 += rowHeight[c3.row];
                currentX = currentX3;
            } else {
                float currentX4 = c3.computedPadRight;
                currentX = currentX2 + spannedCellWidth2 + currentX4;
            }
            align++;
            rowHeight2 = rowHeight;
            expandWidth = expandWidth2;
            expandHeight = expandHeight2;
            totalExpand3 = totalExpand;
            columnWidth2 = columnWidth;
            columns = columns2;
        }
        Array<Actor> childrenArray = getChildren();
        Object[] children = (Actor[]) childrenArray.items;
        int n = childrenArray.size;
        for (int i14 = 0; i14 < n; i14++) {
            Object child = children[i14];
            if (child instanceof Layout) {
                ((Layout) child).validate();
            }
        }
        if (this.debug != Debug.none) {
            addDebugRects(x, y, tableWidth - hpadding3, tableHeight - vpadding3);
        }
    }

    private void addDebugRects(float currentX, float currentY, float width, float height) {
        clearDebugRects();
        if (this.debug == Debug.table || this.debug == Debug.all) {
            addDebugRect(0.0f, 0.0f, getWidth(), getHeight(), debugTableColor);
            addDebugRect(currentX, getHeight() - currentY, width, -height, debugTableColor);
        }
        int n = this.cells.size;
        float currentX2 = currentX;
        float currentY2 = currentY;
        for (int i = 0; i < n; i++) {
            Cell c = this.cells.get(i);
            if (this.debug == Debug.actor || this.debug == Debug.all) {
                addDebugRect(c.actorX, c.actorY, c.actorWidth, c.actorHeight, debugActorColor);
            }
            float spannedCellWidth = 0.0f;
            int column = c.column;
            int nn = c.colspan.intValue() + column;
            while (column < nn) {
                spannedCellWidth += this.columnWidth[column];
                column++;
            }
            float spannedCellWidth2 = spannedCellWidth - (c.computedPadLeft + c.computedPadRight);
            float spannedCellWidth3 = c.computedPadLeft;
            float currentX3 = currentX2 + spannedCellWidth3;
            if (this.debug == Debug.cell || this.debug == Debug.all) {
                float h = (this.rowHeight[c.row] - c.computedPadTop) - c.computedPadBottom;
                float y = currentY2 + c.computedPadTop;
                addDebugRect(currentX3, getHeight() - y, spannedCellWidth2, -h, debugCellColor);
            }
            if (c.endRow) {
                currentY2 += this.rowHeight[c.row];
                currentX2 = currentX;
            } else {
                currentX2 = currentX3 + c.computedPadRight + spannedCellWidth2;
            }
        }
    }

    private void clearDebugRects() {
        if (this.debugRects == null) {
            this.debugRects = new Array<>();
        }
        DebugRect.pool.freeAll(this.debugRects);
        this.debugRects.clear();
    }

    private void addDebugRect(float x, float y, float w, float h, Color color) {
        DebugRect rect = DebugRect.pool.obtain();
        rect.color = color;
        rect.set(x, y, w, h);
        this.debugRects.add(rect);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
    public void drawDebug(ShapeRenderer shapes) {
        if (isTransform()) {
            applyTransform(shapes, computeTransform());
            drawDebugRects(shapes);
            if (this.clip) {
                shapes.flush();
                float x = 0.0f;
                float y = 0.0f;
                float width = getWidth();
                float height = getHeight();
                if (this.background != null) {
                    x = this.padLeft.get(this);
                    y = this.padBottom.get(this);
                    width -= this.padRight.get(this) + x;
                    height -= this.padTop.get(this) + y;
                }
                if (clipBegin(x, y, width, height)) {
                    drawDebugChildren(shapes);
                    clipEnd();
                }
            } else {
                drawDebugChildren(shapes);
            }
            resetTransform(shapes);
            return;
        }
        drawDebugRects(shapes);
        super.drawDebug(shapes);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.badlogic.gdx.scenes.scene2d.Actor
    public void drawDebugBounds(ShapeRenderer shapes) {
    }

    private void drawDebugRects(ShapeRenderer shapes) {
        if (this.debugRects == null || !getDebug()) {
            return;
        }
        shapes.set(ShapeRenderer.ShapeType.Line);
        if (getStage() != null) {
            shapes.setColor(getStage().getDebugColor());
        }
        float x = 0.0f;
        float y = 0.0f;
        if (!isTransform()) {
            x = getX();
            y = getY();
        }
        int n = this.debugRects.size;
        for (int i = 0; i < n; i++) {
            DebugRect debugRect = this.debugRects.get(i);
            shapes.setColor(debugRect.color);
            shapes.rect(debugRect.x + x, debugRect.y + y, debugRect.width, debugRect.height);
        }
    }

    public Skin getSkin() {
        return this.skin;
    }
}