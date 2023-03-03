package com.kotcrab.vis.ui.building.utilities;

import com.badlogic.gdx.scenes.scene2d.ui.Cell;
import com.badlogic.gdx.scenes.scene2d.ui.Table;

/* loaded from: classes.dex */
public class Padding {
    public static final Padding PAD_0 = of(0.0f);
    public static final Padding PAD_2 = of(2.0f);
    public static final Padding PAD_4 = of(4.0f);
    public static final Padding PAD_8 = of(8.0f);
    private final float bottom;
    private final float left;
    private final float right;
    private final float top;

    public Padding(float padding) {
        this(padding, padding, padding, padding);
    }

    public Padding(float horizontal, float vertical) {
        this(vertical, horizontal, vertical, horizontal);
    }

    public Padding(float top, float left, float bottom, float right) {
        this.top = top;
        this.left = left;
        this.bottom = bottom;
        this.right = right;
    }

    public static Padding of(float padding) {
        return new Padding(padding, padding, padding, padding);
    }

    public static Padding of(float horizontal, float vertical) {
        return new Padding(vertical, horizontal, vertical, horizontal);
    }

    public static Padding of(float top, float left, float bottom, float right) {
        return new Padding(top, left, bottom, right);
    }

    public float getTop() {
        return this.top;
    }

    public float getLeft() {
        return this.left;
    }

    public float getBottom() {
        return this.bottom;
    }

    public float getRight() {
        return this.right;
    }

    public Padding add(Padding padding) {
        return new Padding(this.top + padding.getTop(), this.left + padding.getLeft(), this.bottom + padding.getBottom(), this.right + padding.getRight());
    }

    public Padding subtract(Padding padding) {
        return new Padding(this.top - padding.getTop(), this.left - padding.getLeft(), this.bottom - padding.getBottom(), this.right - padding.getRight());
    }

    public Padding reverse() {
        return new Padding(-this.top, -this.left, -this.bottom, -this.right);
    }

    public Table applyPadding(Table table) {
        table.pad(this.top, this.left, this.bottom, this.right);
        return table;
    }

    public Cell<?> applyPadding(Cell<?> cell) {
        cell.pad(this.top, this.left, this.bottom, this.right);
        return cell;
    }

    public Cell<?> applySpacing(Cell<?> cell) {
        cell.space(this.top, this.left, this.bottom, this.right);
        return cell;
    }

    public static Table setPadding(Padding padding, Table table) {
        table.pad(padding.getTop(), padding.getLeft(), padding.getBottom(), padding.getRight());
        return table;
    }

    public static Cell<?> setPadding(Padding padding, Cell<?> cell) {
        return cell.pad(padding.getTop(), padding.getLeft(), padding.getBottom(), padding.getRight());
    }

    public static Cell<?> setSpacing(Padding spacing, Cell<?> cell) {
        return cell.space(spacing.getTop(), spacing.getLeft(), spacing.getBottom(), spacing.getRight());
    }
}