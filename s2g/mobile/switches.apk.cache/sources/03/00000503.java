package com.kotcrab.vis.ui.building.utilities;

import com.badlogic.gdx.scenes.scene2d.ui.Cell;

/* loaded from: classes.dex */
public enum Alignment {
    CENTER(1),
    TOP(2),
    BOTTOM(4),
    LEFT(8),
    RIGHT(16),
    TOP_LEFT(10),
    TOP_RIGHT(18),
    BOTTOM_LEFT(12),
    BOTTOM_RIGHT(20);
    
    private final int alignment;

    Alignment(int alignment) {
        this.alignment = alignment;
    }

    public int getAlignment() {
        return this.alignment;
    }

    public void apply(Cell<?> cell) {
        cell.align(this.alignment);
    }

    public boolean isAlignedWithTop() {
        return (this.alignment & 2) != 0;
    }

    public boolean isAlignedWithBottom() {
        return (this.alignment & 4) != 0;
    }

    public boolean isAlignedWithLeft() {
        return (this.alignment & 8) != 0;
    }

    public boolean isAlignedWithRight() {
        return (this.alignment & 16) != 0;
    }

    public boolean isCentered() {
        return this.alignment == 1;
    }

    public static Alignment getByIndex(int index) {
        if (isIndexValid(index)) {
            return values()[index];
        }
        return null;
    }

    public static Alignment getByValidIndex(int index) {
        return values()[index];
    }

    public static boolean isIndexValid(int index) {
        return index >= 0 && index < values().length;
    }

    public static boolean isIndexLast(int index) {
        return index == values().length - 1;
    }
}