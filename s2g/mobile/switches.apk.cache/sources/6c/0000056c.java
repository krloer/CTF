package com.kotcrab.vis.ui.util.highlight;

import com.badlogic.gdx.graphics.Color;

/* loaded from: classes.dex */
public class Highlight implements Comparable<Highlight> {
    private Color color;
    private int end;
    private int start;

    public Highlight(Color color, int start, int end) {
        if (color == null) {
            throw new IllegalArgumentException("color can't be null");
        }
        if (start >= end) {
            throw new IllegalArgumentException("start can't be >= end: " + start + " >= " + end);
        }
        this.color = color;
        this.start = start;
        this.end = end;
    }

    public Color getColor() {
        return this.color;
    }

    public int getStart() {
        return this.start;
    }

    public int getEnd() {
        return this.end;
    }

    @Override // java.lang.Comparable
    public int compareTo(Highlight o) {
        return getStart() - o.getStart();
    }
}