package com.badlogic.gdx.utils;

/* loaded from: classes.dex */
public class Align {
    public static final int bottom = 4;
    public static final int bottomLeft = 12;
    public static final int bottomRight = 20;
    public static final int center = 1;
    public static final int left = 8;
    public static final int right = 16;
    public static final int top = 2;
    public static final int topLeft = 10;
    public static final int topRight = 18;

    public static final boolean isLeft(int align) {
        return (align & 8) != 0;
    }

    public static final boolean isRight(int align) {
        return (align & 16) != 0;
    }

    public static final boolean isTop(int align) {
        return (align & 2) != 0;
    }

    public static final boolean isBottom(int align) {
        return (align & 4) != 0;
    }

    public static final boolean isCenterVertical(int align) {
        return (align & 2) == 0 && (align & 4) == 0;
    }

    public static final boolean isCenterHorizontal(int align) {
        return (align & 8) == 0 && (align & 16) == 0;
    }

    public static String toString(int align) {
        StringBuilder buffer = new StringBuilder(13);
        if ((align & 2) != 0) {
            buffer.append("top,");
        } else if ((align & 4) != 0) {
            buffer.append("bottom,");
        } else {
            buffer.append("center,");
        }
        if ((align & 8) != 0) {
            buffer.append("left");
        } else if ((align & 16) != 0) {
            buffer.append("right");
        } else {
            buffer.append("center");
        }
        return buffer.toString();
    }
}