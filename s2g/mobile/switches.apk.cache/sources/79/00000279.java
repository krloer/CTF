package com.badlogic.gdx.graphics.glutils;

import com.badlogic.gdx.Gdx;

/* loaded from: classes.dex */
public class HdpiUtils {
    private static HdpiMode mode = HdpiMode.Logical;

    public static void setMode(HdpiMode mode2) {
        mode = mode2;
    }

    public static void glScissor(int x, int y, int width, int height) {
        if (mode == HdpiMode.Logical && (Gdx.graphics.getWidth() != Gdx.graphics.getBackBufferWidth() || Gdx.graphics.getHeight() != Gdx.graphics.getBackBufferHeight())) {
            Gdx.gl.glScissor(toBackBufferX(x), toBackBufferY(y), toBackBufferX(width), toBackBufferY(height));
        } else {
            Gdx.gl.glScissor(x, y, width, height);
        }
    }

    public static void glViewport(int x, int y, int width, int height) {
        if (mode == HdpiMode.Logical && (Gdx.graphics.getWidth() != Gdx.graphics.getBackBufferWidth() || Gdx.graphics.getHeight() != Gdx.graphics.getBackBufferHeight())) {
            Gdx.gl.glViewport(toBackBufferX(x), toBackBufferY(y), toBackBufferX(width), toBackBufferY(height));
        } else {
            Gdx.gl.glViewport(x, y, width, height);
        }
    }

    public static int toLogicalX(int backBufferX) {
        return (int) ((Gdx.graphics.getWidth() * backBufferX) / Gdx.graphics.getBackBufferWidth());
    }

    public static int toLogicalY(int backBufferY) {
        return (int) ((Gdx.graphics.getHeight() * backBufferY) / Gdx.graphics.getBackBufferHeight());
    }

    public static int toBackBufferX(int logicalX) {
        return (int) ((Gdx.graphics.getBackBufferWidth() * logicalX) / Gdx.graphics.getWidth());
    }

    public static int toBackBufferY(int logicalY) {
        return (int) ((Gdx.graphics.getBackBufferHeight() * logicalY) / Gdx.graphics.getHeight());
    }
}