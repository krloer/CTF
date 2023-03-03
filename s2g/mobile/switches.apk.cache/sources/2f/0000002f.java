package com.badlogic.gdx;

/* loaded from: classes.dex */
public abstract class AbstractGraphics implements Graphics {
    @Override // com.badlogic.gdx.Graphics
    public float getRawDeltaTime() {
        return getDeltaTime();
    }

    @Override // com.badlogic.gdx.Graphics
    public float getDensity() {
        return getPpiX() / 160.0f;
    }

    @Override // com.badlogic.gdx.Graphics
    public float getBackBufferScale() {
        return getBackBufferWidth() / getWidth();
    }
}