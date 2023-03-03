package com.badlogic.gdx.utils.viewport;

import com.badlogic.gdx.graphics.Camera;
import com.badlogic.gdx.graphics.OrthographicCamera;

/* loaded from: classes.dex */
public class ScreenViewport extends Viewport {
    private float unitsPerPixel;

    public ScreenViewport() {
        this(new OrthographicCamera());
    }

    public ScreenViewport(Camera camera) {
        this.unitsPerPixel = 1.0f;
        setCamera(camera);
    }

    @Override // com.badlogic.gdx.utils.viewport.Viewport
    public void update(int screenWidth, int screenHeight, boolean centerCamera) {
        setScreenBounds(0, 0, screenWidth, screenHeight);
        float f = this.unitsPerPixel;
        setWorldSize(screenWidth * f, screenHeight * f);
        apply(centerCamera);
    }

    public float getUnitsPerPixel() {
        return this.unitsPerPixel;
    }

    public void setUnitsPerPixel(float unitsPerPixel) {
        this.unitsPerPixel = unitsPerPixel;
    }
}