package com.badlogic.gdx.utils.viewport;

import com.badlogic.gdx.graphics.Camera;
import com.badlogic.gdx.graphics.OrthographicCamera;
import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.utils.Scaling;

/* loaded from: classes.dex */
public class ExtendViewport extends Viewport {
    private float maxWorldHeight;
    private float maxWorldWidth;
    private float minWorldHeight;
    private float minWorldWidth;

    public ExtendViewport(float minWorldWidth, float minWorldHeight) {
        this(minWorldWidth, minWorldHeight, 0.0f, 0.0f, new OrthographicCamera());
    }

    public ExtendViewport(float minWorldWidth, float minWorldHeight, Camera camera) {
        this(minWorldWidth, minWorldHeight, 0.0f, 0.0f, camera);
    }

    public ExtendViewport(float minWorldWidth, float minWorldHeight, float maxWorldWidth, float maxWorldHeight) {
        this(minWorldWidth, minWorldHeight, maxWorldWidth, maxWorldHeight, new OrthographicCamera());
    }

    public ExtendViewport(float minWorldWidth, float minWorldHeight, float maxWorldWidth, float maxWorldHeight, Camera camera) {
        this.minWorldWidth = minWorldWidth;
        this.minWorldHeight = minWorldHeight;
        this.maxWorldWidth = maxWorldWidth;
        this.maxWorldHeight = maxWorldHeight;
        setCamera(camera);
    }

    @Override // com.badlogic.gdx.utils.viewport.Viewport
    public void update(int screenWidth, int screenHeight, boolean centerCamera) {
        float worldWidth = this.minWorldWidth;
        float worldHeight = this.minWorldHeight;
        Vector2 scaled = Scaling.fit.apply(worldWidth, worldHeight, screenWidth, screenHeight);
        int viewportWidth = Math.round(scaled.x);
        int viewportHeight = Math.round(scaled.y);
        if (viewportWidth < screenWidth) {
            float toViewportSpace = viewportHeight / worldHeight;
            float toWorldSpace = worldHeight / viewportHeight;
            float lengthen = (screenWidth - viewportWidth) * toWorldSpace;
            float f = this.maxWorldWidth;
            if (f > 0.0f) {
                lengthen = Math.min(lengthen, f - this.minWorldWidth);
            }
            worldWidth += lengthen;
            viewportWidth += Math.round(lengthen * toViewportSpace);
        } else if (viewportHeight < screenHeight) {
            float toViewportSpace2 = viewportWidth / worldWidth;
            float toWorldSpace2 = worldWidth / viewportWidth;
            float lengthen2 = (screenHeight - viewportHeight) * toWorldSpace2;
            float f2 = this.maxWorldHeight;
            if (f2 > 0.0f) {
                lengthen2 = Math.min(lengthen2, f2 - this.minWorldHeight);
            }
            worldHeight += lengthen2;
            viewportHeight += Math.round(lengthen2 * toViewportSpace2);
        }
        setWorldSize(worldWidth, worldHeight);
        setScreenBounds((screenWidth - viewportWidth) / 2, (screenHeight - viewportHeight) / 2, viewportWidth, viewportHeight);
        apply(centerCamera);
    }

    public float getMinWorldWidth() {
        return this.minWorldWidth;
    }

    public void setMinWorldWidth(float minWorldWidth) {
        this.minWorldWidth = minWorldWidth;
    }

    public float getMinWorldHeight() {
        return this.minWorldHeight;
    }

    public void setMinWorldHeight(float minWorldHeight) {
        this.minWorldHeight = minWorldHeight;
    }

    public float getMaxWorldWidth() {
        return this.maxWorldWidth;
    }

    public void setMaxWorldWidth(float maxWorldWidth) {
        this.maxWorldWidth = maxWorldWidth;
    }

    public float getMaxWorldHeight() {
        return this.maxWorldHeight;
    }

    public void setMaxWorldHeight(float maxWorldHeight) {
        this.maxWorldHeight = maxWorldHeight;
    }
}