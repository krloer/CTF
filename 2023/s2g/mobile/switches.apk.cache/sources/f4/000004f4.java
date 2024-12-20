package com.badlogic.gdx.utils.viewport;

import com.badlogic.gdx.graphics.Camera;
import com.badlogic.gdx.utils.Scaling;

/* loaded from: classes.dex */
public class StretchViewport extends ScalingViewport {
    public StretchViewport(float worldWidth, float worldHeight) {
        super(Scaling.stretch, worldWidth, worldHeight);
    }

    public StretchViewport(float worldWidth, float worldHeight, Camera camera) {
        super(Scaling.stretch, worldWidth, worldHeight, camera);
    }
}