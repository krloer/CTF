package com.badlogic.gdx.graphics;

import com.badlogic.gdx.Application;
import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.utils.TimeUtils;
import kotlin.jvm.internal.IntCompanionObject;

/* loaded from: classes.dex */
public class FPSLogger {
    int bound;
    long startTime;

    public FPSLogger() {
        this(IntCompanionObject.MAX_VALUE);
    }

    public FPSLogger(int bound) {
        this.bound = bound;
        this.startTime = TimeUtils.nanoTime();
    }

    public void log() {
        int fps;
        long nanoTime = TimeUtils.nanoTime();
        if (nanoTime - this.startTime > 1000000000 && (fps = Gdx.graphics.getFramesPerSecond()) < this.bound) {
            Application application = Gdx.app;
            application.log("FPSLogger", "fps: " + fps);
            this.startTime = nanoTime;
        }
    }
}