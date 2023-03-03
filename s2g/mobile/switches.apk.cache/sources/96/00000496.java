package com.badlogic.gdx.utils;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.math.FloatCounter;

/* loaded from: classes.dex */
public class PerformanceCounter {
    private static final float nano2seconds = 1.0E-9f;
    public float current;
    private long lastTick;
    public final FloatCounter load;
    public final String name;
    private long startTime;
    public final FloatCounter time;
    public boolean valid;

    public PerformanceCounter(String name) {
        this(name, 5);
    }

    public PerformanceCounter(String name, int windowSize) {
        this.startTime = 0L;
        this.lastTick = 0L;
        this.current = 0.0f;
        this.valid = false;
        this.name = name;
        this.time = new FloatCounter(windowSize);
        this.load = new FloatCounter(1);
    }

    public void tick() {
        long t = TimeUtils.nanoTime();
        long j = this.lastTick;
        if (j > 0) {
            tick(((float) (t - j)) * 1.0E-9f);
        }
        this.lastTick = t;
    }

    public void tick(float delta) {
        if (!this.valid) {
            Gdx.app.error("PerformanceCounter", "Invalid data, check if you called PerformanceCounter#stop()");
            return;
        }
        this.time.put(this.current);
        float currentLoad = delta == 0.0f ? 0.0f : this.current / delta;
        FloatCounter floatCounter = this.load;
        floatCounter.put(delta > 1.0f ? currentLoad : ((1.0f - delta) * floatCounter.latest) + (delta * currentLoad));
        this.current = 0.0f;
        this.valid = false;
    }

    public void start() {
        this.startTime = TimeUtils.nanoTime();
        this.valid = false;
    }

    public void stop() {
        if (this.startTime > 0) {
            this.current += ((float) (TimeUtils.nanoTime() - this.startTime)) * 1.0E-9f;
            this.startTime = 0L;
            this.valid = true;
        }
    }

    public void reset() {
        this.time.reset();
        this.load.reset();
        this.startTime = 0L;
        this.lastTick = 0L;
        this.current = 0.0f;
        this.valid = false;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        return toString(sb).toString();
    }

    public StringBuilder toString(StringBuilder sb) {
        sb.append(this.name).append(": [time: ").append(this.time.value).append(", load: ").append(this.load.value).append("]");
        return sb;
    }
}