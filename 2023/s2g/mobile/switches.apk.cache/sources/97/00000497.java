package com.badlogic.gdx.utils;

/* loaded from: classes.dex */
public class PerformanceCounters {
    private static final float nano2seconds = 1.0E-9f;
    private long lastTick = 0;
    public final Array<PerformanceCounter> counters = new Array<>();

    public PerformanceCounter add(String name, int windowSize) {
        PerformanceCounter result = new PerformanceCounter(name, windowSize);
        this.counters.add(result);
        return result;
    }

    public PerformanceCounter add(String name) {
        PerformanceCounter result = new PerformanceCounter(name);
        this.counters.add(result);
        return result;
    }

    public void tick() {
        long t = TimeUtils.nanoTime();
        long j = this.lastTick;
        if (j > 0) {
            tick(((float) (t - j)) * 1.0E-9f);
        }
        this.lastTick = t;
    }

    public void tick(float deltaTime) {
        for (int i = 0; i < this.counters.size; i++) {
            this.counters.get(i).tick(deltaTime);
        }
    }

    public StringBuilder toString(StringBuilder sb) {
        sb.setLength(0);
        for (int i = 0; i < this.counters.size; i++) {
            if (i != 0) {
                sb.append("; ");
            }
            this.counters.get(i).toString(sb);
        }
        return sb;
    }
}