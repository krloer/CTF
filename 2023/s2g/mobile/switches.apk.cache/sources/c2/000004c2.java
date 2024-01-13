package com.badlogic.gdx.utils;

/* loaded from: classes.dex */
public final class TimeUtils {
    private static final long nanosPerMilli = 1000000;

    public static long nanoTime() {
        return System.nanoTime();
    }

    public static long millis() {
        return System.currentTimeMillis();
    }

    public static long nanosToMillis(long nanos) {
        return nanos / nanosPerMilli;
    }

    public static long millisToNanos(long millis) {
        return nanosPerMilli * millis;
    }

    public static long timeSinceNanos(long prevTime) {
        return nanoTime() - prevTime;
    }

    public static long timeSinceMillis(long prevTime) {
        return millis() - prevTime;
    }
}