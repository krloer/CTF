package com.badlogic.gdx.backends.android.surfaceview;

/* loaded from: classes.dex */
public interface ResolutionStrategy {
    MeasuredDimension calcMeasures(int i, int i2);

    /* loaded from: classes.dex */
    public static class MeasuredDimension {
        public final int height;
        public final int width;

        public MeasuredDimension(int width, int height) {
            this.width = width;
            this.height = height;
        }
    }
}