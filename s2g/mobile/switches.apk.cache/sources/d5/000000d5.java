package com.badlogic.gdx.backends.android.surfaceview;

import com.badlogic.gdx.backends.android.surfaceview.ResolutionStrategy;

/* loaded from: classes.dex */
public class FixedResolutionStrategy implements ResolutionStrategy {
    private final int height;
    private final int width;

    public FixedResolutionStrategy(int width, int height) {
        this.width = width;
        this.height = height;
    }

    @Override // com.badlogic.gdx.backends.android.surfaceview.ResolutionStrategy
    public ResolutionStrategy.MeasuredDimension calcMeasures(int widthMeasureSpec, int heightMeasureSpec) {
        return new ResolutionStrategy.MeasuredDimension(this.width, this.height);
    }
}