package com.badlogic.gdx.backends.android.surfaceview;

import android.view.View;
import com.badlogic.gdx.backends.android.surfaceview.ResolutionStrategy;

/* loaded from: classes.dex */
public class RatioResolutionStrategy implements ResolutionStrategy {
    private final float ratio;

    public RatioResolutionStrategy(float ratio) {
        this.ratio = ratio;
    }

    public RatioResolutionStrategy(float width, float height) {
        this.ratio = width / height;
    }

    @Override // com.badlogic.gdx.backends.android.surfaceview.ResolutionStrategy
    public ResolutionStrategy.MeasuredDimension calcMeasures(int widthMeasureSpec, int heightMeasureSpec) {
        int height;
        int width;
        int specWidth = View.MeasureSpec.getSize(widthMeasureSpec);
        int specHeight = View.MeasureSpec.getSize(heightMeasureSpec);
        float desiredRatio = this.ratio;
        float realRatio = specWidth / specHeight;
        if (realRatio < desiredRatio) {
            width = specWidth;
            height = Math.round(width / desiredRatio);
        } else {
            height = specHeight;
            width = Math.round(height * desiredRatio);
        }
        return new ResolutionStrategy.MeasuredDimension(width, height);
    }
}