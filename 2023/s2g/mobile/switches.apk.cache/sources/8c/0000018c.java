package com.badlogic.gdx.graphics.g3d.environment;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.utils.GdxRuntimeException;

/* loaded from: classes.dex */
public class SphericalHarmonics {
    private static final float[] coeff = {0.282095f, 0.488603f, 0.488603f, 0.488603f, 1.092548f, 1.092548f, 1.092548f, 0.315392f, 0.546274f};
    public final float[] data;

    private static final float clamp(float v) {
        if (v < 0.0f) {
            return 0.0f;
        }
        if (v > 1.0f) {
            return 1.0f;
        }
        return v;
    }

    public SphericalHarmonics() {
        this.data = new float[27];
    }

    public SphericalHarmonics(float[] copyFrom) {
        if (copyFrom.length != 27) {
            throw new GdxRuntimeException("Incorrect array size");
        }
        this.data = (float[]) copyFrom.clone();
    }

    public SphericalHarmonics set(float[] values) {
        int i = 0;
        while (true) {
            float[] fArr = this.data;
            if (i < fArr.length) {
                fArr[i] = values[i];
                i++;
            } else {
                return this;
            }
        }
    }

    public SphericalHarmonics set(AmbientCubemap other) {
        return set(other.data);
    }

    public SphericalHarmonics set(Color color) {
        return set(color.r, color.g, color.b);
    }

    public SphericalHarmonics set(float r, float g, float b) {
        int idx = 0;
        while (true) {
            float[] fArr = this.data;
            if (idx < fArr.length) {
                int idx2 = idx + 1;
                fArr[idx] = r;
                int idx3 = idx2 + 1;
                fArr[idx2] = g;
                fArr[idx3] = b;
                idx = idx3 + 1;
            } else {
                return this;
            }
        }
    }
}