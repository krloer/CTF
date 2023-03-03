package com.badlogic.gdx.graphics.g3d.environment;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.math.Vector3;
import com.badlogic.gdx.utils.GdxRuntimeException;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class AmbientCubemap {
    private static final int NUM_VALUES = 18;
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

    public AmbientCubemap() {
        this.data = new float[18];
    }

    public AmbientCubemap(float[] copyFrom) {
        if (copyFrom.length != 18) {
            throw new GdxRuntimeException("Incorrect array size");
        }
        this.data = new float[copyFrom.length];
        float[] fArr = this.data;
        System.arraycopy(copyFrom, 0, fArr, 0, fArr.length);
    }

    public AmbientCubemap(AmbientCubemap copyFrom) {
        this(copyFrom.data);
    }

    public AmbientCubemap set(float[] values) {
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

    public AmbientCubemap set(AmbientCubemap other) {
        return set(other.data);
    }

    public AmbientCubemap set(Color color) {
        return set(color.r, color.g, color.b);
    }

    public AmbientCubemap set(float r, float g, float b) {
        for (int idx = 0; idx < 18; idx += 3) {
            float[] fArr = this.data;
            fArr[idx] = r;
            fArr[idx + 1] = g;
            fArr[idx + 2] = b;
        }
        return this;
    }

    public Color getColor(Color out, int side) {
        int side2 = side * 3;
        float[] fArr = this.data;
        return out.set(fArr[side2], fArr[side2 + 1], fArr[side2 + 2], 1.0f);
    }

    public AmbientCubemap clear() {
        int i = 0;
        while (true) {
            float[] fArr = this.data;
            if (i < fArr.length) {
                fArr[i] = 0.0f;
                i++;
            } else {
                return this;
            }
        }
    }

    public AmbientCubemap clamp() {
        int i = 0;
        while (true) {
            float[] fArr = this.data;
            if (i < fArr.length) {
                fArr[i] = clamp(fArr[i]);
                i++;
            } else {
                return this;
            }
        }
    }

    public AmbientCubemap add(float r, float g, float b) {
        int idx = 0;
        while (true) {
            float[] fArr = this.data;
            if (idx < fArr.length) {
                int idx2 = idx + 1;
                fArr[idx] = fArr[idx] + r;
                int idx3 = idx2 + 1;
                fArr[idx2] = fArr[idx2] + g;
                fArr[idx3] = fArr[idx3] + b;
                idx = idx3 + 1;
            } else {
                return this;
            }
        }
    }

    public AmbientCubemap add(Color color) {
        return add(color.r, color.g, color.b);
    }

    public AmbientCubemap add(float r, float g, float b, float x, float y, float z) {
        float x2 = x * x;
        float y2 = y * y;
        float z2 = z * z;
        float d = x2 + y2 + z2;
        if (d == 0.0f) {
            return this;
        }
        float d2 = (1.0f / d) * (1.0f + d);
        float d3 = r * d2;
        float gd = g * d2;
        float bd = b * d2;
        int idx = x > 0.0f ? 0 : 3;
        float[] fArr = this.data;
        fArr[idx] = fArr[idx] + (x2 * d3);
        int i = idx + 1;
        fArr[i] = fArr[i] + (x2 * gd);
        int i2 = idx + 2;
        fArr[i2] = fArr[i2] + (x2 * bd);
        int idx2 = y > 0.0f ? 6 : 9;
        float[] fArr2 = this.data;
        fArr2[idx2] = fArr2[idx2] + (y2 * d3);
        int i3 = idx2 + 1;
        fArr2[i3] = fArr2[i3] + (y2 * gd);
        int i4 = idx2 + 2;
        fArr2[i4] = fArr2[i4] + (y2 * bd);
        int idx3 = z > 0.0f ? 12 : 15;
        float[] fArr3 = this.data;
        fArr3[idx3] = fArr3[idx3] + (z2 * d3);
        int i5 = idx3 + 1;
        fArr3[i5] = fArr3[i5] + (z2 * gd);
        int i6 = idx3 + 2;
        fArr3[i6] = fArr3[i6] + (z2 * bd);
        return this;
    }

    public AmbientCubemap add(Color color, Vector3 direction) {
        return add(color.r, color.g, color.b, direction.x, direction.y, direction.z);
    }

    public AmbientCubemap add(float r, float g, float b, Vector3 direction) {
        return add(r, g, b, direction.x, direction.y, direction.z);
    }

    public AmbientCubemap add(Color color, float x, float y, float z) {
        return add(color.r, color.g, color.b, x, y, z);
    }

    public AmbientCubemap add(Color color, Vector3 point, Vector3 target) {
        return add(color.r, color.g, color.b, target.x - point.x, target.y - point.y, target.z - point.z);
    }

    public AmbientCubemap add(Color color, Vector3 point, Vector3 target, float intensity) {
        float t = intensity / (target.dst(point) + 1.0f);
        return add(color.r * t, color.g * t, color.b * t, target.x - point.x, target.y - point.y, target.z - point.z);
    }

    public String toString() {
        String result = BuildConfig.FLAVOR;
        for (int i = 0; i < this.data.length; i += 3) {
            result = result + Float.toString(this.data[i]) + ", " + Float.toString(this.data[i + 1]) + ", " + Float.toString(this.data[i + 2]) + "\n";
        }
        return result;
    }
}