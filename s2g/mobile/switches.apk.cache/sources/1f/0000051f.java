package com.kotcrab.vis.ui.util;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.math.MathUtils;

/* loaded from: classes.dex */
public class ColorUtils {
    public static Color HSVtoRGB(float h, float s, float v, float alpha) {
        Color c = HSVtoRGB(h, s, v);
        c.a = alpha;
        return c;
    }

    public static Color HSVtoRGB(float h, float s, float v) {
        Color c = new Color(1.0f, 1.0f, 1.0f, 1.0f);
        HSVtoRGB(h, s, v, c);
        return c;
    }

    public static Color HSVtoRGB(float h, float s, float v, Color targetColor) {
        int r;
        int g;
        int b;
        if (h == 360.0f) {
            h = 359.0f;
        }
        float h2 = (float) Math.max(0.0d, Math.min(360.0d, h));
        float s2 = (float) Math.max(0.0d, Math.min(100.0d, s));
        float s3 = s2 / 100.0f;
        float v2 = ((float) Math.max(0.0d, Math.min(100.0d, v))) / 100.0f;
        float h3 = h2 / 60.0f;
        int i = MathUtils.floor(h3);
        float f = h3 - i;
        float p = (1.0f - s3) * v2;
        float q = (1.0f - (s3 * f)) * v2;
        float t = (1.0f - ((1.0f - f) * s3)) * v2;
        if (i == 0) {
            r = MathUtils.round(v2 * 255.0f);
            g = MathUtils.round(t * 255.0f);
            b = MathUtils.round(p * 255.0f);
        } else if (i == 1) {
            r = MathUtils.round(q * 255.0f);
            g = MathUtils.round(v2 * 255.0f);
            b = MathUtils.round(p * 255.0f);
        } else if (i == 2) {
            r = MathUtils.round(p * 255.0f);
            g = MathUtils.round(v2 * 255.0f);
            b = MathUtils.round(t * 255.0f);
        } else if (i == 3) {
            r = MathUtils.round(p * 255.0f);
            g = MathUtils.round(q * 255.0f);
            b = MathUtils.round(v2 * 255.0f);
        } else if (i == 4) {
            r = MathUtils.round(t * 255.0f);
            g = MathUtils.round(p * 255.0f);
            b = MathUtils.round(v2 * 255.0f);
        } else {
            r = MathUtils.round(v2 * 255.0f);
            g = MathUtils.round(p * 255.0f);
            b = MathUtils.round(q * 255.0f);
        }
        targetColor.set(r / 255.0f, g / 255.0f, b / 255.0f, targetColor.a);
        return targetColor;
    }

    public static int[] RGBtoHSV(Color c) {
        return RGBtoHSV(c.r, c.g, c.b);
    }

    public static int[] RGBtoHSV(float r, float g, float b) {
        float h;
        float min = Math.min(Math.min(r, g), b);
        float max = Math.max(Math.max(r, g), b);
        float delta = max - min;
        if (max != 0.0f) {
            float s = delta / max;
            if (delta == 0.0f) {
                h = 0.0f;
            } else if (r == max) {
                h = (g - b) / delta;
            } else if (g == max) {
                h = 2.0f + ((b - r) / delta);
            } else {
                h = 4.0f + ((r - g) / delta);
            }
            float h2 = h * 60.0f;
            if (h2 < 0.0f) {
                h2 += 360.0f;
            }
            float v = max * 100.0f;
            return new int[]{MathUtils.round(h2), MathUtils.round(s * 100.0f), MathUtils.round(v)};
        }
        return new int[]{MathUtils.round(0.0f), MathUtils.round(0.0f), MathUtils.round(max)};
    }
}