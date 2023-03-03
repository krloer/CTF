package com.badlogic.gdx.graphics;

import com.badlogic.gdx.utils.NumberUtils;

/* loaded from: classes.dex */
public class Color {
    public float a;
    public float b;
    public float g;
    public float r;
    public static final Color WHITE = new Color(1.0f, 1.0f, 1.0f, 1.0f);
    public static final Color LIGHT_GRAY = new Color(-1077952513);
    public static final Color GRAY = new Color(2139062271);
    public static final Color DARK_GRAY = new Color(1061109759);
    public static final Color BLACK = new Color(0.0f, 0.0f, 0.0f, 1.0f);
    public static final float WHITE_FLOAT_BITS = WHITE.toFloatBits();
    public static final Color CLEAR = new Color(0.0f, 0.0f, 0.0f, 0.0f);
    public static final Color BLUE = new Color(0.0f, 0.0f, 1.0f, 1.0f);
    public static final Color NAVY = new Color(0.0f, 0.0f, 0.5f, 1.0f);
    public static final Color ROYAL = new Color(1097458175);
    public static final Color SLATE = new Color(1887473919);
    public static final Color SKY = new Color(-2016482305);
    public static final Color CYAN = new Color(0.0f, 1.0f, 1.0f, 1.0f);
    public static final Color TEAL = new Color(0.0f, 0.5f, 0.5f, 1.0f);
    public static final Color GREEN = new Color(16711935);
    public static final Color CHARTREUSE = new Color(2147418367);
    public static final Color LIME = new Color(852308735);
    public static final Color FOREST = new Color(579543807);
    public static final Color OLIVE = new Color(1804477439);
    public static final Color YELLOW = new Color(-65281);
    public static final Color GOLD = new Color(-2686721);
    public static final Color GOLDENROD = new Color(-626712321);
    public static final Color ORANGE = new Color(-5963521);
    public static final Color BROWN = new Color(-1958407169);
    public static final Color TAN = new Color(-759919361);
    public static final Color FIREBRICK = new Color(-1306385665);
    public static final Color RED = new Color(-16776961);
    public static final Color SCARLET = new Color(-13361921);
    public static final Color CORAL = new Color(-8433409);
    public static final Color SALMON = new Color(-92245249);
    public static final Color PINK = new Color(-9849601);
    public static final Color MAGENTA = new Color(1.0f, 0.0f, 1.0f, 1.0f);
    public static final Color PURPLE = new Color(-1608453889);
    public static final Color VIOLET = new Color(-293409025);
    public static final Color MAROON = new Color(-1339006721);

    public Color() {
    }

    public Color(int rgba8888) {
        rgba8888ToColor(this, rgba8888);
    }

    public Color(float r, float g, float b, float a) {
        this.r = r;
        this.g = g;
        this.b = b;
        this.a = a;
        clamp();
    }

    public Color(Color color) {
        set(color);
    }

    public Color set(Color color) {
        this.r = color.r;
        this.g = color.g;
        this.b = color.b;
        this.a = color.a;
        return this;
    }

    public Color mul(Color color) {
        this.r *= color.r;
        this.g *= color.g;
        this.b *= color.b;
        this.a *= color.a;
        return clamp();
    }

    public Color mul(float value) {
        this.r *= value;
        this.g *= value;
        this.b *= value;
        this.a *= value;
        return clamp();
    }

    public Color add(Color color) {
        this.r += color.r;
        this.g += color.g;
        this.b += color.b;
        this.a += color.a;
        return clamp();
    }

    public Color sub(Color color) {
        this.r -= color.r;
        this.g -= color.g;
        this.b -= color.b;
        this.a -= color.a;
        return clamp();
    }

    public Color clamp() {
        float f = this.r;
        if (f < 0.0f) {
            this.r = 0.0f;
        } else if (f > 1.0f) {
            this.r = 1.0f;
        }
        float f2 = this.g;
        if (f2 < 0.0f) {
            this.g = 0.0f;
        } else if (f2 > 1.0f) {
            this.g = 1.0f;
        }
        float f3 = this.b;
        if (f3 < 0.0f) {
            this.b = 0.0f;
        } else if (f3 > 1.0f) {
            this.b = 1.0f;
        }
        float f4 = this.a;
        if (f4 < 0.0f) {
            this.a = 0.0f;
        } else if (f4 > 1.0f) {
            this.a = 1.0f;
        }
        return this;
    }

    public Color set(float r, float g, float b, float a) {
        this.r = r;
        this.g = g;
        this.b = b;
        this.a = a;
        return clamp();
    }

    public Color set(int rgba) {
        rgba8888ToColor(this, rgba);
        return this;
    }

    public Color add(float r, float g, float b, float a) {
        this.r += r;
        this.g += g;
        this.b += b;
        this.a += a;
        return clamp();
    }

    public Color sub(float r, float g, float b, float a) {
        this.r -= r;
        this.g -= g;
        this.b -= b;
        this.a -= a;
        return clamp();
    }

    public Color mul(float r, float g, float b, float a) {
        this.r *= r;
        this.g *= g;
        this.b *= b;
        this.a *= a;
        return clamp();
    }

    public Color lerp(Color target, float t) {
        float f = this.r;
        this.r = f + ((target.r - f) * t);
        float f2 = this.g;
        this.g = f2 + ((target.g - f2) * t);
        float f3 = this.b;
        this.b = f3 + ((target.b - f3) * t);
        float f4 = this.a;
        this.a = f4 + ((target.a - f4) * t);
        return clamp();
    }

    public Color lerp(float r, float g, float b, float a, float t) {
        float f = this.r;
        this.r = f + ((r - f) * t);
        float f2 = this.g;
        this.g = f2 + ((g - f2) * t);
        float f3 = this.b;
        this.b = f3 + ((b - f3) * t);
        float f4 = this.a;
        this.a = f4 + ((a - f4) * t);
        return clamp();
    }

    public Color premultiplyAlpha() {
        float f = this.r;
        float f2 = this.a;
        this.r = f * f2;
        this.g *= f2;
        this.b *= f2;
        return this;
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        Color color = (Color) o;
        return toIntBits() == color.toIntBits();
    }

    public int hashCode() {
        float f = this.r;
        int result = f != 0.0f ? NumberUtils.floatToIntBits(f) : 0;
        int i = result * 31;
        float f2 = this.g;
        int result2 = i + (f2 != 0.0f ? NumberUtils.floatToIntBits(f2) : 0);
        int result3 = result2 * 31;
        float f3 = this.b;
        int result4 = (result3 + (f3 != 0.0f ? NumberUtils.floatToIntBits(f3) : 0)) * 31;
        float f4 = this.a;
        return result4 + (f4 != 0.0f ? NumberUtils.floatToIntBits(f4) : 0);
    }

    public float toFloatBits() {
        int color = (((int) (this.a * 255.0f)) << 24) | (((int) (this.b * 255.0f)) << 16) | (((int) (this.g * 255.0f)) << 8) | ((int) (this.r * 255.0f));
        return NumberUtils.intToFloatColor(color);
    }

    public int toIntBits() {
        return (((int) (this.a * 255.0f)) << 24) | (((int) (this.b * 255.0f)) << 16) | (((int) (this.g * 255.0f)) << 8) | ((int) (this.r * 255.0f));
    }

    public String toString() {
        String value = Integer.toHexString((((int) (this.r * 255.0f)) << 24) | (((int) (this.g * 255.0f)) << 16) | (((int) (this.b * 255.0f)) << 8) | ((int) (this.a * 255.0f)));
        while (value.length() < 8) {
            value = "0" + value;
        }
        return value;
    }

    public static Color valueOf(String hex) {
        return valueOf(hex, new Color());
    }

    public static Color valueOf(String hex, Color color) {
        String hex2 = hex.charAt(0) == '#' ? hex.substring(1) : hex;
        color.r = Integer.parseInt(hex2.substring(0, 2), 16) / 255.0f;
        color.g = Integer.parseInt(hex2.substring(2, 4), 16) / 255.0f;
        color.b = Integer.parseInt(hex2.substring(4, 6), 16) / 255.0f;
        color.a = hex2.length() != 8 ? 1.0f : Integer.parseInt(hex2.substring(6, 8), 16) / 255.0f;
        return color;
    }

    public static float toFloatBits(int r, int g, int b, int a) {
        int color = (a << 24) | (b << 16) | (g << 8) | r;
        float floatColor = NumberUtils.intToFloatColor(color);
        return floatColor;
    }

    public static float toFloatBits(float r, float g, float b, float a) {
        int color = ((int) (255.0f * r)) | (((int) (a * 255.0f)) << 24) | (((int) (b * 255.0f)) << 16) | (((int) (g * 255.0f)) << 8);
        return NumberUtils.intToFloatColor(color);
    }

    public static int toIntBits(int r, int g, int b, int a) {
        return (a << 24) | (b << 16) | (g << 8) | r;
    }

    public static int alpha(float alpha) {
        return (int) (255.0f * alpha);
    }

    public static int luminanceAlpha(float luminance, float alpha) {
        return ((int) (255.0f * alpha)) | (((int) (luminance * 255.0f)) << 8);
    }

    public static int rgb565(float r, float g, float b) {
        return ((int) (31.0f * b)) | (((int) (r * 31.0f)) << 11) | (((int) (63.0f * g)) << 5);
    }

    public static int rgba4444(float r, float g, float b, float a) {
        return ((int) (15.0f * a)) | (((int) (r * 15.0f)) << 12) | (((int) (g * 15.0f)) << 8) | (((int) (b * 15.0f)) << 4);
    }

    public static int rgb888(float r, float g, float b) {
        return ((int) (255.0f * b)) | (((int) (r * 255.0f)) << 16) | (((int) (g * 255.0f)) << 8);
    }

    public static int rgba8888(float r, float g, float b, float a) {
        return ((int) (255.0f * a)) | (((int) (r * 255.0f)) << 24) | (((int) (g * 255.0f)) << 16) | (((int) (b * 255.0f)) << 8);
    }

    public static int argb8888(float a, float r, float g, float b) {
        return ((int) (255.0f * b)) | (((int) (a * 255.0f)) << 24) | (((int) (r * 255.0f)) << 16) | (((int) (g * 255.0f)) << 8);
    }

    public static int rgb565(Color color) {
        return (((int) (color.r * 31.0f)) << 11) | (((int) (color.g * 63.0f)) << 5) | ((int) (color.b * 31.0f));
    }

    public static int rgba4444(Color color) {
        return (((int) (color.r * 15.0f)) << 12) | (((int) (color.g * 15.0f)) << 8) | (((int) (color.b * 15.0f)) << 4) | ((int) (color.a * 15.0f));
    }

    public static int rgb888(Color color) {
        return (((int) (color.r * 255.0f)) << 16) | (((int) (color.g * 255.0f)) << 8) | ((int) (color.b * 255.0f));
    }

    public static int rgba8888(Color color) {
        return (((int) (color.r * 255.0f)) << 24) | (((int) (color.g * 255.0f)) << 16) | (((int) (color.b * 255.0f)) << 8) | ((int) (color.a * 255.0f));
    }

    public static int argb8888(Color color) {
        return (((int) (color.a * 255.0f)) << 24) | (((int) (color.r * 255.0f)) << 16) | (((int) (color.g * 255.0f)) << 8) | ((int) (color.b * 255.0f));
    }

    public static void rgb565ToColor(Color color, int value) {
        color.r = ((63488 & value) >>> 11) / 31.0f;
        color.g = ((value & 2016) >>> 5) / 63.0f;
        color.b = ((value & 31) >>> 0) / 31.0f;
    }

    public static void rgba4444ToColor(Color color, int value) {
        color.r = ((61440 & value) >>> 12) / 15.0f;
        color.g = ((value & 3840) >>> 8) / 15.0f;
        color.b = ((value & 240) >>> 4) / 15.0f;
        color.a = (value & 15) / 15.0f;
    }

    public static void rgb888ToColor(Color color, int value) {
        color.r = ((16711680 & value) >>> 16) / 255.0f;
        color.g = ((65280 & value) >>> 8) / 255.0f;
        color.b = (value & 255) / 255.0f;
    }

    public static void rgba8888ToColor(Color color, int value) {
        color.r = (((-16777216) & value) >>> 24) / 255.0f;
        color.g = ((16711680 & value) >>> 16) / 255.0f;
        color.b = ((65280 & value) >>> 8) / 255.0f;
        color.a = (value & 255) / 255.0f;
    }

    public static void argb8888ToColor(Color color, int value) {
        color.a = (((-16777216) & value) >>> 24) / 255.0f;
        color.r = ((16711680 & value) >>> 16) / 255.0f;
        color.g = ((65280 & value) >>> 8) / 255.0f;
        color.b = (value & 255) / 255.0f;
    }

    public static void abgr8888ToColor(Color color, float value) {
        int c = NumberUtils.floatToIntColor(value);
        color.a = (((-16777216) & c) >>> 24) / 255.0f;
        color.b = ((16711680 & c) >>> 16) / 255.0f;
        color.g = ((65280 & c) >>> 8) / 255.0f;
        color.r = (c & 255) / 255.0f;
    }

    public Color fromHsv(float h, float s, float v) {
        float x = ((h / 60.0f) + 6.0f) % 6.0f;
        int i = (int) x;
        float f = x - i;
        float p = (1.0f - s) * v;
        float q = (1.0f - (s * f)) * v;
        float t = (1.0f - ((1.0f - f) * s)) * v;
        if (i == 0) {
            this.r = v;
            this.g = t;
            this.b = p;
        } else if (i == 1) {
            this.r = q;
            this.g = v;
            this.b = p;
        } else if (i == 2) {
            this.r = p;
            this.g = v;
            this.b = t;
        } else if (i == 3) {
            this.r = p;
            this.g = q;
            this.b = v;
        } else if (i == 4) {
            this.r = t;
            this.g = p;
            this.b = v;
        } else {
            this.r = v;
            this.g = p;
            this.b = q;
        }
        return clamp();
    }

    public Color fromHsv(float[] hsv) {
        return fromHsv(hsv[0], hsv[1], hsv[2]);
    }

    public float[] toHsv(float[] hsv) {
        float max = Math.max(Math.max(this.r, this.g), this.b);
        float min = Math.min(Math.min(this.r, this.g), this.b);
        float range = max - min;
        if (range == 0.0f) {
            hsv[0] = 0.0f;
        } else {
            float f = this.r;
            if (max == f) {
                hsv[0] = ((((this.g - this.b) * 60.0f) / range) + 360.0f) % 360.0f;
            } else {
                float f2 = this.g;
                if (max == f2) {
                    hsv[0] = (((this.b - f) * 60.0f) / range) + 120.0f;
                } else {
                    hsv[0] = (((f - f2) * 60.0f) / range) + 240.0f;
                }
            }
        }
        if (max > 0.0f) {
            hsv[1] = 1.0f - (min / max);
        } else {
            hsv[1] = 0.0f;
        }
        hsv[2] = max;
        return hsv;
    }

    public Color cpy() {
        return new Color(this);
    }
}