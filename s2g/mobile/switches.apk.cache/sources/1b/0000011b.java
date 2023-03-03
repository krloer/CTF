package com.badlogic.gdx.graphics.g2d;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.Texture;
import com.badlogic.gdx.math.MathUtils;
import com.badlogic.gdx.utils.GdxRuntimeException;

/* loaded from: classes.dex */
public class NinePatch {
    public static final int BOTTOM_CENTER = 7;
    public static final int BOTTOM_LEFT = 6;
    public static final int BOTTOM_RIGHT = 8;
    public static final int MIDDLE_CENTER = 4;
    public static final int MIDDLE_LEFT = 3;
    public static final int MIDDLE_RIGHT = 5;
    public static final int TOP_CENTER = 1;
    public static final int TOP_LEFT = 0;
    public static final int TOP_RIGHT = 2;
    private static final Color tmpDrawColor = new Color();
    private int bottomCenter;
    private float bottomHeight;
    private int bottomLeft;
    private int bottomRight;
    private final Color color;
    private int idx;
    private float leftWidth;
    private int middleCenter;
    private float middleHeight;
    private int middleLeft;
    private int middleRight;
    private float middleWidth;
    private float padBottom;
    private float padLeft;
    private float padRight;
    private float padTop;
    private float rightWidth;
    private Texture texture;
    private int topCenter;
    private float topHeight;
    private int topLeft;
    private int topRight;
    private float[] vertices;

    public NinePatch(Texture texture, int left, int right, int top, int bottom) {
        this(new TextureRegion(texture), left, right, top, bottom);
    }

    public NinePatch(TextureRegion region, int left, int right, int top, int bottom) {
        this.vertices = new float[180];
        this.color = new Color(Color.WHITE);
        this.padLeft = -1.0f;
        this.padRight = -1.0f;
        this.padTop = -1.0f;
        this.padBottom = -1.0f;
        if (region == null) {
            throw new IllegalArgumentException("region cannot be null.");
        }
        int middleWidth = (region.getRegionWidth() - left) - right;
        int middleHeight = (region.getRegionHeight() - top) - bottom;
        TextureRegion[] patches = new TextureRegion[9];
        if (top > 0) {
            if (left > 0) {
                patches[0] = new TextureRegion(region, 0, 0, left, top);
            }
            if (middleWidth > 0) {
                patches[1] = new TextureRegion(region, left, 0, middleWidth, top);
            }
            if (right > 0) {
                patches[2] = new TextureRegion(region, left + middleWidth, 0, right, top);
            }
        }
        if (middleHeight > 0) {
            if (left > 0) {
                patches[3] = new TextureRegion(region, 0, top, left, middleHeight);
            }
            if (middleWidth > 0) {
                patches[4] = new TextureRegion(region, left, top, middleWidth, middleHeight);
            }
            if (right > 0) {
                patches[5] = new TextureRegion(region, left + middleWidth, top, right, middleHeight);
            }
        }
        if (bottom > 0) {
            if (left > 0) {
                patches[6] = new TextureRegion(region, 0, top + middleHeight, left, bottom);
            }
            if (middleWidth > 0) {
                patches[7] = new TextureRegion(region, left, top + middleHeight, middleWidth, bottom);
            }
            if (right > 0) {
                patches[8] = new TextureRegion(region, left + middleWidth, top + middleHeight, right, bottom);
            }
        }
        if (left == 0 && middleWidth == 0) {
            patches[1] = patches[2];
            patches[4] = patches[5];
            patches[7] = patches[8];
            patches[2] = null;
            patches[5] = null;
            patches[8] = null;
        }
        if (top == 0 && middleHeight == 0) {
            patches[3] = patches[6];
            patches[4] = patches[7];
            patches[5] = patches[8];
            patches[6] = null;
            patches[7] = null;
            patches[8] = null;
        }
        load(patches);
    }

    public NinePatch(Texture texture, Color color) {
        this(texture);
        setColor(color);
    }

    public NinePatch(Texture texture) {
        this(new TextureRegion(texture));
    }

    public NinePatch(TextureRegion region, Color color) {
        this(region);
        setColor(color);
    }

    public NinePatch(TextureRegion region) {
        this.vertices = new float[180];
        this.color = new Color(Color.WHITE);
        this.padLeft = -1.0f;
        this.padRight = -1.0f;
        this.padTop = -1.0f;
        this.padBottom = -1.0f;
        load(new TextureRegion[]{null, null, null, null, region, null, null, null, null});
    }

    public NinePatch(TextureRegion... patches) {
        this.vertices = new float[180];
        this.color = new Color(Color.WHITE);
        this.padLeft = -1.0f;
        this.padRight = -1.0f;
        this.padTop = -1.0f;
        this.padBottom = -1.0f;
        if (patches == null || patches.length != 9) {
            throw new IllegalArgumentException("NinePatch needs nine TextureRegions");
        }
        load(patches);
        if ((patches[0] != null && patches[0].getRegionWidth() != this.leftWidth) || ((patches[3] != null && patches[3].getRegionWidth() != this.leftWidth) || (patches[6] != null && patches[6].getRegionWidth() != this.leftWidth))) {
            throw new GdxRuntimeException("Left side patches must have the same width");
        }
        if ((patches[2] != null && patches[2].getRegionWidth() != this.rightWidth) || ((patches[5] != null && patches[5].getRegionWidth() != this.rightWidth) || (patches[8] != null && patches[8].getRegionWidth() != this.rightWidth))) {
            throw new GdxRuntimeException("Right side patches must have the same width");
        }
        if ((patches[6] != null && patches[6].getRegionHeight() != this.bottomHeight) || ((patches[7] != null && patches[7].getRegionHeight() != this.bottomHeight) || (patches[8] != null && patches[8].getRegionHeight() != this.bottomHeight))) {
            throw new GdxRuntimeException("Bottom side patches must have the same height");
        }
        if ((patches[0] != null && patches[0].getRegionHeight() != this.topHeight) || ((patches[1] != null && patches[1].getRegionHeight() != this.topHeight) || (patches[2] != null && patches[2].getRegionHeight() != this.topHeight))) {
            throw new GdxRuntimeException("Top side patches must have the same height");
        }
    }

    public NinePatch(NinePatch ninePatch) {
        this(ninePatch, ninePatch.color);
    }

    public NinePatch(NinePatch ninePatch, Color color) {
        this.vertices = new float[180];
        this.color = new Color(Color.WHITE);
        this.padLeft = -1.0f;
        this.padRight = -1.0f;
        this.padTop = -1.0f;
        this.padBottom = -1.0f;
        this.texture = ninePatch.texture;
        this.bottomLeft = ninePatch.bottomLeft;
        this.bottomCenter = ninePatch.bottomCenter;
        this.bottomRight = ninePatch.bottomRight;
        this.middleLeft = ninePatch.middleLeft;
        this.middleCenter = ninePatch.middleCenter;
        this.middleRight = ninePatch.middleRight;
        this.topLeft = ninePatch.topLeft;
        this.topCenter = ninePatch.topCenter;
        this.topRight = ninePatch.topRight;
        this.leftWidth = ninePatch.leftWidth;
        this.rightWidth = ninePatch.rightWidth;
        this.middleWidth = ninePatch.middleWidth;
        this.middleHeight = ninePatch.middleHeight;
        this.topHeight = ninePatch.topHeight;
        this.bottomHeight = ninePatch.bottomHeight;
        this.padLeft = ninePatch.padLeft;
        this.padTop = ninePatch.padTop;
        this.padBottom = ninePatch.padBottom;
        this.padRight = ninePatch.padRight;
        this.vertices = new float[ninePatch.vertices.length];
        float[] fArr = ninePatch.vertices;
        System.arraycopy(fArr, 0, this.vertices, 0, fArr.length);
        this.idx = ninePatch.idx;
        this.color.set(color);
    }

    private void load(TextureRegion[] patches) {
        if (patches[6] != null) {
            this.bottomLeft = add(patches[6], false, false);
            this.leftWidth = patches[6].getRegionWidth();
            this.bottomHeight = patches[6].getRegionHeight();
        } else {
            this.bottomLeft = -1;
        }
        if (patches[7] != null) {
            this.bottomCenter = add(patches[7], (patches[6] == null && patches[8] == null) ? false : true, false);
            this.middleWidth = Math.max(this.middleWidth, patches[7].getRegionWidth());
            this.bottomHeight = Math.max(this.bottomHeight, patches[7].getRegionHeight());
        } else {
            this.bottomCenter = -1;
        }
        if (patches[8] != null) {
            this.bottomRight = add(patches[8], false, false);
            this.rightWidth = Math.max(this.rightWidth, patches[8].getRegionWidth());
            this.bottomHeight = Math.max(this.bottomHeight, patches[8].getRegionHeight());
        } else {
            this.bottomRight = -1;
        }
        if (patches[3] != null) {
            this.middleLeft = add(patches[3], false, (patches[0] == null && patches[6] == null) ? false : true);
            this.leftWidth = Math.max(this.leftWidth, patches[3].getRegionWidth());
            this.middleHeight = Math.max(this.middleHeight, patches[3].getRegionHeight());
        } else {
            this.middleLeft = -1;
        }
        if (patches[4] != null) {
            this.middleCenter = add(patches[4], (patches[3] == null && patches[5] == null) ? false : true, (patches[1] == null && patches[7] == null) ? false : true);
            this.middleWidth = Math.max(this.middleWidth, patches[4].getRegionWidth());
            this.middleHeight = Math.max(this.middleHeight, patches[4].getRegionHeight());
        } else {
            this.middleCenter = -1;
        }
        if (patches[5] != null) {
            this.middleRight = add(patches[5], false, (patches[2] == null && patches[8] == null) ? false : true);
            this.rightWidth = Math.max(this.rightWidth, patches[5].getRegionWidth());
            this.middleHeight = Math.max(this.middleHeight, patches[5].getRegionHeight());
        } else {
            this.middleRight = -1;
        }
        if (patches[0] != null) {
            this.topLeft = add(patches[0], false, false);
            this.leftWidth = Math.max(this.leftWidth, patches[0].getRegionWidth());
            this.topHeight = Math.max(this.topHeight, patches[0].getRegionHeight());
        } else {
            this.topLeft = -1;
        }
        if (patches[1] != null) {
            this.topCenter = add(patches[1], (patches[0] == null && patches[2] == null) ? false : true, false);
            this.middleWidth = Math.max(this.middleWidth, patches[1].getRegionWidth());
            this.topHeight = Math.max(this.topHeight, patches[1].getRegionHeight());
        } else {
            this.topCenter = -1;
        }
        if (patches[2] != null) {
            this.topRight = add(patches[2], false, false);
            this.rightWidth = Math.max(this.rightWidth, patches[2].getRegionWidth());
            this.topHeight = Math.max(this.topHeight, patches[2].getRegionHeight());
        } else {
            this.topRight = -1;
        }
        int i = this.idx;
        float[] fArr = this.vertices;
        if (i < fArr.length) {
            float[] newVertices = new float[i];
            System.arraycopy(fArr, 0, newVertices, 0, i);
            this.vertices = newVertices;
        }
    }

    private int add(TextureRegion region, boolean isStretchW, boolean isStretchH) {
        Texture texture = this.texture;
        if (texture == null) {
            this.texture = region.getTexture();
        } else if (texture != region.getTexture()) {
            throw new IllegalArgumentException("All regions must be from the same texture.");
        }
        float u = region.u;
        float v = region.v2;
        float u2 = region.u2;
        float v2 = region.v;
        if (this.texture.getMagFilter() == Texture.TextureFilter.Linear || this.texture.getMinFilter() == Texture.TextureFilter.Linear) {
            if (isStretchW) {
                float halfTexelWidth = 0.5f / this.texture.getWidth();
                u += halfTexelWidth;
                u2 -= halfTexelWidth;
            }
            if (isStretchH) {
                float halfTexelHeight = 0.5f / this.texture.getHeight();
                v -= halfTexelHeight;
                v2 += halfTexelHeight;
            }
        }
        float[] vertices = this.vertices;
        int i = this.idx;
        vertices[i + 3] = u;
        vertices[i + 4] = v;
        vertices[i + 8] = u;
        vertices[i + 9] = v2;
        vertices[i + 13] = u2;
        vertices[i + 14] = v2;
        vertices[i + 18] = u2;
        vertices[i + 19] = v;
        this.idx += 20;
        return i;
    }

    private void set(int idx, float x, float y, float width, float height, float color) {
        float fx2 = x + width;
        float fy2 = y + height;
        float[] vertices = this.vertices;
        vertices[idx] = x;
        vertices[idx + 1] = y;
        vertices[idx + 2] = color;
        vertices[idx + 5] = x;
        vertices[idx + 6] = fy2;
        vertices[idx + 7] = color;
        vertices[idx + 10] = fx2;
        vertices[idx + 11] = fy2;
        vertices[idx + 12] = color;
        vertices[idx + 15] = fx2;
        vertices[idx + 16] = y;
        vertices[idx + 17] = color;
    }

    private void prepareVertices(Batch batch, float x, float y, float width, float height) {
        float f = this.leftWidth;
        float centerX = x + f;
        float f2 = this.bottomHeight;
        float centerY = y + f2;
        float f3 = this.rightWidth;
        float centerWidth = (width - f3) - f;
        float f4 = this.topHeight;
        float centerHeight = (height - f4) - f2;
        float rightX = (x + width) - f3;
        float topY = (y + height) - f4;
        float c = tmpDrawColor.set(this.color).mul(batch.getColor()).toFloatBits();
        int i = this.bottomLeft;
        if (i != -1) {
            set(i, x, y, this.leftWidth, this.bottomHeight, c);
        }
        int i2 = this.bottomCenter;
        if (i2 != -1) {
            set(i2, centerX, y, centerWidth, this.bottomHeight, c);
        }
        int i3 = this.bottomRight;
        if (i3 != -1) {
            set(i3, rightX, y, this.rightWidth, this.bottomHeight, c);
        }
        int i4 = this.middleLeft;
        if (i4 != -1) {
            set(i4, x, centerY, this.leftWidth, centerHeight, c);
        }
        int i5 = this.middleCenter;
        if (i5 != -1) {
            set(i5, centerX, centerY, centerWidth, centerHeight, c);
        }
        int i6 = this.middleRight;
        if (i6 != -1) {
            set(i6, rightX, centerY, this.rightWidth, centerHeight, c);
        }
        int i7 = this.topLeft;
        if (i7 != -1) {
            set(i7, x, topY, this.leftWidth, this.topHeight, c);
        }
        int i8 = this.topCenter;
        if (i8 != -1) {
            set(i8, centerX, topY, centerWidth, this.topHeight, c);
        }
        int i9 = this.topRight;
        if (i9 != -1) {
            set(i9, rightX, topY, this.rightWidth, this.topHeight, c);
        }
    }

    public void draw(Batch batch, float x, float y, float width, float height) {
        prepareVertices(batch, x, y, width, height);
        batch.draw(this.texture, this.vertices, 0, this.idx);
    }

    public void draw(Batch batch, float x, float y, float originX, float originY, float width, float height, float scaleX, float scaleY, float rotation) {
        prepareVertices(batch, x, y, width, height);
        float worldOriginX = x + originX;
        float worldOriginY = y + originY;
        int n = this.idx;
        float[] vertices = this.vertices;
        if (rotation != 0.0f) {
            for (int i = 0; i < n; i += 5) {
                float vx = (vertices[i] - worldOriginX) * scaleX;
                float vy = (vertices[i + 1] - worldOriginY) * scaleY;
                float cos = MathUtils.cosDeg(rotation);
                float sin = MathUtils.sinDeg(rotation);
                vertices[i] = ((cos * vx) - (sin * vy)) + worldOriginX;
                vertices[i + 1] = (sin * vx) + (cos * vy) + worldOriginY;
            }
        } else if (scaleX != 1.0f || scaleY != 1.0f) {
            for (int i2 = 0; i2 < n; i2 += 5) {
                vertices[i2] = ((vertices[i2] - worldOriginX) * scaleX) + worldOriginX;
                vertices[i2 + 1] = ((vertices[i2 + 1] - worldOriginY) * scaleY) + worldOriginY;
            }
        }
        batch.draw(this.texture, vertices, 0, n);
    }

    public void setColor(Color color) {
        this.color.set(color);
    }

    public Color getColor() {
        return this.color;
    }

    public float getLeftWidth() {
        return this.leftWidth;
    }

    public void setLeftWidth(float leftWidth) {
        this.leftWidth = leftWidth;
    }

    public float getRightWidth() {
        return this.rightWidth;
    }

    public void setRightWidth(float rightWidth) {
        this.rightWidth = rightWidth;
    }

    public float getTopHeight() {
        return this.topHeight;
    }

    public void setTopHeight(float topHeight) {
        this.topHeight = topHeight;
    }

    public float getBottomHeight() {
        return this.bottomHeight;
    }

    public void setBottomHeight(float bottomHeight) {
        this.bottomHeight = bottomHeight;
    }

    public float getMiddleWidth() {
        return this.middleWidth;
    }

    public void setMiddleWidth(float middleWidth) {
        this.middleWidth = middleWidth;
    }

    public float getMiddleHeight() {
        return this.middleHeight;
    }

    public void setMiddleHeight(float middleHeight) {
        this.middleHeight = middleHeight;
    }

    public float getTotalWidth() {
        return this.leftWidth + this.middleWidth + this.rightWidth;
    }

    public float getTotalHeight() {
        return this.topHeight + this.middleHeight + this.bottomHeight;
    }

    public void setPadding(float left, float right, float top, float bottom) {
        this.padLeft = left;
        this.padRight = right;
        this.padTop = top;
        this.padBottom = bottom;
    }

    public float getPadLeft() {
        float f = this.padLeft;
        return f == -1.0f ? getLeftWidth() : f;
    }

    public void setPadLeft(float left) {
        this.padLeft = left;
    }

    public float getPadRight() {
        float f = this.padRight;
        return f == -1.0f ? getRightWidth() : f;
    }

    public void setPadRight(float right) {
        this.padRight = right;
    }

    public float getPadTop() {
        float f = this.padTop;
        return f == -1.0f ? getTopHeight() : f;
    }

    public void setPadTop(float top) {
        this.padTop = top;
    }

    public float getPadBottom() {
        float f = this.padBottom;
        return f == -1.0f ? getBottomHeight() : f;
    }

    public void setPadBottom(float bottom) {
        this.padBottom = bottom;
    }

    public void scale(float scaleX, float scaleY) {
        this.leftWidth *= scaleX;
        this.rightWidth *= scaleX;
        this.topHeight *= scaleY;
        this.bottomHeight *= scaleY;
        this.middleWidth *= scaleX;
        this.middleHeight *= scaleY;
        float f = this.padLeft;
        if (f != -1.0f) {
            this.padLeft = f * scaleX;
        }
        float f2 = this.padRight;
        if (f2 != -1.0f) {
            this.padRight = f2 * scaleX;
        }
        float f3 = this.padTop;
        if (f3 != -1.0f) {
            this.padTop = f3 * scaleY;
        }
        float f4 = this.padBottom;
        if (f4 != -1.0f) {
            this.padBottom = f4 * scaleY;
        }
    }

    public Texture getTexture() {
        return this.texture;
    }
}