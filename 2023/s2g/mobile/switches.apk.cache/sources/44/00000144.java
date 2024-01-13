package com.badlogic.gdx.graphics.g2d;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.Texture;
import com.badlogic.gdx.math.MathUtils;
import com.badlogic.gdx.math.Rectangle;
import com.badlogic.gdx.utils.NumberUtils;

/* loaded from: classes.dex */
public class Sprite extends TextureRegion {
    static final int SPRITE_SIZE = 20;
    static final int VERTEX_SIZE = 5;
    private Rectangle bounds;
    private final Color color;
    private boolean dirty;
    float height;
    private float originX;
    private float originY;
    private float rotation;
    private float scaleX;
    private float scaleY;
    final float[] vertices;
    float width;
    private float x;
    private float y;

    public Sprite() {
        this.vertices = new float[20];
        this.color = new Color(1.0f, 1.0f, 1.0f, 1.0f);
        this.scaleX = 1.0f;
        this.scaleY = 1.0f;
        this.dirty = true;
        setColor(1.0f, 1.0f, 1.0f, 1.0f);
    }

    public Sprite(Texture texture) {
        this(texture, 0, 0, texture.getWidth(), texture.getHeight());
    }

    public Sprite(Texture texture, int srcWidth, int srcHeight) {
        this(texture, 0, 0, srcWidth, srcHeight);
    }

    public Sprite(Texture texture, int srcX, int srcY, int srcWidth, int srcHeight) {
        this.vertices = new float[20];
        this.color = new Color(1.0f, 1.0f, 1.0f, 1.0f);
        this.scaleX = 1.0f;
        this.scaleY = 1.0f;
        this.dirty = true;
        if (texture == null) {
            throw new IllegalArgumentException("texture cannot be null.");
        }
        this.texture = texture;
        setRegion(srcX, srcY, srcWidth, srcHeight);
        setColor(1.0f, 1.0f, 1.0f, 1.0f);
        setSize(Math.abs(srcWidth), Math.abs(srcHeight));
        setOrigin(this.width / 2.0f, this.height / 2.0f);
    }

    public Sprite(TextureRegion region) {
        this.vertices = new float[20];
        this.color = new Color(1.0f, 1.0f, 1.0f, 1.0f);
        this.scaleX = 1.0f;
        this.scaleY = 1.0f;
        this.dirty = true;
        setRegion(region);
        setColor(1.0f, 1.0f, 1.0f, 1.0f);
        setSize(region.getRegionWidth(), region.getRegionHeight());
        setOrigin(this.width / 2.0f, this.height / 2.0f);
    }

    public Sprite(TextureRegion region, int srcX, int srcY, int srcWidth, int srcHeight) {
        this.vertices = new float[20];
        this.color = new Color(1.0f, 1.0f, 1.0f, 1.0f);
        this.scaleX = 1.0f;
        this.scaleY = 1.0f;
        this.dirty = true;
        setRegion(region, srcX, srcY, srcWidth, srcHeight);
        setColor(1.0f, 1.0f, 1.0f, 1.0f);
        setSize(Math.abs(srcWidth), Math.abs(srcHeight));
        setOrigin(this.width / 2.0f, this.height / 2.0f);
    }

    public Sprite(Sprite sprite) {
        this.vertices = new float[20];
        this.color = new Color(1.0f, 1.0f, 1.0f, 1.0f);
        this.scaleX = 1.0f;
        this.scaleY = 1.0f;
        this.dirty = true;
        set(sprite);
    }

    public void set(Sprite sprite) {
        if (sprite == null) {
            throw new IllegalArgumentException("sprite cannot be null.");
        }
        System.arraycopy(sprite.vertices, 0, this.vertices, 0, 20);
        this.texture = sprite.texture;
        this.u = sprite.u;
        this.v = sprite.v;
        this.u2 = sprite.u2;
        this.v2 = sprite.v2;
        this.x = sprite.x;
        this.y = sprite.y;
        this.width = sprite.width;
        this.height = sprite.height;
        this.regionWidth = sprite.regionWidth;
        this.regionHeight = sprite.regionHeight;
        this.originX = sprite.originX;
        this.originY = sprite.originY;
        this.rotation = sprite.rotation;
        this.scaleX = sprite.scaleX;
        this.scaleY = sprite.scaleY;
        this.color.set(sprite.color);
        this.dirty = sprite.dirty;
    }

    public void setBounds(float x, float y, float width, float height) {
        this.x = x;
        this.y = y;
        this.width = width;
        this.height = height;
        if (this.dirty) {
            return;
        }
        if (this.rotation != 0.0f || this.scaleX != 1.0f || this.scaleY != 1.0f) {
            this.dirty = true;
            return;
        }
        float x2 = x + width;
        float y2 = y + height;
        float[] vertices = this.vertices;
        vertices[0] = x;
        vertices[1] = y;
        vertices[5] = x;
        vertices[6] = y2;
        vertices[10] = x2;
        vertices[11] = y2;
        vertices[15] = x2;
        vertices[16] = y;
    }

    public void setSize(float width, float height) {
        this.width = width;
        this.height = height;
        if (this.dirty) {
            return;
        }
        if (this.rotation != 0.0f || this.scaleX != 1.0f || this.scaleY != 1.0f) {
            this.dirty = true;
            return;
        }
        float f = this.x;
        float x2 = f + width;
        float f2 = this.y;
        float y2 = f2 + height;
        float[] vertices = this.vertices;
        vertices[0] = f;
        vertices[1] = f2;
        vertices[5] = f;
        vertices[6] = y2;
        vertices[10] = x2;
        vertices[11] = y2;
        vertices[15] = x2;
        vertices[16] = f2;
    }

    public void setPosition(float x, float y) {
        this.x = x;
        this.y = y;
        if (this.dirty) {
            return;
        }
        if (this.rotation != 0.0f || this.scaleX != 1.0f || this.scaleY != 1.0f) {
            this.dirty = true;
            return;
        }
        float x2 = this.width + x;
        float y2 = this.height + y;
        float[] vertices = this.vertices;
        vertices[0] = x;
        vertices[1] = y;
        vertices[5] = x;
        vertices[6] = y2;
        vertices[10] = x2;
        vertices[11] = y2;
        vertices[15] = x2;
        vertices[16] = y;
    }

    public void setOriginBasedPosition(float x, float y) {
        setPosition(x - this.originX, y - this.originY);
    }

    public void setX(float x) {
        this.x = x;
        if (this.dirty) {
            return;
        }
        if (this.rotation != 0.0f || this.scaleX != 1.0f || this.scaleY != 1.0f) {
            this.dirty = true;
            return;
        }
        float x2 = this.width + x;
        float[] vertices = this.vertices;
        vertices[0] = x;
        vertices[5] = x;
        vertices[10] = x2;
        vertices[15] = x2;
    }

    public void setY(float y) {
        this.y = y;
        if (this.dirty) {
            return;
        }
        if (this.rotation != 0.0f || this.scaleX != 1.0f || this.scaleY != 1.0f) {
            this.dirty = true;
            return;
        }
        float y2 = this.height + y;
        float[] vertices = this.vertices;
        vertices[1] = y;
        vertices[6] = y2;
        vertices[11] = y2;
        vertices[16] = y;
    }

    public void setCenterX(float x) {
        setX(x - (this.width / 2.0f));
    }

    public void setCenterY(float y) {
        setY(y - (this.height / 2.0f));
    }

    public void setCenter(float x, float y) {
        setPosition(x - (this.width / 2.0f), y - (this.height / 2.0f));
    }

    public void translateX(float xAmount) {
        this.x += xAmount;
        if (this.dirty) {
            return;
        }
        if (this.rotation != 0.0f || this.scaleX != 1.0f || this.scaleY != 1.0f) {
            this.dirty = true;
            return;
        }
        float[] vertices = this.vertices;
        vertices[0] = vertices[0] + xAmount;
        vertices[5] = vertices[5] + xAmount;
        vertices[10] = vertices[10] + xAmount;
        vertices[15] = vertices[15] + xAmount;
    }

    public void translateY(float yAmount) {
        this.y += yAmount;
        if (this.dirty) {
            return;
        }
        if (this.rotation != 0.0f || this.scaleX != 1.0f || this.scaleY != 1.0f) {
            this.dirty = true;
            return;
        }
        float[] vertices = this.vertices;
        vertices[1] = vertices[1] + yAmount;
        vertices[6] = vertices[6] + yAmount;
        vertices[11] = vertices[11] + yAmount;
        vertices[16] = vertices[16] + yAmount;
    }

    public void translate(float xAmount, float yAmount) {
        this.x += xAmount;
        this.y += yAmount;
        if (this.dirty) {
            return;
        }
        if (this.rotation != 0.0f || this.scaleX != 1.0f || this.scaleY != 1.0f) {
            this.dirty = true;
            return;
        }
        float[] vertices = this.vertices;
        vertices[0] = vertices[0] + xAmount;
        vertices[1] = vertices[1] + yAmount;
        vertices[5] = vertices[5] + xAmount;
        vertices[6] = vertices[6] + yAmount;
        vertices[10] = vertices[10] + xAmount;
        vertices[11] = vertices[11] + yAmount;
        vertices[15] = vertices[15] + xAmount;
        vertices[16] = vertices[16] + yAmount;
    }

    public void setColor(Color tint) {
        this.color.set(tint);
        float color = tint.toFloatBits();
        float[] vertices = this.vertices;
        vertices[2] = color;
        vertices[7] = color;
        vertices[12] = color;
        vertices[17] = color;
    }

    public void setAlpha(float a) {
        Color color = this.color;
        color.a = a;
        float color2 = color.toFloatBits();
        float[] fArr = this.vertices;
        fArr[2] = color2;
        fArr[7] = color2;
        fArr[12] = color2;
        fArr[17] = color2;
    }

    public void setColor(float r, float g, float b, float a) {
        this.color.set(r, g, b, a);
        float color = this.color.toFloatBits();
        float[] vertices = this.vertices;
        vertices[2] = color;
        vertices[7] = color;
        vertices[12] = color;
        vertices[17] = color;
    }

    public void setPackedColor(float packedColor) {
        Color.abgr8888ToColor(this.color, packedColor);
        float[] vertices = this.vertices;
        vertices[2] = packedColor;
        vertices[7] = packedColor;
        vertices[12] = packedColor;
        vertices[17] = packedColor;
    }

    public void setOrigin(float originX, float originY) {
        this.originX = originX;
        this.originY = originY;
        this.dirty = true;
    }

    public void setOriginCenter() {
        this.originX = this.width / 2.0f;
        this.originY = this.height / 2.0f;
        this.dirty = true;
    }

    public void setRotation(float degrees) {
        this.rotation = degrees;
        this.dirty = true;
    }

    public float getRotation() {
        return this.rotation;
    }

    public void rotate(float degrees) {
        if (degrees == 0.0f) {
            return;
        }
        this.rotation += degrees;
        this.dirty = true;
    }

    public void rotate90(boolean clockwise) {
        float[] vertices = this.vertices;
        if (clockwise) {
            float temp = vertices[4];
            vertices[4] = vertices[19];
            vertices[19] = vertices[14];
            vertices[14] = vertices[9];
            vertices[9] = temp;
            float temp2 = vertices[3];
            vertices[3] = vertices[18];
            vertices[18] = vertices[13];
            vertices[13] = vertices[8];
            vertices[8] = temp2;
            return;
        }
        float temp3 = vertices[4];
        vertices[4] = vertices[9];
        vertices[9] = vertices[14];
        vertices[14] = vertices[19];
        vertices[19] = temp3;
        float temp4 = vertices[3];
        vertices[3] = vertices[8];
        vertices[8] = vertices[13];
        vertices[13] = vertices[18];
        vertices[18] = temp4;
    }

    public void setScale(float scaleXY) {
        this.scaleX = scaleXY;
        this.scaleY = scaleXY;
        this.dirty = true;
    }

    public void setScale(float scaleX, float scaleY) {
        this.scaleX = scaleX;
        this.scaleY = scaleY;
        this.dirty = true;
    }

    public void scale(float amount) {
        this.scaleX += amount;
        this.scaleY += amount;
        this.dirty = true;
    }

    public float[] getVertices() {
        if (this.dirty) {
            this.dirty = false;
            float[] vertices = this.vertices;
            float localX = -this.originX;
            float localY = -this.originY;
            float localX2 = this.width + localX;
            float localY2 = this.height + localY;
            float worldOriginX = this.x - localX;
            float worldOriginY = this.y - localY;
            if (this.scaleX != 1.0f || this.scaleY != 1.0f) {
                float f = this.scaleX;
                localX *= f;
                float f2 = this.scaleY;
                localY *= f2;
                localX2 *= f;
                localY2 *= f2;
            }
            float f3 = this.rotation;
            if (f3 != 0.0f) {
                float cos = MathUtils.cosDeg(f3);
                float sin = MathUtils.sinDeg(this.rotation);
                float localXCos = localX * cos;
                float localXSin = localX * sin;
                float localYCos = localY * cos;
                float localYSin = localY * sin;
                float localX2Cos = localX2 * cos;
                float localX2Sin = localX2 * sin;
                float localY2Cos = localY2 * cos;
                float localY2Sin = localY2 * sin;
                float x1 = (localXCos - localYSin) + worldOriginX;
                float y1 = localYCos + localXSin + worldOriginY;
                vertices[0] = x1;
                vertices[1] = y1;
                float x2 = (localXCos - localY2Sin) + worldOriginX;
                float y2 = localY2Cos + localXSin + worldOriginY;
                vertices[5] = x2;
                vertices[6] = y2;
                float x3 = (localX2Cos - localY2Sin) + worldOriginX;
                float y3 = localY2Cos + localX2Sin + worldOriginY;
                vertices[10] = x3;
                vertices[11] = y3;
                vertices[15] = x1 + (x3 - x2);
                vertices[16] = y3 - (y2 - y1);
            } else {
                float x12 = localX + worldOriginX;
                float y12 = localY + worldOriginY;
                float x22 = localX2 + worldOriginX;
                float y22 = localY2 + worldOriginY;
                vertices[0] = x12;
                vertices[1] = y12;
                vertices[5] = x12;
                vertices[6] = y22;
                vertices[10] = x22;
                vertices[11] = y22;
                vertices[15] = x22;
                vertices[16] = y12;
            }
        }
        return this.vertices;
    }

    public Rectangle getBoundingRectangle() {
        float[] vertices = getVertices();
        float minx = vertices[0];
        float miny = vertices[1];
        float maxx = vertices[0];
        float maxy = vertices[1];
        float minx2 = minx > vertices[5] ? vertices[5] : minx;
        float minx3 = minx2 > vertices[10] ? vertices[10] : minx2;
        float minx4 = minx3 > vertices[15] ? vertices[15] : minx3;
        float maxx2 = maxx < vertices[5] ? vertices[5] : maxx;
        float maxx3 = maxx2 < vertices[10] ? vertices[10] : maxx2;
        float maxx4 = maxx3 < vertices[15] ? vertices[15] : maxx3;
        float miny2 = miny > vertices[6] ? vertices[6] : miny;
        float miny3 = miny2 > vertices[11] ? vertices[11] : miny2;
        float miny4 = miny3 > vertices[16] ? vertices[16] : miny3;
        float maxy2 = maxy < vertices[6] ? vertices[6] : maxy;
        float maxy3 = maxy2 < vertices[11] ? vertices[11] : maxy2;
        float maxy4 = maxy3 < vertices[16] ? vertices[16] : maxy3;
        if (this.bounds == null) {
            this.bounds = new Rectangle();
        }
        Rectangle rectangle = this.bounds;
        rectangle.x = minx4;
        rectangle.y = miny4;
        rectangle.width = maxx4 - minx4;
        rectangle.height = maxy4 - miny4;
        return rectangle;
    }

    public void draw(Batch batch) {
        batch.draw(this.texture, getVertices(), 0, 20);
    }

    public void draw(Batch batch, float alphaModulation) {
        float oldAlpha = getColor().a;
        setAlpha(oldAlpha * alphaModulation);
        draw(batch);
        setAlpha(oldAlpha);
    }

    public float getX() {
        return this.x;
    }

    public float getY() {
        return this.y;
    }

    public float getWidth() {
        return this.width;
    }

    public float getHeight() {
        return this.height;
    }

    public float getOriginX() {
        return this.originX;
    }

    public float getOriginY() {
        return this.originY;
    }

    public float getScaleX() {
        return this.scaleX;
    }

    public float getScaleY() {
        return this.scaleY;
    }

    public Color getColor() {
        int intBits = NumberUtils.floatToIntColor(this.vertices[2]);
        Color color = this.color;
        color.r = (intBits & 255) / 255.0f;
        color.g = ((intBits >>> 8) & 255) / 255.0f;
        color.b = ((intBits >>> 16) & 255) / 255.0f;
        color.a = ((intBits >>> 24) & 255) / 255.0f;
        return color;
    }

    @Override // com.badlogic.gdx.graphics.g2d.TextureRegion
    public void setRegion(float u, float v, float u2, float v2) {
        super.setRegion(u, v, u2, v2);
        float[] vertices = this.vertices;
        vertices[3] = u;
        vertices[4] = v2;
        vertices[8] = u;
        vertices[9] = v;
        vertices[13] = u2;
        vertices[14] = v;
        vertices[18] = u2;
        vertices[19] = v2;
    }

    @Override // com.badlogic.gdx.graphics.g2d.TextureRegion
    public void setU(float u) {
        super.setU(u);
        float[] fArr = this.vertices;
        fArr[3] = u;
        fArr[8] = u;
    }

    @Override // com.badlogic.gdx.graphics.g2d.TextureRegion
    public void setV(float v) {
        super.setV(v);
        float[] fArr = this.vertices;
        fArr[9] = v;
        fArr[14] = v;
    }

    @Override // com.badlogic.gdx.graphics.g2d.TextureRegion
    public void setU2(float u2) {
        super.setU2(u2);
        float[] fArr = this.vertices;
        fArr[13] = u2;
        fArr[18] = u2;
    }

    @Override // com.badlogic.gdx.graphics.g2d.TextureRegion
    public void setV2(float v2) {
        super.setV2(v2);
        float[] fArr = this.vertices;
        fArr[4] = v2;
        fArr[19] = v2;
    }

    public void setFlip(boolean x, boolean y) {
        boolean performX = false;
        boolean performY = false;
        if (isFlipX() != x) {
            performX = true;
        }
        if (isFlipY() != y) {
            performY = true;
        }
        flip(performX, performY);
    }

    @Override // com.badlogic.gdx.graphics.g2d.TextureRegion
    public void flip(boolean x, boolean y) {
        super.flip(x, y);
        float[] vertices = this.vertices;
        if (x) {
            float temp = vertices[3];
            vertices[3] = vertices[13];
            vertices[13] = temp;
            float temp2 = vertices[8];
            vertices[8] = vertices[18];
            vertices[18] = temp2;
        }
        if (y) {
            float temp3 = vertices[4];
            vertices[4] = vertices[14];
            vertices[14] = temp3;
            float temp4 = vertices[9];
            vertices[9] = vertices[19];
            vertices[19] = temp4;
        }
    }

    @Override // com.badlogic.gdx.graphics.g2d.TextureRegion
    public void scroll(float xAmount, float yAmount) {
        float[] vertices = this.vertices;
        if (xAmount != 0.0f) {
            float u = (vertices[3] + xAmount) % 1.0f;
            float u2 = (this.width / this.texture.getWidth()) + u;
            this.u = u;
            this.u2 = u2;
            vertices[3] = u;
            vertices[8] = u;
            vertices[13] = u2;
            vertices[18] = u2;
        }
        if (yAmount != 0.0f) {
            float v = (vertices[9] + yAmount) % 1.0f;
            float v2 = (this.height / this.texture.getHeight()) + v;
            this.v = v;
            this.v2 = v2;
            vertices[4] = v2;
            vertices[9] = v;
            vertices[14] = v;
            vertices[19] = v2;
        }
    }
}