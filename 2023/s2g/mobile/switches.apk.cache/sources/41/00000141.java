package com.badlogic.gdx.graphics.g2d;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.math.MathUtils;
import com.badlogic.gdx.math.Rectangle;

/* loaded from: classes.dex */
public class PolygonSprite {
    private boolean dirty;
    private float height;
    private float originX;
    private float originY;
    PolygonRegion region;
    private float rotation;
    private float[] vertices;
    private float width;
    private float x;
    private float y;
    private float scaleX = 1.0f;
    private float scaleY = 1.0f;
    private Rectangle bounds = new Rectangle();
    private final Color color = new Color(1.0f, 1.0f, 1.0f, 1.0f);

    public PolygonSprite(PolygonRegion region) {
        setRegion(region);
        setSize(region.region.regionWidth, region.region.regionHeight);
        setOrigin(this.width / 2.0f, this.height / 2.0f);
    }

    public PolygonSprite(PolygonSprite sprite) {
        set(sprite);
    }

    public void set(PolygonSprite sprite) {
        if (sprite == null) {
            throw new IllegalArgumentException("sprite cannot be null.");
        }
        setRegion(sprite.region);
        this.x = sprite.x;
        this.y = sprite.y;
        this.width = sprite.width;
        this.height = sprite.height;
        this.originX = sprite.originX;
        this.originY = sprite.originY;
        this.rotation = sprite.rotation;
        this.scaleX = sprite.scaleX;
        this.scaleY = sprite.scaleY;
        this.color.set(sprite.color);
    }

    public void setBounds(float x, float y, float width, float height) {
        this.x = x;
        this.y = y;
        this.width = width;
        this.height = height;
        this.dirty = true;
    }

    public void setSize(float width, float height) {
        this.width = width;
        this.height = height;
        this.dirty = true;
    }

    public void setPosition(float x, float y) {
        translate(x - this.x, y - this.y);
    }

    public void setX(float x) {
        translateX(x - this.x);
    }

    public void setY(float y) {
        translateY(y - this.y);
    }

    public void translateX(float xAmount) {
        this.x += xAmount;
        if (this.dirty) {
            return;
        }
        float[] vertices = this.vertices;
        for (int i = 0; i < vertices.length; i += 5) {
            vertices[i] = vertices[i] + xAmount;
        }
    }

    public void translateY(float yAmount) {
        this.y += yAmount;
        if (this.dirty) {
            return;
        }
        float[] vertices = this.vertices;
        for (int i = 1; i < vertices.length; i += 5) {
            vertices[i] = vertices[i] + yAmount;
        }
    }

    public void translate(float xAmount, float yAmount) {
        this.x += xAmount;
        this.y += yAmount;
        if (this.dirty) {
            return;
        }
        float[] vertices = this.vertices;
        for (int i = 0; i < vertices.length; i += 5) {
            vertices[i] = vertices[i] + xAmount;
            int i2 = i + 1;
            vertices[i2] = vertices[i2] + yAmount;
        }
    }

    public void setColor(Color tint) {
        this.color.set(tint);
        float color = tint.toFloatBits();
        float[] vertices = this.vertices;
        for (int i = 2; i < vertices.length; i += 5) {
            vertices[i] = color;
        }
    }

    public void setColor(float r, float g, float b, float a) {
        this.color.set(r, g, b, a);
        float packedColor = this.color.toFloatBits();
        float[] vertices = this.vertices;
        for (int i = 2; i < vertices.length; i += 5) {
            vertices[i] = packedColor;
        }
    }

    public void setOrigin(float originX, float originY) {
        this.originX = originX;
        this.originY = originY;
        this.dirty = true;
    }

    public void setRotation(float degrees) {
        this.rotation = degrees;
        this.dirty = true;
    }

    public void rotate(float degrees) {
        this.rotation += degrees;
        this.dirty = true;
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
        if (!this.dirty) {
            return this.vertices;
        }
        this.dirty = false;
        float originX = this.originX;
        float originY = this.originY;
        float scaleX = this.scaleX;
        float scaleY = this.scaleY;
        PolygonRegion region = this.region;
        float[] vertices = this.vertices;
        float[] regionVertices = region.vertices;
        float worldOriginX = this.x + originX;
        float worldOriginY = this.y + originY;
        float sX = this.width / region.region.getRegionWidth();
        float sY = this.height / region.region.getRegionHeight();
        float cos = MathUtils.cosDeg(this.rotation);
        float sin = MathUtils.sinDeg(this.rotation);
        int i = 0;
        int v = 0;
        int n = regionVertices.length;
        while (i < n) {
            float fx = ((regionVertices[i] * sX) - originX) * scaleX;
            float fy = ((regionVertices[i + 1] * sY) - originY) * scaleY;
            vertices[v] = ((cos * fx) - (sin * fy)) + worldOriginX;
            vertices[v + 1] = (sin * fx) + (cos * fy) + worldOriginY;
            i += 2;
            v += 5;
        }
        return vertices;
    }

    public Rectangle getBoundingRectangle() {
        float[] vertices = getVertices();
        float minx = vertices[0];
        float miny = vertices[1];
        float maxx = vertices[0];
        float maxy = vertices[1];
        for (int i = 5; i < vertices.length; i += 5) {
            float x = vertices[i];
            float y = vertices[i + 1];
            minx = minx > x ? x : minx;
            maxx = maxx < x ? x : maxx;
            miny = miny > y ? y : miny;
            maxy = maxy < y ? y : maxy;
        }
        Rectangle rectangle = this.bounds;
        rectangle.x = minx;
        rectangle.y = miny;
        rectangle.width = maxx - minx;
        rectangle.height = maxy - miny;
        return rectangle;
    }

    public void draw(PolygonSpriteBatch spriteBatch) {
        PolygonRegion region = this.region;
        spriteBatch.draw(region.region.texture, getVertices(), 0, this.vertices.length, region.triangles, 0, region.triangles.length);
    }

    public void draw(PolygonSpriteBatch spriteBatch, float alphaModulation) {
        Color color = getColor();
        float oldAlpha = color.a;
        color.a *= alphaModulation;
        setColor(color);
        draw(spriteBatch);
        color.a = oldAlpha;
        setColor(color);
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

    public float getRotation() {
        return this.rotation;
    }

    public float getScaleX() {
        return this.scaleX;
    }

    public float getScaleY() {
        return this.scaleY;
    }

    public Color getColor() {
        return this.color;
    }

    public Color getPackedColor() {
        Color.abgr8888ToColor(this.color, this.vertices[2]);
        return this.color;
    }

    public void setRegion(PolygonRegion region) {
        this.region = region;
        float[] regionVertices = region.vertices;
        float[] textureCoords = region.textureCoords;
        int verticesLength = (regionVertices.length / 2) * 5;
        float[] fArr = this.vertices;
        if (fArr == null || fArr.length != verticesLength) {
            this.vertices = new float[verticesLength];
        }
        float floatColor = this.color.toFloatBits();
        float[] vertices = this.vertices;
        int i = 0;
        for (int v = 2; v < verticesLength; v += 5) {
            vertices[v] = floatColor;
            vertices[v + 1] = textureCoords[i];
            vertices[v + 2] = textureCoords[i + 1];
            i += 2;
        }
        this.dirty = true;
    }

    public PolygonRegion getRegion() {
        return this.region;
    }
}