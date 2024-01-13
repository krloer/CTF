package com.badlogic.gdx.math;

/* loaded from: classes.dex */
public class Polyline implements Shape2D {
    private boolean calculateLength;
    private boolean calculateScaledLength;
    private boolean dirty;
    private float length;
    private float[] localVertices;
    private float originX;
    private float originY;
    private float rotation;
    private float scaleX;
    private float scaleY;
    private float scaledLength;
    private float[] worldVertices;
    private float x;
    private float y;

    public Polyline() {
        this.scaleX = 1.0f;
        this.scaleY = 1.0f;
        this.calculateScaledLength = true;
        this.calculateLength = true;
        this.dirty = true;
        this.localVertices = new float[0];
    }

    public Polyline(float[] vertices) {
        this.scaleX = 1.0f;
        this.scaleY = 1.0f;
        this.calculateScaledLength = true;
        this.calculateLength = true;
        this.dirty = true;
        if (vertices.length < 4) {
            throw new IllegalArgumentException("polylines must contain at least 2 points.");
        }
        this.localVertices = vertices;
    }

    public float[] getVertices() {
        return this.localVertices;
    }

    public float[] getTransformedVertices() {
        if (!this.dirty) {
            return this.worldVertices;
        }
        boolean scale = false;
        this.dirty = false;
        float[] localVertices = this.localVertices;
        float[] fArr = this.worldVertices;
        if (fArr == null || fArr.length < localVertices.length) {
            this.worldVertices = new float[localVertices.length];
        }
        float[] worldVertices = this.worldVertices;
        float positionX = this.x;
        float positionY = this.y;
        float originX = this.originX;
        float originY = this.originY;
        float scaleX = this.scaleX;
        float scaleY = this.scaleY;
        scale = (scaleX == 1.0f && scaleY == 1.0f) ? true : true;
        float rotation = this.rotation;
        float cos = MathUtils.cosDeg(rotation);
        float sin = MathUtils.sinDeg(rotation);
        int n = localVertices.length;
        for (int i = 0; i < n; i += 2) {
            float x = localVertices[i] - originX;
            float y = localVertices[i + 1] - originY;
            if (scale) {
                x *= scaleX;
                y *= scaleY;
            }
            if (rotation != 0.0f) {
                float oldX = x;
                x = (cos * x) - (sin * y);
                y = (sin * oldX) + (cos * y);
            }
            float oldX2 = positionX + x;
            worldVertices[i] = oldX2 + originX;
            worldVertices[i + 1] = positionY + y + originY;
        }
        return worldVertices;
    }

    public float getLength() {
        if (this.calculateLength) {
            this.calculateLength = false;
            this.length = 0.0f;
            int n = this.localVertices.length - 2;
            for (int i = 0; i < n; i += 2) {
                float[] fArr = this.localVertices;
                float x = fArr[i + 2] - fArr[i];
                float y = fArr[i + 1] - fArr[i + 3];
                this.length += (float) Math.sqrt((x * x) + (y * y));
            }
            return this.length;
        }
        return this.length;
    }

    public float getScaledLength() {
        if (this.calculateScaledLength) {
            this.calculateScaledLength = false;
            this.scaledLength = 0.0f;
            int n = this.localVertices.length - 2;
            for (int i = 0; i < n; i += 2) {
                float[] fArr = this.localVertices;
                float f = fArr[i + 2];
                float f2 = this.scaleX;
                float x = (f * f2) - (fArr[i] * f2);
                float f3 = fArr[i + 1];
                float f4 = this.scaleY;
                float y = (f3 * f4) - (fArr[i + 3] * f4);
                this.scaledLength += (float) Math.sqrt((x * x) + (y * y));
            }
            return this.scaledLength;
        }
        return this.scaledLength;
    }

    public float getX() {
        return this.x;
    }

    public float getY() {
        return this.y;
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

    public void setOrigin(float originX, float originY) {
        this.originX = originX;
        this.originY = originY;
        this.dirty = true;
    }

    public void setPosition(float x, float y) {
        this.x = x;
        this.y = y;
        this.dirty = true;
    }

    public void setVertices(float[] vertices) {
        if (vertices.length < 4) {
            throw new IllegalArgumentException("polylines must contain at least 2 points.");
        }
        this.localVertices = vertices;
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

    public void setScale(float scaleX, float scaleY) {
        this.scaleX = scaleX;
        this.scaleY = scaleY;
        this.dirty = true;
        this.calculateScaledLength = true;
    }

    public void scale(float amount) {
        this.scaleX += amount;
        this.scaleY += amount;
        this.dirty = true;
        this.calculateScaledLength = true;
    }

    public void calculateLength() {
        this.calculateLength = true;
    }

    public void calculateScaledLength() {
        this.calculateScaledLength = true;
    }

    public void dirty() {
        this.dirty = true;
    }

    public void translate(float x, float y) {
        this.x += x;
        this.y += y;
        this.dirty = true;
    }

    @Override // com.badlogic.gdx.math.Shape2D
    public boolean contains(Vector2 point) {
        return false;
    }

    @Override // com.badlogic.gdx.math.Shape2D
    public boolean contains(float x, float y) {
        return false;
    }
}