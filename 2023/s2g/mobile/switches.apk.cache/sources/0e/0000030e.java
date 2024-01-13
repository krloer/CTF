package com.badlogic.gdx.math;

import com.badlogic.gdx.utils.GdxRuntimeException;
import com.badlogic.gdx.utils.NumberUtils;
import java.io.Serializable;

/* loaded from: classes.dex */
public class Rectangle implements Serializable, Shape2D {
    private static final long serialVersionUID = 5733252015138115702L;
    public static final Rectangle tmp = new Rectangle();
    public static final Rectangle tmp2 = new Rectangle();
    public float height;
    public float width;
    public float x;
    public float y;

    public Rectangle() {
    }

    public Rectangle(float x, float y, float width, float height) {
        this.x = x;
        this.y = y;
        this.width = width;
        this.height = height;
    }

    public Rectangle(Rectangle rect) {
        this.x = rect.x;
        this.y = rect.y;
        this.width = rect.width;
        this.height = rect.height;
    }

    public Rectangle set(float x, float y, float width, float height) {
        this.x = x;
        this.y = y;
        this.width = width;
        this.height = height;
        return this;
    }

    public float getX() {
        return this.x;
    }

    public Rectangle setX(float x) {
        this.x = x;
        return this;
    }

    public float getY() {
        return this.y;
    }

    public Rectangle setY(float y) {
        this.y = y;
        return this;
    }

    public float getWidth() {
        return this.width;
    }

    public Rectangle setWidth(float width) {
        this.width = width;
        return this;
    }

    public float getHeight() {
        return this.height;
    }

    public Rectangle setHeight(float height) {
        this.height = height;
        return this;
    }

    public Vector2 getPosition(Vector2 position) {
        return position.set(this.x, this.y);
    }

    public Rectangle setPosition(Vector2 position) {
        this.x = position.x;
        this.y = position.y;
        return this;
    }

    public Rectangle setPosition(float x, float y) {
        this.x = x;
        this.y = y;
        return this;
    }

    public Rectangle setSize(float width, float height) {
        this.width = width;
        this.height = height;
        return this;
    }

    public Rectangle setSize(float sizeXY) {
        this.width = sizeXY;
        this.height = sizeXY;
        return this;
    }

    public Vector2 getSize(Vector2 size) {
        return size.set(this.width, this.height);
    }

    @Override // com.badlogic.gdx.math.Shape2D
    public boolean contains(float x, float y) {
        float f = this.x;
        if (f <= x && f + this.width >= x) {
            float f2 = this.y;
            if (f2 <= y && f2 + this.height >= y) {
                return true;
            }
        }
        return false;
    }

    @Override // com.badlogic.gdx.math.Shape2D
    public boolean contains(Vector2 point) {
        return contains(point.x, point.y);
    }

    public boolean contains(Circle circle) {
        return circle.x - circle.radius >= this.x && circle.x + circle.radius <= this.x + this.width && circle.y - circle.radius >= this.y && circle.y + circle.radius <= this.y + this.height;
    }

    public boolean contains(Rectangle rectangle) {
        float xmin = rectangle.x;
        float xmax = rectangle.width + xmin;
        float ymin = rectangle.y;
        float ymax = rectangle.height + ymin;
        float f = this.x;
        if (xmin > f) {
            float f2 = this.width;
            if (xmin < f + f2 && xmax > f && xmax < f + f2) {
                float f3 = this.y;
                if (ymin > f3) {
                    float f4 = this.height;
                    if (ymin < f3 + f4 && ymax > f3 && ymax < f3 + f4) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    public boolean overlaps(Rectangle r) {
        float f = this.x;
        float f2 = r.x;
        if (f < r.width + f2 && f + this.width > f2) {
            float f3 = this.y;
            float f4 = r.y;
            if (f3 < r.height + f4 && f3 + this.height > f4) {
                return true;
            }
        }
        return false;
    }

    public Rectangle set(Rectangle rect) {
        this.x = rect.x;
        this.y = rect.y;
        this.width = rect.width;
        this.height = rect.height;
        return this;
    }

    public Rectangle merge(Rectangle rect) {
        float minX = Math.min(this.x, rect.x);
        float maxX = Math.max(this.x + this.width, rect.x + rect.width);
        this.x = minX;
        this.width = maxX - minX;
        float minY = Math.min(this.y, rect.y);
        float maxY = Math.max(this.y + this.height, rect.y + rect.height);
        this.y = minY;
        this.height = maxY - minY;
        return this;
    }

    public Rectangle merge(float x, float y) {
        float minX = Math.min(this.x, x);
        float maxX = Math.max(this.x + this.width, x);
        this.x = minX;
        this.width = maxX - minX;
        float minY = Math.min(this.y, y);
        float maxY = Math.max(this.y + this.height, y);
        this.y = minY;
        this.height = maxY - minY;
        return this;
    }

    public Rectangle merge(Vector2 vec) {
        return merge(vec.x, vec.y);
    }

    public Rectangle merge(Vector2[] vecs) {
        float minX = this.x;
        float maxX = this.x + this.width;
        float minY = this.y;
        float maxY = this.y + this.height;
        for (Vector2 v : vecs) {
            minX = Math.min(minX, v.x);
            maxX = Math.max(maxX, v.x);
            minY = Math.min(minY, v.y);
            maxY = Math.max(maxY, v.y);
        }
        this.x = minX;
        this.width = maxX - minX;
        this.y = minY;
        this.height = maxY - minY;
        return this;
    }

    public float getAspectRatio() {
        float f = this.height;
        if (f == 0.0f) {
            return Float.NaN;
        }
        return this.width / f;
    }

    public Vector2 getCenter(Vector2 vector) {
        vector.x = this.x + (this.width / 2.0f);
        vector.y = this.y + (this.height / 2.0f);
        return vector;
    }

    public Rectangle setCenter(float x, float y) {
        setPosition(x - (this.width / 2.0f), y - (this.height / 2.0f));
        return this;
    }

    public Rectangle setCenter(Vector2 position) {
        setPosition(position.x - (this.width / 2.0f), position.y - (this.height / 2.0f));
        return this;
    }

    public Rectangle fitOutside(Rectangle rect) {
        float ratio = getAspectRatio();
        if (ratio > rect.getAspectRatio()) {
            float f = rect.height;
            setSize(f * ratio, f);
        } else {
            float f2 = rect.width;
            setSize(f2, f2 / ratio);
        }
        setPosition((rect.x + (rect.width / 2.0f)) - (this.width / 2.0f), (rect.y + (rect.height / 2.0f)) - (this.height / 2.0f));
        return this;
    }

    public Rectangle fitInside(Rectangle rect) {
        float ratio = getAspectRatio();
        if (ratio < rect.getAspectRatio()) {
            float f = rect.height;
            setSize(f * ratio, f);
        } else {
            float f2 = rect.width;
            setSize(f2, f2 / ratio);
        }
        setPosition((rect.x + (rect.width / 2.0f)) - (this.width / 2.0f), (rect.y + (rect.height / 2.0f)) - (this.height / 2.0f));
        return this;
    }

    public String toString() {
        return "[" + this.x + "," + this.y + "," + this.width + "," + this.height + "]";
    }

    public Rectangle fromString(String v) {
        int s0 = v.indexOf(44, 1);
        int s1 = v.indexOf(44, s0 + 1);
        int s2 = v.indexOf(44, s1 + 1);
        if (s0 != -1 && s1 != -1 && s2 != -1 && v.charAt(0) == '[' && v.charAt(v.length() - 1) == ']') {
            try {
                float x = Float.parseFloat(v.substring(1, s0));
                float y = Float.parseFloat(v.substring(s0 + 1, s1));
                float width = Float.parseFloat(v.substring(s1 + 1, s2));
                float height = Float.parseFloat(v.substring(s2 + 1, v.length() - 1));
                return set(x, y, width, height);
            } catch (NumberFormatException e) {
            }
        }
        throw new GdxRuntimeException("Malformed Rectangle: " + v);
    }

    public float area() {
        return this.width * this.height;
    }

    public float perimeter() {
        return (this.width + this.height) * 2.0f;
    }

    public int hashCode() {
        int result = (1 * 31) + NumberUtils.floatToRawIntBits(this.height);
        return (((((result * 31) + NumberUtils.floatToRawIntBits(this.width)) * 31) + NumberUtils.floatToRawIntBits(this.x)) * 31) + NumberUtils.floatToRawIntBits(this.y);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        Rectangle other = (Rectangle) obj;
        if (NumberUtils.floatToRawIntBits(this.height) == NumberUtils.floatToRawIntBits(other.height) && NumberUtils.floatToRawIntBits(this.width) == NumberUtils.floatToRawIntBits(other.width) && NumberUtils.floatToRawIntBits(this.x) == NumberUtils.floatToRawIntBits(other.x) && NumberUtils.floatToRawIntBits(this.y) == NumberUtils.floatToRawIntBits(other.y)) {
            return true;
        }
        return false;
    }
}