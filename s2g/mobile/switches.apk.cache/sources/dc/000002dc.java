package com.badlogic.gdx.math;

import com.badlogic.gdx.utils.NumberUtils;
import java.io.Serializable;

/* loaded from: classes.dex */
public class Ellipse implements Serializable, Shape2D {
    private static final long serialVersionUID = 7381533206532032099L;
    public float height;
    public float width;
    public float x;
    public float y;

    public Ellipse() {
    }

    public Ellipse(Ellipse ellipse) {
        this.x = ellipse.x;
        this.y = ellipse.y;
        this.width = ellipse.width;
        this.height = ellipse.height;
    }

    public Ellipse(float x, float y, float width, float height) {
        this.x = x;
        this.y = y;
        this.width = width;
        this.height = height;
    }

    public Ellipse(Vector2 position, float width, float height) {
        this.x = position.x;
        this.y = position.y;
        this.width = width;
        this.height = height;
    }

    public Ellipse(Vector2 position, Vector2 size) {
        this.x = position.x;
        this.y = position.y;
        this.width = size.x;
        this.height = size.y;
    }

    public Ellipse(Circle circle) {
        this.x = circle.x;
        this.y = circle.y;
        this.width = circle.radius * 2.0f;
        this.height = circle.radius * 2.0f;
    }

    @Override // com.badlogic.gdx.math.Shape2D
    public boolean contains(float x, float y) {
        float x2 = x - this.x;
        float y2 = y - this.y;
        float f = this.width;
        float f2 = (x2 * x2) / (((f * 0.5f) * f) * 0.5f);
        float f3 = this.height;
        return f2 + ((y2 * y2) / (((f3 * 0.5f) * f3) * 0.5f)) <= 1.0f;
    }

    @Override // com.badlogic.gdx.math.Shape2D
    public boolean contains(Vector2 point) {
        return contains(point.x, point.y);
    }

    public void set(float x, float y, float width, float height) {
        this.x = x;
        this.y = y;
        this.width = width;
        this.height = height;
    }

    public void set(Ellipse ellipse) {
        this.x = ellipse.x;
        this.y = ellipse.y;
        this.width = ellipse.width;
        this.height = ellipse.height;
    }

    public void set(Circle circle) {
        this.x = circle.x;
        this.y = circle.y;
        this.width = circle.radius * 2.0f;
        this.height = circle.radius * 2.0f;
    }

    public void set(Vector2 position, Vector2 size) {
        this.x = position.x;
        this.y = position.y;
        this.width = size.x;
        this.height = size.y;
    }

    public Ellipse setPosition(Vector2 position) {
        this.x = position.x;
        this.y = position.y;
        return this;
    }

    public Ellipse setPosition(float x, float y) {
        this.x = x;
        this.y = y;
        return this;
    }

    public Ellipse setSize(float width, float height) {
        this.width = width;
        this.height = height;
        return this;
    }

    public float area() {
        return ((this.width * this.height) * 3.1415927f) / 4.0f;
    }

    public float circumference() {
        float a = this.width / 2.0f;
        float b = this.height / 2.0f;
        if (a * 3.0f > b || b * 3.0f > a) {
            double d = (a + b) * 3.0f;
            double sqrt = Math.sqrt(((a * 3.0f) + b) * ((3.0f * b) + a));
            Double.isNaN(d);
            return (float) ((d - sqrt) * 3.1415927410125732d);
        }
        return (float) (Math.sqrt(((a * a) + (b * b)) / 2.0f) * 6.2831854820251465d);
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (o == null || o.getClass() != getClass()) {
            return false;
        }
        Ellipse e = (Ellipse) o;
        return this.x == e.x && this.y == e.y && this.width == e.width && this.height == e.height;
    }

    public int hashCode() {
        int result = (1 * 53) + NumberUtils.floatToRawIntBits(this.height);
        return (((((result * 53) + NumberUtils.floatToRawIntBits(this.width)) * 53) + NumberUtils.floatToRawIntBits(this.x)) * 53) + NumberUtils.floatToRawIntBits(this.y);
    }
}