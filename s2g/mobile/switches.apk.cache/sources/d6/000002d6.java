package com.badlogic.gdx.math;

import com.badlogic.gdx.utils.NumberUtils;
import java.io.Serializable;

/* loaded from: classes.dex */
public class Circle implements Serializable, Shape2D {
    public float radius;
    public float x;
    public float y;

    public Circle() {
    }

    public Circle(float x, float y, float radius) {
        this.x = x;
        this.y = y;
        this.radius = radius;
    }

    public Circle(Vector2 position, float radius) {
        this.x = position.x;
        this.y = position.y;
        this.radius = radius;
    }

    public Circle(Circle circle) {
        this.x = circle.x;
        this.y = circle.y;
        this.radius = circle.radius;
    }

    public Circle(Vector2 center, Vector2 edge) {
        this.x = center.x;
        this.y = center.y;
        this.radius = Vector2.len(center.x - edge.x, center.y - edge.y);
    }

    public void set(float x, float y, float radius) {
        this.x = x;
        this.y = y;
        this.radius = radius;
    }

    public void set(Vector2 position, float radius) {
        this.x = position.x;
        this.y = position.y;
        this.radius = radius;
    }

    public void set(Circle circle) {
        this.x = circle.x;
        this.y = circle.y;
        this.radius = circle.radius;
    }

    public void set(Vector2 center, Vector2 edge) {
        this.x = center.x;
        this.y = center.y;
        this.radius = Vector2.len(center.x - edge.x, center.y - edge.y);
    }

    public void setPosition(Vector2 position) {
        this.x = position.x;
        this.y = position.y;
    }

    public void setPosition(float x, float y) {
        this.x = x;
        this.y = y;
    }

    public void setX(float x) {
        this.x = x;
    }

    public void setY(float y) {
        this.y = y;
    }

    public void setRadius(float radius) {
        this.radius = radius;
    }

    @Override // com.badlogic.gdx.math.Shape2D
    public boolean contains(float x, float y) {
        float x2 = this.x - x;
        float x3 = this.y;
        float y2 = x3 - y;
        float y3 = x2 * x2;
        float f = y3 + (y2 * y2);
        float f2 = this.radius;
        return f <= f2 * f2;
    }

    @Override // com.badlogic.gdx.math.Shape2D
    public boolean contains(Vector2 point) {
        float dx = this.x - point.x;
        float dy = this.y - point.y;
        float f = (dx * dx) + (dy * dy);
        float f2 = this.radius;
        return f <= f2 * f2;
    }

    public boolean contains(Circle c) {
        float f = this.radius;
        float f2 = c.radius;
        float radiusDiff = f - f2;
        if (radiusDiff < 0.0f) {
            return false;
        }
        float dx = this.x - c.x;
        float dy = this.y - c.y;
        float dst = (dx * dx) + (dy * dy);
        float radiusSum = f + f2;
        return radiusDiff * radiusDiff >= dst && dst < radiusSum * radiusSum;
    }

    public boolean overlaps(Circle c) {
        float dx = this.x - c.x;
        float dy = this.y - c.y;
        float distance = (dx * dx) + (dy * dy);
        float radiusSum = this.radius + c.radius;
        return distance < radiusSum * radiusSum;
    }

    public String toString() {
        return this.x + "," + this.y + "," + this.radius;
    }

    public float circumference() {
        return this.radius * 6.2831855f;
    }

    public float area() {
        float f = this.radius;
        return f * f * 3.1415927f;
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (o == null || o.getClass() != getClass()) {
            return false;
        }
        Circle c = (Circle) o;
        return this.x == c.x && this.y == c.y && this.radius == c.radius;
    }

    public int hashCode() {
        int result = (1 * 41) + NumberUtils.floatToRawIntBits(this.radius);
        return (((result * 41) + NumberUtils.floatToRawIntBits(this.x)) * 41) + NumberUtils.floatToRawIntBits(this.y);
    }
}