package com.badlogic.gdx.math;

import java.io.Serializable;

/* loaded from: classes.dex */
public class GridPoint3 implements Serializable {
    private static final long serialVersionUID = 5922187982746752830L;
    public int x;
    public int y;
    public int z;

    public GridPoint3() {
    }

    public GridPoint3(int x, int y, int z) {
        this.x = x;
        this.y = y;
        this.z = z;
    }

    public GridPoint3(GridPoint3 point) {
        this.x = point.x;
        this.y = point.y;
        this.z = point.z;
    }

    public GridPoint3 set(GridPoint3 point) {
        this.x = point.x;
        this.y = point.y;
        this.z = point.z;
        return this;
    }

    public GridPoint3 set(int x, int y, int z) {
        this.x = x;
        this.y = y;
        this.z = z;
        return this;
    }

    public float dst2(GridPoint3 other) {
        int xd = other.x - this.x;
        int yd = other.y - this.y;
        int zd = other.z - this.z;
        return (xd * xd) + (yd * yd) + (zd * zd);
    }

    public float dst2(int x, int y, int z) {
        int xd = x - this.x;
        int yd = y - this.y;
        int zd = z - this.z;
        return (xd * xd) + (yd * yd) + (zd * zd);
    }

    public float dst(GridPoint3 other) {
        int xd = other.x - this.x;
        int yd = other.y - this.y;
        int zd = other.z - this.z;
        return (float) Math.sqrt((xd * xd) + (yd * yd) + (zd * zd));
    }

    public float dst(int x, int y, int z) {
        int xd = x - this.x;
        int yd = y - this.y;
        int zd = z - this.z;
        return (float) Math.sqrt((xd * xd) + (yd * yd) + (zd * zd));
    }

    public GridPoint3 add(GridPoint3 other) {
        this.x += other.x;
        this.y += other.y;
        this.z += other.z;
        return this;
    }

    public GridPoint3 add(int x, int y, int z) {
        this.x += x;
        this.y += y;
        this.z += z;
        return this;
    }

    public GridPoint3 sub(GridPoint3 other) {
        this.x -= other.x;
        this.y -= other.y;
        this.z -= other.z;
        return this;
    }

    public GridPoint3 sub(int x, int y, int z) {
        this.x -= x;
        this.y -= y;
        this.z -= z;
        return this;
    }

    public GridPoint3 cpy() {
        return new GridPoint3(this);
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || o.getClass() != getClass()) {
            return false;
        }
        GridPoint3 g = (GridPoint3) o;
        return this.x == g.x && this.y == g.y && this.z == g.z;
    }

    public int hashCode() {
        int result = (1 * 17) + this.x;
        return (((result * 17) + this.y) * 17) + this.z;
    }

    public String toString() {
        return "(" + this.x + ", " + this.y + ", " + this.z + ")";
    }
}