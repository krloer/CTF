package com.badlogic.gdx.math.collision;

import com.badlogic.gdx.math.Vector3;
import com.badlogic.gdx.utils.NumberUtils;
import java.io.Serializable;

/* loaded from: classes.dex */
public class Sphere implements Serializable {
    private static final float PI_4_3 = 4.1887903f;
    private static final long serialVersionUID = -6487336868908521596L;
    public final Vector3 center;
    public float radius;

    public Sphere(Vector3 center, float radius) {
        this.center = new Vector3(center);
        this.radius = radius;
    }

    public boolean overlaps(Sphere sphere) {
        float dst2 = this.center.dst2(sphere.center);
        float f = this.radius;
        float f2 = sphere.radius;
        return dst2 < (f + f2) * (f + f2);
    }

    public int hashCode() {
        int result = (1 * 71) + this.center.hashCode();
        return (result * 71) + NumberUtils.floatToRawIntBits(this.radius);
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || o.getClass() != getClass()) {
            return false;
        }
        Sphere s = (Sphere) o;
        return this.radius == s.radius && this.center.equals(s.center);
    }

    public float volume() {
        float f = this.radius;
        return PI_4_3 * f * f * f;
    }

    public float surfaceArea() {
        float f = this.radius;
        return 12.566371f * f * f;
    }
}