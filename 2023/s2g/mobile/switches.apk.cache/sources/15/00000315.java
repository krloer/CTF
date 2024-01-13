package com.badlogic.gdx.math.collision;

import com.badlogic.gdx.math.Matrix4;
import com.badlogic.gdx.math.Vector3;
import java.io.Serializable;

/* loaded from: classes.dex */
public class Ray implements Serializable {
    private static final long serialVersionUID = -620692054835390878L;
    static Vector3 tmp = new Vector3();
    public final Vector3 origin = new Vector3();
    public final Vector3 direction = new Vector3();

    public Ray() {
    }

    public Ray(Vector3 origin, Vector3 direction) {
        this.origin.set(origin);
        this.direction.set(direction).nor();
    }

    public Ray cpy() {
        return new Ray(this.origin, this.direction);
    }

    public Vector3 getEndPoint(Vector3 out, float distance) {
        return out.set(this.direction).scl(distance).add(this.origin);
    }

    public Ray mul(Matrix4 matrix) {
        tmp.set(this.origin).add(this.direction);
        tmp.mul(matrix);
        this.origin.mul(matrix);
        this.direction.set(tmp.sub(this.origin)).nor();
        return this;
    }

    public String toString() {
        return "ray [" + this.origin + ":" + this.direction + "]";
    }

    public Ray set(Vector3 origin, Vector3 direction) {
        this.origin.set(origin);
        this.direction.set(direction).nor();
        return this;
    }

    public Ray set(float x, float y, float z, float dx, float dy, float dz) {
        this.origin.set(x, y, z);
        this.direction.set(dx, dy, dz).nor();
        return this;
    }

    public Ray set(Ray ray) {
        this.origin.set(ray.origin);
        this.direction.set(ray.direction).nor();
        return this;
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (o == null || o.getClass() != getClass()) {
            return false;
        }
        Ray r = (Ray) o;
        return this.direction.equals(r.direction) && this.origin.equals(r.origin);
    }

    public int hashCode() {
        int result = (1 * 73) + this.direction.hashCode();
        return (result * 73) + this.origin.hashCode();
    }
}