package com.badlogic.gdx.math;

import java.io.Serializable;

/* loaded from: classes.dex */
public class Plane implements Serializable {
    private static final long serialVersionUID = -1240652082930747866L;
    public float d;
    public final Vector3 normal;

    /* loaded from: classes.dex */
    public enum PlaneSide {
        OnPlane,
        Back,
        Front
    }

    public Plane() {
        this.normal = new Vector3();
        this.d = 0.0f;
    }

    public Plane(Vector3 normal, float d) {
        this.normal = new Vector3();
        this.d = 0.0f;
        this.normal.set(normal).nor();
        this.d = d;
    }

    public Plane(Vector3 normal, Vector3 point) {
        this.normal = new Vector3();
        this.d = 0.0f;
        this.normal.set(normal).nor();
        this.d = -this.normal.dot(point);
    }

    public Plane(Vector3 point1, Vector3 point2, Vector3 point3) {
        this.normal = new Vector3();
        this.d = 0.0f;
        set(point1, point2, point3);
    }

    public void set(Vector3 point1, Vector3 point2, Vector3 point3) {
        this.normal.set(point1).sub(point2).crs(point2.x - point3.x, point2.y - point3.y, point2.z - point3.z).nor();
        this.d = -point1.dot(this.normal);
    }

    public void set(float nx, float ny, float nz, float d) {
        this.normal.set(nx, ny, nz);
        this.d = d;
    }

    public float distance(Vector3 point) {
        return this.normal.dot(point) + this.d;
    }

    public PlaneSide testPoint(Vector3 point) {
        float dist = this.normal.dot(point) + this.d;
        if (dist == 0.0f) {
            return PlaneSide.OnPlane;
        }
        if (dist < 0.0f) {
            return PlaneSide.Back;
        }
        return PlaneSide.Front;
    }

    public PlaneSide testPoint(float x, float y, float z) {
        float dist = this.normal.dot(x, y, z) + this.d;
        if (dist == 0.0f) {
            return PlaneSide.OnPlane;
        }
        if (dist < 0.0f) {
            return PlaneSide.Back;
        }
        return PlaneSide.Front;
    }

    public boolean isFrontFacing(Vector3 direction) {
        float dot = this.normal.dot(direction);
        return dot <= 0.0f;
    }

    public Vector3 getNormal() {
        return this.normal;
    }

    public float getD() {
        return this.d;
    }

    public void set(Vector3 point, Vector3 normal) {
        this.normal.set(normal);
        this.d = -point.dot(normal);
    }

    public void set(float pointX, float pointY, float pointZ, float norX, float norY, float norZ) {
        this.normal.set(norX, norY, norZ);
        this.d = -((pointX * norX) + (pointY * norY) + (pointZ * norZ));
    }

    public void set(Plane plane) {
        this.normal.set(plane.normal);
        this.d = plane.d;
    }

    public String toString() {
        return this.normal.toString() + ", " + this.d;
    }
}