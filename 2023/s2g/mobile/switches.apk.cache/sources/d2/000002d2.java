package com.badlogic.gdx.math;

import com.badlogic.gdx.math.Vector;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.GdxRuntimeException;

/* loaded from: classes.dex */
public class Bezier<T extends Vector<T>> implements Path<T> {
    public Array<T> points = new Array<>();
    private T tmp;
    private T tmp2;
    private T tmp3;

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.badlogic.gdx.math.Path
    public /* bridge */ /* synthetic */ float approximate(Object obj) {
        return approximate((Bezier<T>) ((Vector) obj));
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.badlogic.gdx.math.Path
    public /* bridge */ /* synthetic */ Object derivativeAt(Object obj, float f) {
        return derivativeAt((Bezier<T>) ((Vector) obj), f);
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.badlogic.gdx.math.Path
    public /* bridge */ /* synthetic */ float locate(Object obj) {
        return locate((Bezier<T>) ((Vector) obj));
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.badlogic.gdx.math.Path
    public /* bridge */ /* synthetic */ Object valueAt(Object obj, float f) {
        return valueAt((Bezier<T>) ((Vector) obj), f);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static <T extends Vector<T>> T linear(T out, float t, T p0, T p1, T tmp) {
        return (T) out.set(p0).scl(1.0f - t).add(tmp.set(p1).scl(t));
    }

    public static <T extends Vector<T>> T linear_derivative(T out, float t, T p0, T p1, T tmp) {
        return (T) out.set(p1).sub(p0);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static <T extends Vector<T>> T quadratic(T out, float t, T p0, T p1, T p2, T tmp) {
        float dt = 1.0f - t;
        return (T) out.set(p0).scl(dt * dt).add(tmp.set(p1).scl(2.0f * dt * t)).add(tmp.set(p2).scl(t * t));
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static <T extends Vector<T>> T quadratic_derivative(T out, float t, T p0, T p1, T p2, T tmp) {
        float f = 1.0f - t;
        return (T) out.set(p1).sub(p0).scl(2.0f).scl(1.0f - t).add(tmp.set(p2).sub(p1).scl(t).scl(2.0f));
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static <T extends Vector<T>> T cubic(T out, float t, T p0, T p1, T p2, T p3, T tmp) {
        float dt = 1.0f - t;
        float dt2 = dt * dt;
        float t2 = t * t;
        return (T) out.set(p0).scl(dt2 * dt).add(tmp.set(p1).scl(dt2 * 3.0f * t)).add(tmp.set(p2).scl(3.0f * dt * t2)).add(tmp.set(p3).scl(t2 * t));
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static <T extends Vector<T>> T cubic_derivative(T out, float t, T p0, T p1, T p2, T p3, T tmp) {
        float dt = 1.0f - t;
        float dt2 = dt * dt;
        float t2 = t * t;
        return (T) out.set(p1).sub(p0).scl(dt2 * 3.0f).add(tmp.set(p2).sub(p1).scl(dt * t * 6.0f)).add(tmp.set(p3).sub(p2).scl(3.0f * t2));
    }

    public Bezier() {
    }

    public Bezier(T... points) {
        set(points);
    }

    public Bezier(T[] points, int offset, int length) {
        set(points, offset, length);
    }

    public Bezier(Array<T> points, int offset, int length) {
        set(points, offset, length);
    }

    public Bezier set(T... points) {
        return set(points, 0, points.length);
    }

    public Bezier set(T[] points, int offset, int length) {
        if (length < 2 || length > 4) {
            throw new GdxRuntimeException("Only first, second and third degree Bezier curves are supported.");
        }
        if (this.tmp == null) {
            this.tmp = (T) points[0].cpy();
        }
        if (this.tmp2 == null) {
            this.tmp2 = (T) points[0].cpy();
        }
        if (this.tmp3 == null) {
            this.tmp3 = (T) points[0].cpy();
        }
        this.points.clear();
        this.points.addAll(points, offset, length);
        return this;
    }

    public Bezier set(Array<T> points, int offset, int length) {
        if (length < 2 || length > 4) {
            throw new GdxRuntimeException("Only first, second and third degree Bezier curves are supported.");
        }
        if (this.tmp == null) {
            this.tmp = (T) points.get(0).cpy();
        }
        if (this.tmp2 == null) {
            this.tmp2 = (T) points.get(0).cpy();
        }
        if (this.tmp3 == null) {
            this.tmp3 = (T) points.get(0).cpy();
        }
        this.points.clear();
        this.points.addAll(points, offset, length);
        return this;
    }

    public T valueAt(T out, float t) {
        int n = this.points.size;
        if (n == 2) {
            linear(out, t, this.points.get(0), this.points.get(1), this.tmp);
        } else if (n == 3) {
            quadratic(out, t, this.points.get(0), this.points.get(1), this.points.get(2), this.tmp);
        } else if (n == 4) {
            cubic(out, t, this.points.get(0), this.points.get(1), this.points.get(2), this.points.get(3), this.tmp);
        }
        return out;
    }

    public T derivativeAt(T out, float t) {
        int n = this.points.size;
        if (n == 2) {
            linear_derivative(out, t, this.points.get(0), this.points.get(1), this.tmp);
        } else if (n == 3) {
            quadratic_derivative(out, t, this.points.get(0), this.points.get(1), this.points.get(2), this.tmp);
        } else if (n == 4) {
            cubic_derivative(out, t, this.points.get(0), this.points.get(1), this.points.get(2), this.points.get(3), this.tmp);
        }
        return out;
    }

    public float approximate(T v) {
        T p1 = this.points.get(0);
        Array<T> array = this.points;
        T p2 = array.get(array.size - 1);
        float l1Sqr = p1.dst2(p2);
        float l2Sqr = v.dst2(p2);
        float l3Sqr = v.dst2(p1);
        float l1 = (float) Math.sqrt(l1Sqr);
        float s = ((l2Sqr + l1Sqr) - l3Sqr) / (2.0f * l1);
        return MathUtils.clamp((l1 - s) / l1, 0.0f, 1.0f);
    }

    public float locate(T v) {
        return approximate((Bezier<T>) v);
    }

    @Override // com.badlogic.gdx.math.Path
    public float approxLength(int samples) {
        float tempLength = 0.0f;
        for (int i = 0; i < samples; i++) {
            this.tmp2.set(this.tmp3);
            valueAt((Bezier<T>) this.tmp3, i / (samples - 1.0f));
            if (i > 0) {
                tempLength += this.tmp2.dst(this.tmp3);
            }
        }
        return tempLength;
    }
}