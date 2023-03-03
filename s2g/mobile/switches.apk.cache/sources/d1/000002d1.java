package com.badlogic.gdx.math;

import com.badlogic.gdx.math.Vector;
import com.badlogic.gdx.utils.Array;

/* loaded from: classes.dex */
public class BSpline<T extends Vector<T>> implements Path<T> {
    private static final float d6 = 0.16666667f;
    public boolean continuous;
    public T[] controlPoints;
    public int degree;
    public Array<T> knots;
    public int spanCount;
    private T tmp;
    private T tmp2;
    private T tmp3;

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.badlogic.gdx.math.Path
    public /* bridge */ /* synthetic */ float approximate(Object obj) {
        return approximate((BSpline<T>) ((Vector) obj));
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.badlogic.gdx.math.Path
    public /* bridge */ /* synthetic */ Object derivativeAt(Object obj, float f) {
        return derivativeAt((BSpline<T>) ((Vector) obj), f);
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.badlogic.gdx.math.Path
    public /* bridge */ /* synthetic */ float locate(Object obj) {
        return locate((BSpline<T>) ((Vector) obj));
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.badlogic.gdx.math.Path
    public /* bridge */ /* synthetic */ Object valueAt(Object obj, float f) {
        return valueAt((BSpline<T>) ((Vector) obj), f);
    }

    public static <T extends Vector<T>> T cubic(T out, float t, T[] points, boolean continuous, T tmp) {
        int n = points.length;
        if (!continuous) {
            n -= 3;
        }
        float u = n * t;
        int i = t >= 1.0f ? n - 1 : (int) u;
        return (T) cubic(out, i, u - i, points, continuous, tmp);
    }

    public static <T extends Vector<T>> T cubic_derivative(T out, float t, T[] points, boolean continuous, T tmp) {
        int n = points.length;
        if (!continuous) {
            n -= 3;
        }
        float u = n * t;
        int i = t >= 1.0f ? n - 1 : (int) u;
        return (T) cubic(out, i, u - i, points, continuous, tmp);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static <T extends Vector<T>> T cubic(T out, int i, float u, T[] points, boolean continuous, T tmp) {
        int n = points.length;
        float dt = 1.0f - u;
        float t2 = u * u;
        float t3 = t2 * u;
        out.set(points[i]).scl((((t3 * 3.0f) - (6.0f * t2)) + 4.0f) * d6);
        if (continuous || i > 0) {
            out.add(tmp.set(points[((n + i) - 1) % n]).scl(dt * dt * dt * d6));
        }
        if (continuous || i < n - 1) {
            out.add(tmp.set(points[(i + 1) % n]).scl((((-3.0f) * t3) + (t2 * 3.0f) + (3.0f * u) + 1.0f) * d6));
        }
        if (continuous || i < n - 2) {
            out.add(tmp.set(points[(i + 2) % n]).scl(d6 * t3));
        }
        return out;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static <T extends Vector<T>> T cubic_derivative(T out, int i, float u, T[] points, boolean continuous, T tmp) {
        int n = points.length;
        float dt = 1.0f - u;
        float t2 = u * u;
        float f = t2 * u;
        out.set(points[i]).scl((1.5f * t2) - (2.0f * u));
        if (continuous || i > 0) {
            out.add(tmp.set(points[((n + i) - 1) % n]).scl((-0.5f) * dt * dt));
        }
        if (continuous || i < n - 1) {
            out.add(tmp.set(points[(i + 1) % n]).scl(((-1.5f) * t2) + u + 0.5f));
        }
        if (continuous || i < n - 2) {
            out.add(tmp.set(points[(i + 2) % n]).scl(0.5f * t2));
        }
        return out;
    }

    public static <T extends Vector<T>> T calculate(T out, float t, T[] points, int degree, boolean continuous, T tmp) {
        int n = points.length;
        if (!continuous) {
            n -= degree;
        }
        float u = n * t;
        int i = t >= 1.0f ? n - 1 : (int) u;
        return (T) calculate(out, i, u - i, points, degree, continuous, tmp);
    }

    public static <T extends Vector<T>> T derivative(T out, float t, T[] points, int degree, boolean continuous, T tmp) {
        int n = points.length;
        if (!continuous) {
            n -= degree;
        }
        float u = n * t;
        int i = t >= 1.0f ? n - 1 : (int) u;
        return (T) derivative(out, i, u - i, points, degree, continuous, tmp);
    }

    public static <T extends Vector<T>> T calculate(T out, int i, float u, T[] points, int degree, boolean continuous, T tmp) {
        if (degree == 3) {
            return (T) cubic(out, i, u, points, continuous, tmp);
        }
        throw new IllegalArgumentException();
    }

    public static <T extends Vector<T>> T derivative(T out, int i, float u, T[] points, int degree, boolean continuous, T tmp) {
        if (degree == 3) {
            return (T) cubic_derivative(out, i, u, points, continuous, tmp);
        }
        throw new IllegalArgumentException();
    }

    public BSpline() {
    }

    public BSpline(T[] controlPoints, int degree, boolean continuous) {
        set(controlPoints, degree, continuous);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public BSpline set(T[] controlPoints, int degree, boolean continuous) {
        if (this.tmp == null) {
            this.tmp = (T) controlPoints[0].cpy();
        }
        if (this.tmp2 == null) {
            this.tmp2 = (T) controlPoints[0].cpy();
        }
        if (this.tmp3 == null) {
            this.tmp3 = (T) controlPoints[0].cpy();
        }
        this.controlPoints = controlPoints;
        this.degree = degree;
        this.continuous = continuous;
        int length = controlPoints.length;
        if (!continuous) {
            length -= degree;
        }
        this.spanCount = length;
        Array<T> array = this.knots;
        if (array == null) {
            this.knots = new Array<>(this.spanCount);
        } else {
            array.clear();
            this.knots.ensureCapacity(this.spanCount);
        }
        for (int i = 0; i < this.spanCount; i++) {
            this.knots.add(calculate(controlPoints[0].cpy(), continuous ? i : (int) (i + (degree * 0.5f)), 0.0f, controlPoints, degree, continuous, this.tmp));
        }
        return this;
    }

    public T valueAt(T out, float t) {
        int n = this.spanCount;
        float u = n * t;
        int i = t >= 1.0f ? n - 1 : (int) u;
        return valueAt(out, i, u - i);
    }

    public T valueAt(T out, int span, float u) {
        return (T) calculate(out, this.continuous ? span : ((int) (this.degree * 0.5f)) + span, u, this.controlPoints, this.degree, this.continuous, this.tmp);
    }

    public T derivativeAt(T out, float t) {
        int n = this.spanCount;
        float u = n * t;
        int i = t >= 1.0f ? n - 1 : (int) u;
        return derivativeAt(out, i, u - i);
    }

    public T derivativeAt(T out, int span, float u) {
        return (T) derivative(out, this.continuous ? span : ((int) (this.degree * 0.5f)) + span, u, this.controlPoints, this.degree, this.continuous, this.tmp);
    }

    public int nearest(T in) {
        return nearest(in, 0, this.spanCount);
    }

    public int nearest(T in, int start, int count) {
        while (start < 0) {
            start += this.spanCount;
        }
        int result = start % this.spanCount;
        float dst = in.dst2(this.knots.get(result));
        for (int i = 1; i < count; i++) {
            int idx = (start + i) % this.spanCount;
            float d = in.dst2(this.knots.get(idx));
            if (d < dst) {
                dst = d;
                result = idx;
            }
        }
        return result;
    }

    public float approximate(T v) {
        return approximate(v, nearest(v));
    }

    public float approximate(T in, int start, int count) {
        return approximate(in, nearest(in, start, count));
    }

    public float approximate(T in, int near) {
        T P1;
        T P2;
        T P3;
        int n = near;
        T nearest = this.knots.get(n);
        T previous = this.knots.get(n > 0 ? n - 1 : this.spanCount - 1);
        T next = this.knots.get((n + 1) % this.spanCount);
        float dstPrev2 = in.dst2(previous);
        float dstNext2 = in.dst2(next);
        if (dstNext2 < dstPrev2) {
            P1 = nearest;
            P2 = next;
            P3 = in;
        } else {
            P1 = previous;
            P2 = nearest;
            P3 = in;
            n = n > 0 ? n - 1 : this.spanCount - 1;
        }
        float L1Sqr = P1.dst2(P2);
        float L2Sqr = P3.dst2(P2);
        float L3Sqr = P3.dst2(P1);
        float L1 = (float) Math.sqrt(L1Sqr);
        float s = ((L2Sqr + L1Sqr) - L3Sqr) / (2.0f * L1);
        float u = MathUtils.clamp((L1 - s) / L1, 0.0f, 1.0f);
        return (n + u) / this.spanCount;
    }

    public float locate(T v) {
        return approximate((BSpline<T>) v);
    }

    @Override // com.badlogic.gdx.math.Path
    public float approxLength(int samples) {
        float tempLength = 0.0f;
        for (int i = 0; i < samples; i++) {
            this.tmp2.set(this.tmp3);
            valueAt((BSpline<T>) this.tmp3, i / (samples - 1.0f));
            if (i > 0) {
                tempLength += this.tmp2.dst(this.tmp3);
            }
        }
        return tempLength;
    }
}