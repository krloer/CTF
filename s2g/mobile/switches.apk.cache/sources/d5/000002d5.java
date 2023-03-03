package com.badlogic.gdx.math;

import com.badlogic.gdx.math.Vector;

/* loaded from: classes.dex */
public class CatmullRomSpline<T extends Vector<T>> implements Path<T> {
    public boolean continuous;
    public T[] controlPoints;
    public int spanCount;
    private T tmp;
    private T tmp2;
    private T tmp3;

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.badlogic.gdx.math.Path
    public /* bridge */ /* synthetic */ float approximate(Object obj) {
        return approximate((CatmullRomSpline<T>) ((Vector) obj));
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.badlogic.gdx.math.Path
    public /* bridge */ /* synthetic */ Object derivativeAt(Object obj, float f) {
        return derivativeAt((CatmullRomSpline<T>) ((Vector) obj), f);
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.badlogic.gdx.math.Path
    public /* bridge */ /* synthetic */ float locate(Object obj) {
        return locate((CatmullRomSpline<T>) ((Vector) obj));
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.badlogic.gdx.math.Path
    public /* bridge */ /* synthetic */ Object valueAt(Object obj, float f) {
        return valueAt((CatmullRomSpline<T>) ((Vector) obj), f);
    }

    public static <T extends Vector<T>> T calculate(T out, float t, T[] points, boolean continuous, T tmp) {
        int n = points.length;
        if (!continuous) {
            n -= 3;
        }
        float u = n * t;
        int i = t >= 1.0f ? n - 1 : (int) u;
        return (T) calculate(out, i, u - i, points, continuous, tmp);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static <T extends Vector<T>> T calculate(T out, int i, float u, T[] points, boolean continuous, T tmp) {
        int n = points.length;
        float u2 = u * u;
        float u3 = u2 * u;
        out.set(points[i]).scl(((1.5f * u3) - (2.5f * u2)) + 1.0f);
        if (continuous || i > 0) {
            out.add(tmp.set(points[((n + i) - 1) % n]).scl((((-0.5f) * u3) + u2) - (u * 0.5f)));
        }
        if (continuous || i < n - 1) {
            out.add(tmp.set(points[(i + 1) % n]).scl(((-1.5f) * u3) + (2.0f * u2) + (u * 0.5f)));
        }
        if (continuous || i < n - 2) {
            out.add(tmp.set(points[(i + 2) % n]).scl((u3 * 0.5f) - (0.5f * u2)));
        }
        return out;
    }

    public static <T extends Vector<T>> T derivative(T out, float t, T[] points, boolean continuous, T tmp) {
        int n = points.length;
        if (!continuous) {
            n -= 3;
        }
        float u = n * t;
        int i = t >= 1.0f ? n - 1 : (int) u;
        return (T) derivative(out, i, u - i, points, continuous, tmp);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static <T extends Vector<T>> T derivative(T out, int i, float u, T[] points, boolean continuous, T tmp) {
        int n = points.length;
        float u2 = u * u;
        out.set(points[i]).scl(((-u) * 5.0f) + (u2 * 4.5f));
        if (continuous || i > 0) {
            out.add(tmp.set(points[((n + i) - 1) % n]).scl(((2.0f * u) - 0.5f) - (u2 * 1.5f)));
        }
        if (continuous || i < n - 1) {
            out.add(tmp.set(points[(i + 1) % n]).scl(((4.0f * u) + 0.5f) - (4.5f * u2)));
        }
        if (continuous || i < n - 2) {
            out.add(tmp.set(points[(i + 2) % n]).scl((-u) + (1.5f * u2)));
        }
        return out;
    }

    public CatmullRomSpline() {
    }

    public CatmullRomSpline(T[] controlPoints, boolean continuous) {
        set(controlPoints, continuous);
    }

    public CatmullRomSpline set(T[] controlPoints, boolean continuous) {
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
        this.continuous = continuous;
        int length = controlPoints.length;
        if (!continuous) {
            length -= 3;
        }
        this.spanCount = length;
        return this;
    }

    public T valueAt(T out, float t) {
        int n = this.spanCount;
        float u = n * t;
        int i = t >= 1.0f ? n - 1 : (int) u;
        return valueAt(out, i, u - i);
    }

    public T valueAt(T out, int span, float u) {
        return (T) calculate(out, this.continuous ? span : span + 1, u, this.controlPoints, this.continuous, this.tmp);
    }

    public T derivativeAt(T out, float t) {
        int n = this.spanCount;
        float u = n * t;
        int i = t >= 1.0f ? n - 1 : (int) u;
        return derivativeAt(out, i, u - i);
    }

    public T derivativeAt(T out, int span, float u) {
        return (T) derivative(out, this.continuous ? span : span + 1, u, this.controlPoints, this.continuous, this.tmp);
    }

    public int nearest(T in) {
        return nearest(in, 0, this.spanCount);
    }

    public int nearest(T in, int start, int count) {
        while (start < 0) {
            start += this.spanCount;
        }
        int result = start % this.spanCount;
        float dst = in.dst2(this.controlPoints[result]);
        for (int i = 1; i < count; i++) {
            int idx = (start + i) % this.spanCount;
            float d = in.dst2(this.controlPoints[idx]);
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
        T[] tArr = this.controlPoints;
        T nearest = tArr[n];
        T previous = tArr[n > 0 ? n - 1 : this.spanCount - 1];
        T next = this.controlPoints[(n + 1) % this.spanCount];
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
        return approximate((CatmullRomSpline<T>) v);
    }

    @Override // com.badlogic.gdx.math.Path
    public float approxLength(int samples) {
        float tempLength = 0.0f;
        for (int i = 0; i < samples; i++) {
            this.tmp2.set(this.tmp3);
            valueAt((CatmullRomSpline<T>) this.tmp3, i / (samples - 1.0f));
            if (i > 0) {
                tempLength += this.tmp2.dst(this.tmp3);
            }
        }
        return tempLength;
    }
}