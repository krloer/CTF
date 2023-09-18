package x0;

import android.animation.TimeInterpolator;

/* loaded from: classes.dex */
public final class c {

    /* renamed from: a  reason: collision with root package name */
    public final long f3318a;

    /* renamed from: b  reason: collision with root package name */
    public final long f3319b;

    /* renamed from: c  reason: collision with root package name */
    public final TimeInterpolator f3320c;

    /* renamed from: d  reason: collision with root package name */
    public int f3321d = 0;

    /* renamed from: e  reason: collision with root package name */
    public int f3322e = 1;

    public c(long j2, long j3, TimeInterpolator timeInterpolator) {
        this.f3318a = 0L;
        this.f3319b = 300L;
        this.f3320c = null;
        this.f3318a = j2;
        this.f3319b = j3;
        this.f3320c = timeInterpolator;
    }

    public final TimeInterpolator a() {
        TimeInterpolator timeInterpolator = this.f3320c;
        return timeInterpolator != null ? timeInterpolator : a.f3313b;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof c) {
            c cVar = (c) obj;
            if (this.f3318a == cVar.f3318a && this.f3319b == cVar.f3319b && this.f3321d == cVar.f3321d && this.f3322e == cVar.f3322e) {
                return a().getClass().equals(cVar.a().getClass());
            }
            return false;
        }
        return false;
    }

    public final int hashCode() {
        long j2 = this.f3318a;
        long j3 = this.f3319b;
        return ((((a().getClass().hashCode() + (((((int) (j2 ^ (j2 >>> 32))) * 31) + ((int) ((j3 >>> 32) ^ j3))) * 31)) * 31) + this.f3321d) * 31) + this.f3322e;
    }

    public final String toString() {
        return "\n" + c.class.getName() + '{' + Integer.toHexString(System.identityHashCode(this)) + " delay: " + this.f3318a + " duration: " + this.f3319b + " interpolator: " + a().getClass() + " repeatCount: " + this.f3321d + " repeatMode: " + this.f3322e + "}\n";
    }
}