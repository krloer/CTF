package z0;

import android.view.View;
import android.view.ViewParent;
import androidx.emoji2.text.i;
import com.google.android.material.behavior.SwipeDismissBehavior;

/* loaded from: classes.dex */
public final class a extends i {

    /* renamed from: q  reason: collision with root package name */
    public int f3338q;

    /* renamed from: r  reason: collision with root package name */
    public int f3339r = -1;

    /* renamed from: s  reason: collision with root package name */
    public final /* synthetic */ SwipeDismissBehavior f3340s;

    public a(SwipeDismissBehavior swipeDismissBehavior) {
        this.f3340s = swipeDismissBehavior;
    }

    @Override // androidx.emoji2.text.i
    public final boolean J0(View view, int i2) {
        int i3 = this.f3339r;
        return (i3 == -1 || i3 == i2) && this.f3340s.r(view);
    }

    @Override // androidx.emoji2.text.i
    public final int T(View view) {
        return view.getWidth();
    }

    @Override // androidx.emoji2.text.i
    public final void q0(View view, int i2) {
        this.f3339r = i2;
        this.f3338q = view.getLeft();
        ViewParent parent = view.getParent();
        if (parent != null) {
            parent.requestDisallowInterceptTouchEvent(true);
        }
    }

    @Override // androidx.emoji2.text.i
    public final void r0(int i2) {
        this.f3340s.getClass();
    }

    @Override // androidx.emoji2.text.i
    public final void s0(View view, int i2, int i3) {
        SwipeDismissBehavior swipeDismissBehavior = this.f3340s;
        float width = (view.getWidth() * swipeDismissBehavior.f1233e) + this.f3338q;
        float width2 = (view.getWidth() * swipeDismissBehavior.f1234f) + this.f3338q;
        float f2 = i2;
        if (f2 <= width) {
            view.setAlpha(1.0f);
        } else if (f2 >= width2) {
            view.setAlpha(0.0f);
        } else {
            view.setAlpha(Math.min(Math.max(0.0f, 1.0f - ((f2 - width) / (width2 - width))), 1.0f));
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:26:0x0050, code lost:
        if (java.lang.Math.abs(r9.getLeft() - r8.f3338q) >= java.lang.Math.round(r9.getWidth() * r3.f1232d)) goto L31;
     */
    @Override // androidx.emoji2.text.i
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public final void t0(android.view.View r9, float r10, float r11) {
        /*
            r8 = this;
            r11 = -1
            r8.f3339r = r11
            int r11 = r9.getWidth()
            r0 = 0
            int r1 = (r10 > r0 ? 1 : (r10 == r0 ? 0 : -1))
            r2 = 1
            com.google.android.material.behavior.SwipeDismissBehavior r3 = r8.f3340s
            r4 = 0
            if (r1 == 0) goto L39
            java.util.WeakHashMap r5 = e0.o0.f1697a
            int r5 = e0.z.d(r9)
            if (r5 != r2) goto L1a
            r5 = r2
            goto L1b
        L1a:
            r5 = r4
        L1b:
            int r6 = r3.f1231c
            r7 = 2
            if (r6 != r7) goto L21
            goto L52
        L21:
            if (r6 != 0) goto L2d
            if (r5 == 0) goto L2a
            int r10 = (r10 > r0 ? 1 : (r10 == r0 ? 0 : -1))
            if (r10 >= 0) goto L54
            goto L52
        L2a:
            if (r1 <= 0) goto L54
            goto L52
        L2d:
            if (r6 != r2) goto L54
            if (r5 == 0) goto L34
            if (r1 <= 0) goto L54
            goto L52
        L34:
            int r10 = (r10 > r0 ? 1 : (r10 == r0 ? 0 : -1))
            if (r10 >= 0) goto L54
            goto L52
        L39:
            int r10 = r9.getLeft()
            int r0 = r8.f3338q
            int r10 = r10 - r0
            int r0 = r9.getWidth()
            float r0 = (float) r0
            float r1 = r3.f1232d
            float r0 = r0 * r1
            int r0 = java.lang.Math.round(r0)
            int r10 = java.lang.Math.abs(r10)
            if (r10 < r0) goto L54
        L52:
            r10 = r2
            goto L55
        L54:
            r10 = r4
        L55:
            if (r10 == 0) goto L63
            int r10 = r9.getLeft()
            int r8 = r8.f3338q
            if (r10 >= r8) goto L61
            int r8 = r8 - r11
            goto L66
        L61:
            int r8 = r8 + r11
            goto L66
        L63:
            int r8 = r8.f3338q
            r2 = r4
        L66:
            k0.d r10 = r3.f1229a
            int r11 = r9.getTop()
            boolean r8 = r10.q(r8, r11)
            if (r8 == 0) goto L7c
            z0.b r8 = new z0.b
            r8.<init>(r3, r9, r2)
            java.util.WeakHashMap r10 = e0.o0.f1697a
            e0.y.m(r9, r8)
        L7c:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: z0.a.t0(android.view.View, float, float):void");
    }

    /* JADX WARN: Code restructure failed: missing block: B:11:0x0017, code lost:
        if (r0 != false) goto L7;
     */
    /* JADX WARN: Code restructure failed: missing block: B:12:0x0019, code lost:
        r4 = r4.f3338q;
        r5 = r5.getWidth() + r4;
     */
    /* JADX WARN: Code restructure failed: missing block: B:13:0x0021, code lost:
        r5 = r4.f3338q - r5.getWidth();
        r5 = r4.f3338q;
        r4 = r5;
     */
    /* JADX WARN: Code restructure failed: missing block: B:8:0x0012, code lost:
        if (r0 != false) goto L11;
     */
    @Override // androidx.emoji2.text.i
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public final int x(android.view.View r5, int r6) {
        /*
            r4 = this;
            java.util.WeakHashMap r0 = e0.o0.f1697a
            int r0 = e0.z.d(r5)
            r1 = 1
            if (r0 != r1) goto Lb
            r0 = r1
            goto Lc
        Lb:
            r0 = 0
        Lc:
            com.google.android.material.behavior.SwipeDismissBehavior r2 = r4.f3340s
            int r2 = r2.f1231c
            if (r2 != 0) goto L15
            if (r0 == 0) goto L19
            goto L21
        L15:
            if (r2 != r1) goto L2f
            if (r0 == 0) goto L21
        L19:
            int r4 = r4.f3338q
            int r5 = r5.getWidth()
            int r5 = r5 + r4
            goto L3e
        L21:
            int r0 = r4.f3338q
            int r5 = r5.getWidth()
            int r5 = r0 - r5
            int r4 = r4.f3338q
            r3 = r5
            r5 = r4
            r4 = r3
            goto L3e
        L2f:
            int r0 = r4.f3338q
            int r1 = r5.getWidth()
            int r0 = r0 - r1
            int r4 = r4.f3338q
            int r5 = r5.getWidth()
            int r5 = r5 + r4
            r4 = r0
        L3e:
            int r4 = java.lang.Math.max(r4, r6)
            int r4 = java.lang.Math.min(r4, r5)
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: z0.a.x(android.view.View, int):int");
    }

    @Override // androidx.emoji2.text.i
    public final int y(View view, int i2) {
        return view.getTop();
    }
}