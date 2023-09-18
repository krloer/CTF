package androidx.recyclerview.widget;

import android.content.Context;
import android.graphics.Rect;
import android.util.AttributeSet;
import android.util.Log;
import android.util.SparseIntArray;
import android.view.View;
import android.view.ViewGroup;
import androidx.appcompat.widget.u2;
import d.c0;
import e0.y;
import f0.c;
import java.util.WeakHashMap;
import r0.a1;
import r0.o0;
import r0.p0;
import r0.q;
import r0.t;
import r0.v;
import r0.v0;
import r0.x;

/* loaded from: classes.dex */
public class GridLayoutManager extends LinearLayoutManager {
    public boolean E;
    public int F;
    public int[] G;
    public View[] H;
    public final SparseIntArray I;
    public final SparseIntArray J;
    public final u2 K;
    public final Rect L;

    public GridLayoutManager(int i2) {
        super(1);
        this.E = false;
        this.F = -1;
        this.I = new SparseIntArray();
        this.J = new SparseIntArray();
        this.K = new u2(1);
        this.L = new Rect();
        g1(i2);
    }

    @Override // r0.o0
    public final int F(v0 v0Var, a1 a1Var) {
        if (this.f1042p == 0) {
            return this.F;
        }
        if (a1Var.b() < 1) {
            return 0;
        }
        return c1(a1Var.b() - 1, v0Var, a1Var) + 1;
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager
    public final View J0(v0 v0Var, a1 a1Var, int i2, int i3, int i4) {
        B0();
        int h2 = this.f1044r.h();
        int f2 = this.f1044r.f();
        int i5 = i3 > i2 ? 1 : -1;
        View view = null;
        View view2 = null;
        while (i2 != i3) {
            View u2 = u(i2);
            int D = o0.D(u2);
            if (D >= 0 && D < i4 && d1(D, v0Var, a1Var) == 0) {
                if (((p0) u2.getLayoutParams()).c()) {
                    if (view2 == null) {
                        view2 = u2;
                    }
                } else if (this.f1044r.d(u2) < f2 && this.f1044r.b(u2) >= h2) {
                    return u2;
                } else {
                    if (view == null) {
                        view = u2;
                    }
                }
            }
            i2 += i5;
        }
        return view != null ? view : view2;
    }

    /* JADX WARN: Code restructure failed: missing block: B:65:0x00df, code lost:
        if (r13 == (r2 > r15)) goto L52;
     */
    /* JADX WARN: Code restructure failed: missing block: B:82:0x010f, code lost:
        if (r13 == (r2 > r9)) goto L87;
     */
    /* JADX WARN: Removed duplicated region for block: B:87:0x011b  */
    @Override // androidx.recyclerview.widget.LinearLayoutManager, r0.o0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public final android.view.View N(android.view.View r23, int r24, r0.v0 r25, r0.a1 r26) {
        /*
            Method dump skipped, instructions count: 347
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.GridLayoutManager.N(android.view.View, int, r0.v0, r0.a1):android.view.View");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:47:0x00ad  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x00b0  */
    /* JADX WARN: Type inference failed for: r12v25 */
    /* JADX WARN: Type inference failed for: r12v26, types: [int, boolean] */
    /* JADX WARN: Type inference failed for: r12v34 */
    /* JADX WARN: Type inference failed for: r12v35 */
    /* JADX WARN: Type inference failed for: r12v42 */
    @Override // androidx.recyclerview.widget.LinearLayoutManager
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public final void P0(r0.v0 r20, r0.a1 r21, r0.x r22, r0.w r23) {
        /*
            Method dump skipped, instructions count: 652
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.GridLayoutManager.P0(r0.v0, r0.a1, r0.x, r0.w):void");
    }

    @Override // r0.o0
    public final void Q(v0 v0Var, a1 a1Var, View view, c cVar) {
        int i2;
        int i3;
        ViewGroup.LayoutParams layoutParams = view.getLayoutParams();
        if (!(layoutParams instanceof t)) {
            P(view, cVar);
            return;
        }
        t tVar = (t) layoutParams;
        int c12 = c1(tVar.a(), v0Var, a1Var);
        int i4 = 1;
        if (this.f1042p == 0) {
            c12 = tVar.f3062e;
            i2 = c12;
            i3 = 1;
            i4 = tVar.f3063f;
        } else {
            i2 = tVar.f3062e;
            i3 = tVar.f3063f;
        }
        cVar.f(c0.a(c12, i4, i2, i3, false));
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager
    public final void Q0(v0 v0Var, a1 a1Var, v vVar, int i2) {
        h1();
        if (a1Var.b() > 0 && !a1Var.f2841g) {
            boolean z = i2 == 1;
            int d12 = d1(vVar.f3080b, v0Var, a1Var);
            if (z) {
                while (d12 > 0) {
                    int i3 = vVar.f3080b;
                    if (i3 <= 0) {
                        break;
                    }
                    int i4 = i3 - 1;
                    vVar.f3080b = i4;
                    d12 = d1(i4, v0Var, a1Var);
                }
            } else {
                int b2 = a1Var.b() - 1;
                int i5 = vVar.f3080b;
                while (i5 < b2) {
                    int i6 = i5 + 1;
                    int d13 = d1(i6, v0Var, a1Var);
                    if (d13 <= d12) {
                        break;
                    }
                    i5 = i6;
                    d12 = d13;
                }
                vVar.f3080b = i5;
            }
        }
        View[] viewArr = this.H;
        if (viewArr == null || viewArr.length != this.F) {
            this.H = new View[this.F];
        }
    }

    @Override // r0.o0
    public final void R(int i2, int i3) {
        u2 u2Var = this.K;
        u2Var.d();
        ((SparseIntArray) u2Var.f499d).clear();
    }

    @Override // r0.o0
    public final void S() {
        u2 u2Var = this.K;
        u2Var.d();
        ((SparseIntArray) u2Var.f499d).clear();
    }

    @Override // r0.o0
    public final void T(int i2, int i3) {
        u2 u2Var = this.K;
        u2Var.d();
        ((SparseIntArray) u2Var.f499d).clear();
    }

    @Override // r0.o0
    public final void U(int i2, int i3) {
        u2 u2Var = this.K;
        u2Var.d();
        ((SparseIntArray) u2Var.f499d).clear();
    }

    @Override // r0.o0
    public final void V(int i2, int i3) {
        u2 u2Var = this.K;
        u2Var.d();
        ((SparseIntArray) u2Var.f499d).clear();
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, r0.o0
    public final void W(v0 v0Var, a1 a1Var) {
        boolean z = a1Var.f2841g;
        SparseIntArray sparseIntArray = this.J;
        SparseIntArray sparseIntArray2 = this.I;
        if (z) {
            int v2 = v();
            for (int i2 = 0; i2 < v2; i2++) {
                t tVar = (t) u(i2).getLayoutParams();
                int a2 = tVar.a();
                sparseIntArray2.put(a2, tVar.f3063f);
                sparseIntArray.put(a2, tVar.f3062e);
            }
        }
        super.W(v0Var, a1Var);
        sparseIntArray2.clear();
        sparseIntArray.clear();
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager
    public final void W0(boolean z) {
        if (z) {
            throw new UnsupportedOperationException("GridLayoutManager does not support stack from end. Consider using reverse layout");
        }
        super.W0(false);
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, r0.o0
    public final void X(a1 a1Var) {
        super.X(a1Var);
        this.E = false;
    }

    public final void a1(int i2) {
        int i3;
        int[] iArr = this.G;
        int i4 = this.F;
        if (iArr == null || iArr.length != i4 + 1 || iArr[iArr.length - 1] != i2) {
            iArr = new int[i4 + 1];
        }
        int i5 = 0;
        iArr[0] = 0;
        int i6 = i2 / i4;
        int i7 = i2 % i4;
        int i8 = 0;
        for (int i9 = 1; i9 <= i4; i9++) {
            i5 += i7;
            if (i5 <= 0 || i4 - i5 >= i7) {
                i3 = i6;
            } else {
                i3 = i6 + 1;
                i5 -= i4;
            }
            i8 += i3;
            iArr[i9] = i8;
        }
        this.G = iArr;
    }

    public final int b1(int i2, int i3) {
        if (this.f1042p != 1 || !O0()) {
            int[] iArr = this.G;
            return iArr[i3 + i2] - iArr[i2];
        }
        int[] iArr2 = this.G;
        int i4 = this.F;
        return iArr2[i4 - i2] - iArr2[(i4 - i2) - i3];
    }

    public final int c1(int i2, v0 v0Var, a1 a1Var) {
        boolean z = a1Var.f2841g;
        u2 u2Var = this.K;
        if (z) {
            int b2 = v0Var.b(i2);
            if (b2 == -1) {
                Log.w("GridLayoutManager", "Cannot find span size for pre layout position. " + i2);
                return 0;
            }
            return u2Var.a(b2, this.F);
        }
        return u2Var.a(i2, this.F);
    }

    public final int d1(int i2, v0 v0Var, a1 a1Var) {
        boolean z = a1Var.f2841g;
        u2 u2Var = this.K;
        if (z) {
            int i3 = this.J.get(i2, -1);
            if (i3 != -1) {
                return i3;
            }
            int b2 = v0Var.b(i2);
            if (b2 == -1) {
                Log.w("GridLayoutManager", "Cannot find span size for pre layout position. It is not cached, not in the adapter. Pos:" + i2);
                return 0;
            }
            return u2Var.b(b2, this.F);
        }
        return u2Var.b(i2, this.F);
    }

    public final int e1(int i2, v0 v0Var, a1 a1Var) {
        boolean z = a1Var.f2841g;
        u2 u2Var = this.K;
        if (!z) {
            u2Var.getClass();
            return 1;
        }
        int i3 = this.I.get(i2, -1);
        if (i3 != -1) {
            return i3;
        }
        if (v0Var.b(i2) != -1) {
            u2Var.getClass();
            return 1;
        }
        Log.w("GridLayoutManager", "Cannot find span size for pre layout position. It is not cached, not in the adapter. Pos:" + i2);
        return 1;
    }

    @Override // r0.o0
    public final boolean f(p0 p0Var) {
        return p0Var instanceof t;
    }

    public final void f1(View view, int i2, boolean z) {
        int i3;
        int i4;
        t tVar = (t) view.getLayoutParams();
        Rect rect = tVar.f3041b;
        int i5 = rect.top + rect.bottom + ((ViewGroup.MarginLayoutParams) tVar).topMargin + ((ViewGroup.MarginLayoutParams) tVar).bottomMargin;
        int i6 = rect.left + rect.right + ((ViewGroup.MarginLayoutParams) tVar).leftMargin + ((ViewGroup.MarginLayoutParams) tVar).rightMargin;
        int b12 = b1(tVar.f3062e, tVar.f3063f);
        if (this.f1042p == 1) {
            i4 = o0.w(false, b12, i2, i6, ((ViewGroup.MarginLayoutParams) tVar).width);
            i3 = o0.w(true, this.f1044r.i(), this.f3009m, i5, ((ViewGroup.MarginLayoutParams) tVar).height);
        } else {
            int w2 = o0.w(false, b12, i2, i5, ((ViewGroup.MarginLayoutParams) tVar).height);
            int w3 = o0.w(true, this.f1044r.i(), this.l, i6, ((ViewGroup.MarginLayoutParams) tVar).width);
            i3 = w2;
            i4 = w3;
        }
        p0 p0Var = (p0) view.getLayoutParams();
        if (z ? r0(view, i4, i3, p0Var) : p0(view, i4, i3, p0Var)) {
            view.measure(i4, i3);
        }
    }

    public final void g1(int i2) {
        if (i2 == this.F) {
            return;
        }
        this.E = true;
        if (i2 < 1) {
            throw new IllegalArgumentException("Span count should be at least 1. Provided " + i2);
        }
        this.F = i2;
        this.K.d();
        g0();
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, r0.o0
    public final int h0(int i2, v0 v0Var, a1 a1Var) {
        h1();
        View[] viewArr = this.H;
        if (viewArr == null || viewArr.length != this.F) {
            this.H = new View[this.F];
        }
        return super.h0(i2, v0Var, a1Var);
    }

    public final void h1() {
        int z;
        int C;
        if (this.f1042p == 1) {
            z = this.f3010n - B();
            C = A();
        } else {
            z = this.f3011o - z();
            C = C();
        }
        a1(z - C);
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, r0.o0
    public final int j0(int i2, v0 v0Var, a1 a1Var) {
        h1();
        View[] viewArr = this.H;
        if (viewArr == null || viewArr.length != this.F) {
            this.H = new View[this.F];
        }
        return super.j0(i2, v0Var, a1Var);
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, r0.o0
    public final int k(a1 a1Var) {
        return y0(a1Var);
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, r0.o0
    public final int l(a1 a1Var) {
        return z0(a1Var);
    }

    @Override // r0.o0
    public final void m0(Rect rect, int i2, int i3) {
        int g2;
        int g3;
        if (this.G == null) {
            super.m0(rect, i2, i3);
        }
        int B = B() + A();
        int z = z() + C();
        if (this.f1042p == 1) {
            int height = rect.height() + z;
            RecyclerView recyclerView = this.f2999b;
            WeakHashMap weakHashMap = e0.o0.f1697a;
            g3 = o0.g(i3, height, y.d(recyclerView));
            int[] iArr = this.G;
            g2 = o0.g(i2, iArr[iArr.length - 1] + B, y.e(this.f2999b));
        } else {
            int width = rect.width() + B;
            RecyclerView recyclerView2 = this.f2999b;
            WeakHashMap weakHashMap2 = e0.o0.f1697a;
            g2 = o0.g(i2, width, y.e(recyclerView2));
            int[] iArr2 = this.G;
            g3 = o0.g(i3, iArr2[iArr2.length - 1] + z, y.d(this.f2999b));
        }
        this.f2999b.setMeasuredDimension(g2, g3);
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, r0.o0
    public final int n(a1 a1Var) {
        return y0(a1Var);
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, r0.o0
    public final int o(a1 a1Var) {
        return z0(a1Var);
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, r0.o0
    public final p0 r() {
        return this.f1042p == 0 ? new t(-2, -1) : new t(-1, -2);
    }

    @Override // r0.o0
    public final p0 s(Context context, AttributeSet attributeSet) {
        return new t(context, attributeSet);
    }

    @Override // r0.o0
    public final p0 t(ViewGroup.LayoutParams layoutParams) {
        return layoutParams instanceof ViewGroup.MarginLayoutParams ? new t((ViewGroup.MarginLayoutParams) layoutParams) : new t(layoutParams);
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, r0.o0
    public final boolean u0() {
        return this.z == null && !this.E;
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager
    public final void w0(a1 a1Var, x xVar, q qVar) {
        int i2 = this.F;
        for (int i3 = 0; i3 < this.F; i3++) {
            int i4 = xVar.f3099d;
            if (!(i4 >= 0 && i4 < a1Var.b()) || i2 <= 0) {
                return;
            }
            qVar.a(xVar.f3099d, Math.max(0, xVar.f3102g));
            this.K.getClass();
            i2--;
            xVar.f3099d += xVar.f3100e;
        }
    }

    @Override // r0.o0
    public final int x(v0 v0Var, a1 a1Var) {
        if (this.f1042p == 1) {
            return this.F;
        }
        if (a1Var.b() < 1) {
            return 0;
        }
        return c1(a1Var.b() - 1, v0Var, a1Var) + 1;
    }

    public GridLayoutManager(Context context, AttributeSet attributeSet, int i2, int i3) {
        super(context, attributeSet, i2, i3);
        this.E = false;
        this.F = -1;
        this.I = new SparseIntArray();
        this.J = new SparseIntArray();
        this.K = new u2(1);
        this.L = new Rect();
        g1(o0.E(context, attributeSet, i2, i3).f2994b);
    }
}