package androidx.recyclerview.widget;

import android.content.Context;
import android.graphics.PointF;
import android.graphics.Rect;
import android.os.Parcelable;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import android.view.accessibility.AccessibilityEvent;
import androidx.emoji2.text.i;
import e0.z;
import java.util.WeakHashMap;
import r0.a0;
import r0.a1;
import r0.b0;
import r0.n0;
import r0.o0;
import r0.p0;
import r0.q;
import r0.v;
import r0.v0;
import r0.w;
import r0.x;
import r0.y;
import r0.z0;

/* loaded from: classes.dex */
public class LinearLayoutManager extends o0 implements z0 {
    public final v A;
    public final w B;
    public final int C;
    public final int[] D;

    /* renamed from: p  reason: collision with root package name */
    public int f1042p;

    /* renamed from: q  reason: collision with root package name */
    public x f1043q;

    /* renamed from: r  reason: collision with root package name */
    public a0 f1044r;

    /* renamed from: s  reason: collision with root package name */
    public boolean f1045s;

    /* renamed from: t  reason: collision with root package name */
    public boolean f1046t;

    /* renamed from: u  reason: collision with root package name */
    public boolean f1047u;

    /* renamed from: v  reason: collision with root package name */
    public boolean f1048v;

    /* renamed from: w  reason: collision with root package name */
    public final boolean f1049w;

    /* renamed from: x  reason: collision with root package name */
    public int f1050x;

    /* renamed from: y  reason: collision with root package name */
    public int f1051y;
    public y z;

    public LinearLayoutManager(int i2) {
        this.f1042p = 1;
        this.f1046t = false;
        this.f1047u = false;
        this.f1048v = false;
        this.f1049w = true;
        this.f1050x = -1;
        this.f1051y = Integer.MIN_VALUE;
        this.z = null;
        this.A = new v();
        this.B = new w();
        this.C = 2;
        this.D = new int[2];
        V0(i2);
        c(null);
        if (this.f1046t) {
            this.f1046t = false;
            g0();
        }
    }

    public final int A0(int i2) {
        return i2 != 1 ? i2 != 2 ? i2 != 17 ? i2 != 33 ? i2 != 66 ? (i2 == 130 && this.f1042p == 1) ? 1 : Integer.MIN_VALUE : this.f1042p == 0 ? 1 : Integer.MIN_VALUE : this.f1042p == 1 ? -1 : Integer.MIN_VALUE : this.f1042p == 0 ? -1 : Integer.MIN_VALUE : (this.f1042p != 1 && O0()) ? -1 : 1 : (this.f1042p != 1 && O0()) ? 1 : -1;
    }

    public final void B0() {
        if (this.f1043q == null) {
            this.f1043q = new x();
        }
    }

    public final int C0(v0 v0Var, x xVar, a1 a1Var, boolean z) {
        int i2 = xVar.f3098c;
        int i3 = xVar.f3102g;
        if (i3 != Integer.MIN_VALUE) {
            if (i2 < 0) {
                xVar.f3102g = i3 + i2;
            }
            R0(v0Var, xVar);
        }
        int i4 = xVar.f3098c + xVar.f3103h;
        while (true) {
            if (!xVar.l && i4 <= 0) {
                break;
            }
            int i5 = xVar.f3099d;
            if (!(i5 >= 0 && i5 < a1Var.b())) {
                break;
            }
            w wVar = this.B;
            wVar.f3092a = 0;
            wVar.f3093b = false;
            wVar.f3094c = false;
            wVar.f3095d = false;
            P0(v0Var, a1Var, xVar, wVar);
            if (!wVar.f3093b) {
                int i6 = xVar.f3097b;
                int i7 = wVar.f3092a;
                xVar.f3097b = (xVar.f3101f * i7) + i6;
                if (!wVar.f3094c || xVar.f3106k != null || !a1Var.f2841g) {
                    xVar.f3098c -= i7;
                    i4 -= i7;
                }
                int i8 = xVar.f3102g;
                if (i8 != Integer.MIN_VALUE) {
                    int i9 = i8 + i7;
                    xVar.f3102g = i9;
                    int i10 = xVar.f3098c;
                    if (i10 < 0) {
                        xVar.f3102g = i9 + i10;
                    }
                    R0(v0Var, xVar);
                }
                if (z && wVar.f3095d) {
                    break;
                }
            } else {
                break;
            }
        }
        return i2 - xVar.f3098c;
    }

    public final View D0(boolean z) {
        int v2;
        int i2;
        if (this.f1047u) {
            i2 = v();
            v2 = 0;
        } else {
            v2 = v() - 1;
            i2 = -1;
        }
        return I0(v2, i2, z);
    }

    public final View E0(boolean z) {
        int v2;
        int i2;
        if (this.f1047u) {
            v2 = -1;
            i2 = v() - 1;
        } else {
            v2 = v();
            i2 = 0;
        }
        return I0(i2, v2, z);
    }

    public final int F0() {
        View I0 = I0(0, v(), false);
        if (I0 == null) {
            return -1;
        }
        return o0.D(I0);
    }

    public final int G0() {
        View I0 = I0(v() - 1, -1, false);
        if (I0 == null) {
            return -1;
        }
        return o0.D(I0);
    }

    @Override // r0.o0
    public final boolean H() {
        return true;
    }

    public final View H0(int i2, int i3) {
        int i4;
        int i5;
        B0();
        if ((i3 > i2 ? (char) 1 : i3 < i2 ? (char) 65535 : (char) 0) == 0) {
            return u(i2);
        }
        if (this.f1044r.d(u(i2)) < this.f1044r.h()) {
            i4 = 16644;
            i5 = 16388;
        } else {
            i4 = 4161;
            i5 = 4097;
        }
        return (this.f1042p == 0 ? this.f3000c : this.f3001d).f(i2, i3, i4, i5);
    }

    public final View I0(int i2, int i3, boolean z) {
        B0();
        return (this.f1042p == 0 ? this.f3000c : this.f3001d).f(i2, i3, z ? 24579 : 320, 320);
    }

    public View J0(v0 v0Var, a1 a1Var, int i2, int i3, int i4) {
        B0();
        int h2 = this.f1044r.h();
        int f2 = this.f1044r.f();
        int i5 = i3 > i2 ? 1 : -1;
        View view = null;
        View view2 = null;
        while (i2 != i3) {
            View u2 = u(i2);
            int D = o0.D(u2);
            if (D >= 0 && D < i4) {
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

    public final int K0(int i2, v0 v0Var, a1 a1Var, boolean z) {
        int f2;
        int f3 = this.f1044r.f() - i2;
        if (f3 > 0) {
            int i3 = -U0(-f3, v0Var, a1Var);
            int i4 = i2 + i3;
            if (!z || (f2 = this.f1044r.f() - i4) <= 0) {
                return i3;
            }
            this.f1044r.m(f2);
            return f2 + i3;
        }
        return 0;
    }

    public final int L0(int i2, v0 v0Var, a1 a1Var, boolean z) {
        int h2;
        int h3 = i2 - this.f1044r.h();
        if (h3 > 0) {
            int i3 = -U0(h3, v0Var, a1Var);
            int i4 = i2 + i3;
            if (!z || (h2 = i4 - this.f1044r.h()) <= 0) {
                return i3;
            }
            this.f1044r.m(-h2);
            return i3 - h2;
        }
        return 0;
    }

    @Override // r0.o0
    public final void M(RecyclerView recyclerView) {
    }

    public final View M0() {
        return u(this.f1047u ? 0 : v() - 1);
    }

    @Override // r0.o0
    public View N(View view, int i2, v0 v0Var, a1 a1Var) {
        int A0;
        T0();
        if (v() == 0 || (A0 = A0(i2)) == Integer.MIN_VALUE) {
            return null;
        }
        B0();
        X0(A0, (int) (this.f1044r.i() * 0.33333334f), false, a1Var);
        x xVar = this.f1043q;
        xVar.f3102g = Integer.MIN_VALUE;
        xVar.f3096a = false;
        C0(v0Var, xVar, a1Var, true);
        View H0 = A0 == -1 ? this.f1047u ? H0(v() - 1, -1) : H0(0, v()) : this.f1047u ? H0(0, v()) : H0(v() - 1, -1);
        View N0 = A0 == -1 ? N0() : M0();
        if (N0.hasFocusable()) {
            if (H0 == null) {
                return null;
            }
            return N0;
        }
        return H0;
    }

    public final View N0() {
        return u(this.f1047u ? v() - 1 : 0);
    }

    @Override // r0.o0
    public final void O(AccessibilityEvent accessibilityEvent) {
        super.O(accessibilityEvent);
        if (v() > 0) {
            accessibilityEvent.setFromIndex(F0());
            accessibilityEvent.setToIndex(G0());
        }
    }

    public final boolean O0() {
        RecyclerView recyclerView = this.f2999b;
        WeakHashMap weakHashMap = e0.o0.f1697a;
        return z.d(recyclerView) == 1;
    }

    public void P0(v0 v0Var, a1 a1Var, x xVar, w wVar) {
        int i2;
        int i3;
        int i4;
        int i5;
        View b2 = xVar.b(v0Var);
        if (b2 == null) {
            wVar.f3093b = true;
            return;
        }
        p0 p0Var = (p0) b2.getLayoutParams();
        if (xVar.f3106k == null) {
            if (this.f1047u == (xVar.f3101f == -1)) {
                b(b2, -1, false);
            } else {
                b(b2, 0, false);
            }
        } else {
            if (this.f1047u == (xVar.f3101f == -1)) {
                b(b2, -1, true);
            } else {
                b(b2, 0, true);
            }
        }
        p0 p0Var2 = (p0) b2.getLayoutParams();
        Rect J = this.f2999b.J(b2);
        int w2 = o0.w(d(), this.f3010n, this.l, B() + A() + ((ViewGroup.MarginLayoutParams) p0Var2).leftMargin + ((ViewGroup.MarginLayoutParams) p0Var2).rightMargin + J.left + J.right + 0, ((ViewGroup.MarginLayoutParams) p0Var2).width);
        int w3 = o0.w(e(), this.f3011o, this.f3009m, z() + C() + ((ViewGroup.MarginLayoutParams) p0Var2).topMargin + ((ViewGroup.MarginLayoutParams) p0Var2).bottomMargin + J.top + J.bottom + 0, ((ViewGroup.MarginLayoutParams) p0Var2).height);
        if (p0(b2, w2, w3, p0Var2)) {
            b2.measure(w2, w3);
        }
        wVar.f3092a = this.f1044r.c(b2);
        if (this.f1042p == 1) {
            if (O0()) {
                i5 = this.f3010n - B();
                i3 = i5 - this.f1044r.n(b2);
            } else {
                int A = A();
                i5 = this.f1044r.n(b2) + A;
                i3 = A;
            }
            int i6 = xVar.f3101f;
            i4 = xVar.f3097b;
            if (i6 == -1) {
                i2 = i4;
                i4 -= wVar.f3092a;
            } else {
                i2 = wVar.f3092a + i4;
            }
        } else {
            int C = C();
            int n2 = this.f1044r.n(b2) + C;
            int i7 = xVar.f3101f;
            int i8 = xVar.f3097b;
            if (i7 == -1) {
                i2 = n2;
                i3 = i8 - wVar.f3092a;
                i5 = i8;
                i4 = C;
            } else {
                int i9 = wVar.f3092a + i8;
                i2 = n2;
                i3 = i8;
                i4 = C;
                i5 = i9;
            }
        }
        o0.J(b2, i3, i4, i5, i2);
        if (p0Var.c() || p0Var.b()) {
            wVar.f3094c = true;
        }
        wVar.f3095d = b2.hasFocusable();
    }

    public void Q0(v0 v0Var, a1 a1Var, v vVar, int i2) {
    }

    public final void R0(v0 v0Var, x xVar) {
        if (!xVar.f3096a || xVar.l) {
            return;
        }
        int i2 = xVar.f3102g;
        int i3 = xVar.f3104i;
        if (xVar.f3101f == -1) {
            int v2 = v();
            if (i2 < 0) {
                return;
            }
            int e2 = (this.f1044r.e() - i2) + i3;
            if (this.f1047u) {
                for (int i4 = 0; i4 < v2; i4++) {
                    View u2 = u(i4);
                    if (this.f1044r.d(u2) < e2 || this.f1044r.l(u2) < e2) {
                        S0(v0Var, 0, i4);
                        return;
                    }
                }
                return;
            }
            int i5 = v2 - 1;
            for (int i6 = i5; i6 >= 0; i6--) {
                View u3 = u(i6);
                if (this.f1044r.d(u3) < e2 || this.f1044r.l(u3) < e2) {
                    S0(v0Var, i5, i6);
                    return;
                }
            }
        } else if (i2 >= 0) {
            int i7 = i2 - i3;
            int v3 = v();
            if (!this.f1047u) {
                for (int i8 = 0; i8 < v3; i8++) {
                    View u4 = u(i8);
                    if (this.f1044r.b(u4) > i7 || this.f1044r.k(u4) > i7) {
                        S0(v0Var, 0, i8);
                        return;
                    }
                }
                return;
            }
            int i9 = v3 - 1;
            for (int i10 = i9; i10 >= 0; i10--) {
                View u5 = u(i10);
                if (this.f1044r.b(u5) > i7 || this.f1044r.k(u5) > i7) {
                    S0(v0Var, i9, i10);
                    return;
                }
            }
        }
    }

    public final void S0(v0 v0Var, int i2, int i3) {
        if (i2 == i3) {
            return;
        }
        if (i3 <= i2) {
            while (i2 > i3) {
                View u2 = u(i2);
                e0(i2);
                v0Var.f(u2);
                i2--;
            }
            return;
        }
        while (true) {
            i3--;
            if (i3 < i2) {
                return;
            }
            View u3 = u(i3);
            e0(i3);
            v0Var.f(u3);
        }
    }

    public final void T0() {
        this.f1047u = (this.f1042p == 1 || !O0()) ? this.f1046t : !this.f1046t;
    }

    public final int U0(int i2, v0 v0Var, a1 a1Var) {
        if (v() == 0 || i2 == 0) {
            return 0;
        }
        B0();
        this.f1043q.f3096a = true;
        int i3 = i2 > 0 ? 1 : -1;
        int abs = Math.abs(i2);
        X0(i3, abs, true, a1Var);
        x xVar = this.f1043q;
        int C0 = C0(v0Var, xVar, a1Var, false) + xVar.f3102g;
        if (C0 < 0) {
            return 0;
        }
        if (abs > C0) {
            i2 = i3 * C0;
        }
        this.f1044r.m(-i2);
        this.f1043q.f3105j = i2;
        return i2;
    }

    public final void V0(int i2) {
        if (i2 != 0 && i2 != 1) {
            throw new IllegalArgumentException("invalid orientation:" + i2);
        }
        c(null);
        if (i2 != this.f1042p || this.f1044r == null) {
            a0 a2 = b0.a(this, i2);
            this.f1044r = a2;
            this.A.f3079a = a2;
            this.f1042p = i2;
            g0();
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:105:0x0191  */
    /* JADX WARN: Removed duplicated region for block: B:162:0x028d  */
    /* JADX WARN: Type inference failed for: r2v30 */
    /* JADX WARN: Type inference failed for: r2v31, types: [int, boolean] */
    /* JADX WARN: Type inference failed for: r2v32 */
    @Override // r0.o0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public void W(r0.v0 r18, r0.a1 r19) {
        /*
            Method dump skipped, instructions count: 1224
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.LinearLayoutManager.W(r0.v0, r0.a1):void");
    }

    public void W0(boolean z) {
        c(null);
        if (this.f1048v == z) {
            return;
        }
        this.f1048v = z;
        g0();
    }

    @Override // r0.o0
    public void X(a1 a1Var) {
        this.z = null;
        this.f1050x = -1;
        this.f1051y = Integer.MIN_VALUE;
        this.A.c();
    }

    public final void X0(int i2, int i3, boolean z, a1 a1Var) {
        int h2;
        int z2;
        this.f1043q.l = this.f1044r.g() == 0 && this.f1044r.e() == 0;
        this.f1043q.f3101f = i2;
        int[] iArr = this.D;
        iArr[0] = 0;
        iArr[1] = 0;
        v0(a1Var, iArr);
        int max = Math.max(0, iArr[0]);
        int max2 = Math.max(0, iArr[1]);
        boolean z3 = i2 == 1;
        x xVar = this.f1043q;
        int i4 = z3 ? max2 : max;
        xVar.f3103h = i4;
        if (!z3) {
            max = max2;
        }
        xVar.f3104i = max;
        if (z3) {
            a0 a0Var = this.f1044r;
            int i5 = a0Var.f2834d;
            o0 o0Var = a0Var.f2853a;
            switch (i5) {
                case 0:
                    z2 = o0Var.B();
                    break;
                default:
                    z2 = o0Var.z();
                    break;
            }
            xVar.f3103h = z2 + i4;
            View M0 = M0();
            x xVar2 = this.f1043q;
            xVar2.f3100e = this.f1047u ? -1 : 1;
            int D = o0.D(M0);
            x xVar3 = this.f1043q;
            xVar2.f3099d = D + xVar3.f3100e;
            xVar3.f3097b = this.f1044r.b(M0);
            h2 = this.f1044r.b(M0) - this.f1044r.f();
        } else {
            View N0 = N0();
            x xVar4 = this.f1043q;
            xVar4.f3103h = this.f1044r.h() + xVar4.f3103h;
            x xVar5 = this.f1043q;
            xVar5.f3100e = this.f1047u ? 1 : -1;
            int D2 = o0.D(N0);
            x xVar6 = this.f1043q;
            xVar5.f3099d = D2 + xVar6.f3100e;
            xVar6.f3097b = this.f1044r.d(N0);
            h2 = (-this.f1044r.d(N0)) + this.f1044r.h();
        }
        x xVar7 = this.f1043q;
        xVar7.f3098c = i3;
        if (z) {
            xVar7.f3098c = i3 - h2;
        }
        xVar7.f3102g = h2;
    }

    @Override // r0.o0
    public final void Y(Parcelable parcelable) {
        if (parcelable instanceof y) {
            this.z = (y) parcelable;
            g0();
        }
    }

    public final void Y0(int i2, int i3) {
        this.f1043q.f3098c = this.f1044r.f() - i3;
        x xVar = this.f1043q;
        xVar.f3100e = this.f1047u ? -1 : 1;
        xVar.f3099d = i2;
        xVar.f3101f = 1;
        xVar.f3097b = i3;
        xVar.f3102g = Integer.MIN_VALUE;
    }

    @Override // r0.o0
    public final Parcelable Z() {
        y yVar = this.z;
        if (yVar != null) {
            return new y(yVar);
        }
        y yVar2 = new y();
        if (v() > 0) {
            B0();
            boolean z = this.f1045s ^ this.f1047u;
            yVar2.f3110c = z;
            if (z) {
                View M0 = M0();
                yVar2.f3109b = this.f1044r.f() - this.f1044r.b(M0);
                yVar2.f3108a = o0.D(M0);
            } else {
                View N0 = N0();
                yVar2.f3108a = o0.D(N0);
                yVar2.f3109b = this.f1044r.d(N0) - this.f1044r.h();
            }
        } else {
            yVar2.f3108a = -1;
        }
        return yVar2;
    }

    public final void Z0(int i2, int i3) {
        this.f1043q.f3098c = i3 - this.f1044r.h();
        x xVar = this.f1043q;
        xVar.f3099d = i2;
        xVar.f3100e = this.f1047u ? 1 : -1;
        xVar.f3101f = -1;
        xVar.f3097b = i3;
        xVar.f3102g = Integer.MIN_VALUE;
    }

    @Override // r0.z0
    public final PointF a(int i2) {
        if (v() == 0) {
            return null;
        }
        int i3 = (i2 < o0.D(u(0))) != this.f1047u ? -1 : 1;
        return this.f1042p == 0 ? new PointF(i3, 0.0f) : new PointF(0.0f, i3);
    }

    @Override // r0.o0
    public final void c(String str) {
        RecyclerView recyclerView;
        if (this.z != null || (recyclerView = this.f2999b) == null) {
            return;
        }
        recyclerView.i(str);
    }

    @Override // r0.o0
    public final boolean d() {
        return this.f1042p == 0;
    }

    @Override // r0.o0
    public final boolean e() {
        return this.f1042p == 1;
    }

    @Override // r0.o0
    public final void h(int i2, int i3, a1 a1Var, q qVar) {
        if (this.f1042p != 0) {
            i2 = i3;
        }
        if (v() == 0 || i2 == 0) {
            return;
        }
        B0();
        X0(i2 > 0 ? 1 : -1, Math.abs(i2), true, a1Var);
        w0(a1Var, this.f1043q, qVar);
    }

    @Override // r0.o0
    public int h0(int i2, v0 v0Var, a1 a1Var) {
        if (this.f1042p == 1) {
            return 0;
        }
        return U0(i2, v0Var, a1Var);
    }

    /* JADX WARN: Removed duplicated region for block: B:16:0x0024  */
    @Override // r0.o0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public final void i(int r7, r0.q r8) {
        /*
            r6 = this;
            r0.y r0 = r6.z
            r1 = 1
            r2 = -1
            r3 = 0
            if (r0 == 0) goto L13
            int r4 = r0.f3108a
            if (r4 < 0) goto Ld
            r5 = r1
            goto Le
        Ld:
            r5 = r3
        Le:
            if (r5 == 0) goto L13
            boolean r0 = r0.f3110c
            goto L22
        L13:
            r6.T0()
            boolean r0 = r6.f1047u
            int r4 = r6.f1050x
            if (r4 != r2) goto L22
            if (r0 == 0) goto L21
            int r4 = r7 + (-1)
            goto L22
        L21:
            r4 = r3
        L22:
            if (r0 == 0) goto L25
            r1 = r2
        L25:
            r0 = r3
        L26:
            int r2 = r6.C
            if (r0 >= r2) goto L35
            if (r4 < 0) goto L35
            if (r4 >= r7) goto L35
            r8.a(r4, r3)
            int r4 = r4 + r1
            int r0 = r0 + 1
            goto L26
        L35:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.LinearLayoutManager.i(int, r0.q):void");
    }

    @Override // r0.o0
    public final void i0(int i2) {
        this.f1050x = i2;
        this.f1051y = Integer.MIN_VALUE;
        y yVar = this.z;
        if (yVar != null) {
            yVar.f3108a = -1;
        }
        g0();
    }

    @Override // r0.o0
    public final int j(a1 a1Var) {
        return x0(a1Var);
    }

    @Override // r0.o0
    public int j0(int i2, v0 v0Var, a1 a1Var) {
        if (this.f1042p == 0) {
            return 0;
        }
        return U0(i2, v0Var, a1Var);
    }

    @Override // r0.o0
    public int k(a1 a1Var) {
        return y0(a1Var);
    }

    @Override // r0.o0
    public int l(a1 a1Var) {
        return z0(a1Var);
    }

    @Override // r0.o0
    public final int m(a1 a1Var) {
        return x0(a1Var);
    }

    @Override // r0.o0
    public int n(a1 a1Var) {
        return y0(a1Var);
    }

    @Override // r0.o0
    public int o(a1 a1Var) {
        return z0(a1Var);
    }

    @Override // r0.o0
    public final View q(int i2) {
        int v2 = v();
        if (v2 == 0) {
            return null;
        }
        int D = i2 - o0.D(u(0));
        if (D >= 0 && D < v2) {
            View u2 = u(D);
            if (o0.D(u2) == i2) {
                return u2;
            }
        }
        return super.q(i2);
    }

    @Override // r0.o0
    public final boolean q0() {
        boolean z;
        if (this.f3009m == 1073741824 || this.l == 1073741824) {
            return false;
        }
        int v2 = v();
        int i2 = 0;
        while (true) {
            if (i2 >= v2) {
                z = false;
                break;
            }
            ViewGroup.LayoutParams layoutParams = u(i2).getLayoutParams();
            if (layoutParams.width < 0 && layoutParams.height < 0) {
                z = true;
                break;
            }
            i2++;
        }
        return z;
    }

    @Override // r0.o0
    public p0 r() {
        return new p0(-2, -2);
    }

    @Override // r0.o0
    public void s0(RecyclerView recyclerView, int i2) {
        r0.z zVar = new r0.z(recyclerView.getContext());
        zVar.f3118a = i2;
        t0(zVar);
    }

    @Override // r0.o0
    public boolean u0() {
        return this.z == null && this.f1045s == this.f1048v;
    }

    public void v0(a1 a1Var, int[] iArr) {
        int i2;
        int i3 = a1Var.f2835a != -1 ? this.f1044r.i() : 0;
        if (this.f1043q.f3101f == -1) {
            i2 = 0;
        } else {
            i2 = i3;
            i3 = 0;
        }
        iArr[0] = i3;
        iArr[1] = i2;
    }

    public void w0(a1 a1Var, x xVar, q qVar) {
        int i2 = xVar.f3099d;
        if (i2 < 0 || i2 >= a1Var.b()) {
            return;
        }
        qVar.a(i2, Math.max(0, xVar.f3102g));
    }

    public final int x0(a1 a1Var) {
        if (v() == 0) {
            return 0;
        }
        B0();
        a0 a0Var = this.f1044r;
        boolean z = !this.f1049w;
        return i.z(a1Var, a0Var, E0(z), D0(z), this, this.f1049w);
    }

    public final int y0(a1 a1Var) {
        if (v() == 0) {
            return 0;
        }
        B0();
        a0 a0Var = this.f1044r;
        boolean z = !this.f1049w;
        return i.A(a1Var, a0Var, E0(z), D0(z), this, this.f1049w, this.f1047u);
    }

    public final int z0(a1 a1Var) {
        if (v() == 0) {
            return 0;
        }
        B0();
        a0 a0Var = this.f1044r;
        boolean z = !this.f1049w;
        return i.B(a1Var, a0Var, E0(z), D0(z), this, this.f1049w);
    }

    public LinearLayoutManager(Context context, AttributeSet attributeSet, int i2, int i3) {
        this.f1042p = 1;
        this.f1046t = false;
        this.f1047u = false;
        this.f1048v = false;
        this.f1049w = true;
        this.f1050x = -1;
        this.f1051y = Integer.MIN_VALUE;
        this.z = null;
        this.A = new v();
        this.B = new w();
        this.C = 2;
        this.D = new int[2];
        n0 E = o0.E(context, attributeSet, i2, i3);
        V0(E.f2993a);
        boolean z = E.f2995c;
        c(null);
        if (z != this.f1046t) {
            this.f1046t = z;
            g0();
        }
        W0(E.f2996d);
    }
}