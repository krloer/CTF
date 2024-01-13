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
import d.c0;
import e0.y;
import e0.z;
import f0.c;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.List;
import java.util.WeakHashMap;
import r0.a1;
import r0.b0;
import r0.h1;
import r0.i1;
import r0.k1;
import r0.l;
import r0.l1;
import r0.n0;
import r0.o0;
import r0.p0;
import r0.p1;
import r0.q;
import r0.u;
import r0.v0;
import r0.z0;

/* loaded from: classes.dex */
public class StaggeredGridLayoutManager extends o0 implements z0 {
    public final p1 B;
    public final int C;
    public boolean D;
    public boolean E;
    public k1 F;
    public final Rect G;
    public final h1 H;
    public final boolean I;
    public int[] J;
    public final l K;

    /* renamed from: p  reason: collision with root package name */
    public int f1097p;

    /* renamed from: q  reason: collision with root package name */
    public l1[] f1098q;

    /* renamed from: r  reason: collision with root package name */
    public b0 f1099r;

    /* renamed from: s  reason: collision with root package name */
    public b0 f1100s;

    /* renamed from: t  reason: collision with root package name */
    public int f1101t;

    /* renamed from: u  reason: collision with root package name */
    public int f1102u;

    /* renamed from: v  reason: collision with root package name */
    public final u f1103v;

    /* renamed from: w  reason: collision with root package name */
    public boolean f1104w;

    /* renamed from: y  reason: collision with root package name */
    public BitSet f1106y;

    /* renamed from: x  reason: collision with root package name */
    public boolean f1105x = false;
    public int z = -1;
    public int A = Integer.MIN_VALUE;

    public StaggeredGridLayoutManager(Context context, AttributeSet attributeSet, int i2, int i3) {
        this.f1097p = -1;
        this.f1104w = false;
        p1 p1Var = new p1(1);
        this.B = p1Var;
        this.C = 2;
        this.G = new Rect();
        this.H = new h1(this);
        this.I = true;
        this.K = new l(1, this);
        n0 E = o0.E(context, attributeSet, i2, i3);
        int i4 = E.f2993a;
        if (i4 != 0 && i4 != 1) {
            throw new IllegalArgumentException("invalid orientation.");
        }
        c(null);
        if (i4 != this.f1101t) {
            this.f1101t = i4;
            b0 b0Var = this.f1099r;
            this.f1099r = this.f1100s;
            this.f1100s = b0Var;
            g0();
        }
        int i5 = E.f2994b;
        c(null);
        if (i5 != this.f1097p) {
            p1Var.d();
            g0();
            this.f1097p = i5;
            this.f1106y = new BitSet(this.f1097p);
            this.f1098q = new l1[this.f1097p];
            for (int i6 = 0; i6 < this.f1097p; i6++) {
                this.f1098q[i6] = new l1(this, i6);
            }
            g0();
        }
        boolean z = E.f2995c;
        c(null);
        k1 k1Var = this.F;
        if (k1Var != null && k1Var.f2967h != z) {
            k1Var.f2967h = z;
        }
        this.f1104w = z;
        g0();
        this.f1103v = new u();
        this.f1099r = b0.a(this, this.f1101t);
        this.f1100s = b0.a(this, 1 - this.f1101t);
    }

    public static int X0(int i2, int i3, int i4) {
        if (i3 == 0 && i4 == 0) {
            return i2;
        }
        int mode = View.MeasureSpec.getMode(i2);
        return (mode == Integer.MIN_VALUE || mode == 1073741824) ? View.MeasureSpec.makeMeasureSpec(Math.max(0, (View.MeasureSpec.getSize(i2) - i3) - i4), mode) : i2;
    }

    /* JADX WARN: Type inference failed for: r8v0 */
    /* JADX WARN: Type inference failed for: r8v1, types: [int, boolean] */
    /* JADX WARN: Type inference failed for: r8v31 */
    public final int A0(v0 v0Var, u uVar, a1 a1Var) {
        l1 l1Var;
        ?? r8;
        int w2;
        int i2;
        int w3;
        int i3;
        int c2;
        int h2;
        int c3;
        int i4;
        int i5;
        int i6;
        int i7;
        int i8 = 0;
        int i9 = 1;
        this.f1106y.set(0, this.f1097p, true);
        u uVar2 = this.f1103v;
        int i10 = uVar2.f3076i ? uVar.f3072e == 1 ? Integer.MAX_VALUE : Integer.MIN_VALUE : uVar.f3072e == 1 ? uVar.f3074g + uVar.f3069b : uVar.f3073f - uVar.f3069b;
        int i11 = uVar.f3072e;
        for (int i12 = 0; i12 < this.f1097p; i12++) {
            if (!this.f1098q[i12].f2978a.isEmpty()) {
                W0(this.f1098q[i12], i11, i10);
            }
        }
        int f2 = this.f1105x ? this.f1099r.f() : this.f1099r.h();
        boolean z = false;
        while (true) {
            int i13 = uVar.f3070c;
            if (((i13 < 0 || i13 >= a1Var.b()) ? i8 : i9) == 0 || (!uVar2.f3076i && this.f1106y.isEmpty())) {
                break;
            }
            View view = v0Var.i(uVar.f3070c, Long.MAX_VALUE).f2875a;
            uVar.f3070c += uVar.f3071d;
            i1 i1Var = (i1) view.getLayoutParams();
            int a2 = i1Var.a();
            p1 p1Var = this.B;
            int[] iArr = (int[]) p1Var.f3045b;
            int i14 = (iArr == null || a2 >= iArr.length) ? -1 : iArr[a2];
            if ((i14 == -1 ? i9 : i8) != 0) {
                if (N0(uVar.f3072e)) {
                    i7 = this.f1097p - i9;
                    i6 = -1;
                    i5 = -1;
                } else {
                    i5 = i9;
                    i6 = this.f1097p;
                    i7 = i8;
                }
                l1 l1Var2 = null;
                if (uVar.f3072e == i9) {
                    int h3 = this.f1099r.h();
                    int i15 = Integer.MAX_VALUE;
                    while (i7 != i6) {
                        l1 l1Var3 = this.f1098q[i7];
                        int f3 = l1Var3.f(h3);
                        if (f3 < i15) {
                            i15 = f3;
                            l1Var2 = l1Var3;
                        }
                        i7 += i5;
                    }
                } else {
                    int f4 = this.f1099r.f();
                    int i16 = Integer.MIN_VALUE;
                    while (i7 != i6) {
                        l1 l1Var4 = this.f1098q[i7];
                        int i17 = l1Var4.i(f4);
                        if (i17 > i16) {
                            l1Var2 = l1Var4;
                            i16 = i17;
                        }
                        i7 += i5;
                    }
                }
                l1Var = l1Var2;
                p1Var.e(a2);
                ((int[]) p1Var.f3045b)[a2] = l1Var.f2982e;
            } else {
                l1Var = this.f1098q[i14];
            }
            i1Var.f2934e = l1Var;
            if (uVar.f3072e == 1) {
                r8 = 0;
                b(view, -1, false);
            } else {
                r8 = 0;
                b(view, 0, false);
            }
            if (this.f1101t == 1) {
                w2 = o0.w(r8, this.f1102u, this.l, r8, ((ViewGroup.MarginLayoutParams) i1Var).width);
                w3 = o0.w(true, this.f3011o, this.f3009m, z() + C(), ((ViewGroup.MarginLayoutParams) i1Var).height);
                i2 = 0;
            } else {
                w2 = o0.w(true, this.f3010n, this.l, B() + A(), ((ViewGroup.MarginLayoutParams) i1Var).width);
                i2 = 0;
                w3 = o0.w(false, this.f1102u, this.f3009m, 0, ((ViewGroup.MarginLayoutParams) i1Var).height);
            }
            RecyclerView recyclerView = this.f2999b;
            Rect rect = this.G;
            if (recyclerView == null) {
                rect.set(i2, i2, i2, i2);
            } else {
                rect.set(recyclerView.J(view));
            }
            i1 i1Var2 = (i1) view.getLayoutParams();
            int X0 = X0(w2, ((ViewGroup.MarginLayoutParams) i1Var2).leftMargin + rect.left, ((ViewGroup.MarginLayoutParams) i1Var2).rightMargin + rect.right);
            int X02 = X0(w3, ((ViewGroup.MarginLayoutParams) i1Var2).topMargin + rect.top, ((ViewGroup.MarginLayoutParams) i1Var2).bottomMargin + rect.bottom);
            if (p0(view, X0, X02, i1Var2)) {
                view.measure(X0, X02);
            }
            if (uVar.f3072e == 1) {
                c2 = l1Var.f(f2);
                i3 = this.f1099r.c(view) + c2;
            } else {
                i3 = l1Var.i(f2);
                c2 = i3 - this.f1099r.c(view);
            }
            int i18 = uVar.f3072e;
            l1 l1Var5 = i1Var.f2934e;
            l1Var5.getClass();
            if (i18 == 1) {
                i1 i1Var3 = (i1) view.getLayoutParams();
                i1Var3.f2934e = l1Var5;
                ArrayList arrayList = l1Var5.f2978a;
                arrayList.add(view);
                l1Var5.f2980c = Integer.MIN_VALUE;
                if (arrayList.size() == 1) {
                    l1Var5.f2979b = Integer.MIN_VALUE;
                }
                if (i1Var3.c() || i1Var3.b()) {
                    l1Var5.f2981d = l1Var5.f2983f.f1099r.c(view) + l1Var5.f2981d;
                }
            } else {
                i1 i1Var4 = (i1) view.getLayoutParams();
                i1Var4.f2934e = l1Var5;
                ArrayList arrayList2 = l1Var5.f2978a;
                arrayList2.add(0, view);
                l1Var5.f2979b = Integer.MIN_VALUE;
                if (arrayList2.size() == 1) {
                    l1Var5.f2980c = Integer.MIN_VALUE;
                }
                if (i1Var4.c() || i1Var4.b()) {
                    l1Var5.f2981d = l1Var5.f2983f.f1099r.c(view) + l1Var5.f2981d;
                }
            }
            if (L0() && this.f1101t == 1) {
                c3 = this.f1100s.f() - (((this.f1097p - 1) - l1Var.f2982e) * this.f1102u);
                h2 = c3 - this.f1100s.c(view);
            } else {
                h2 = this.f1100s.h() + (l1Var.f2982e * this.f1102u);
                c3 = this.f1100s.c(view) + h2;
            }
            if (this.f1101t == 1) {
                int i19 = h2;
                h2 = c2;
                c2 = i19;
                int i20 = c3;
                c3 = i3;
                i3 = i20;
            }
            o0.J(view, c2, h2, i3, c3);
            W0(l1Var, uVar2.f3072e, i10);
            P0(v0Var, uVar2);
            if (uVar2.f3075h && view.hasFocusable()) {
                i4 = 0;
                this.f1106y.set(l1Var.f2982e, false);
            } else {
                i4 = 0;
            }
            i8 = i4;
            i9 = 1;
            z = true;
        }
        int i21 = i8;
        if (!z) {
            P0(v0Var, uVar2);
        }
        int h4 = uVar2.f3072e == -1 ? this.f1099r.h() - I0(this.f1099r.h()) : H0(this.f1099r.f()) - this.f1099r.f();
        return h4 > 0 ? Math.min(uVar.f3069b, h4) : i21;
    }

    public final View B0(boolean z) {
        int h2 = this.f1099r.h();
        int f2 = this.f1099r.f();
        View view = null;
        for (int v2 = v() - 1; v2 >= 0; v2--) {
            View u2 = u(v2);
            int d2 = this.f1099r.d(u2);
            int b2 = this.f1099r.b(u2);
            if (b2 > h2 && d2 < f2) {
                if (b2 <= f2 || !z) {
                    return u2;
                }
                if (view == null) {
                    view = u2;
                }
            }
        }
        return view;
    }

    public final View C0(boolean z) {
        int h2 = this.f1099r.h();
        int f2 = this.f1099r.f();
        int v2 = v();
        View view = null;
        for (int i2 = 0; i2 < v2; i2++) {
            View u2 = u(i2);
            int d2 = this.f1099r.d(u2);
            if (this.f1099r.b(u2) > h2 && d2 < f2) {
                if (d2 >= h2 || !z) {
                    return u2;
                }
                if (view == null) {
                    view = u2;
                }
            }
        }
        return view;
    }

    public final void D0(v0 v0Var, a1 a1Var, boolean z) {
        int f2;
        int H0 = H0(Integer.MIN_VALUE);
        if (H0 != Integer.MIN_VALUE && (f2 = this.f1099r.f() - H0) > 0) {
            int i2 = f2 - (-T0(-f2, v0Var, a1Var));
            if (!z || i2 <= 0) {
                return;
            }
            this.f1099r.m(i2);
        }
    }

    public final void E0(v0 v0Var, a1 a1Var, boolean z) {
        int h2;
        int I0 = I0(Integer.MAX_VALUE);
        if (I0 != Integer.MAX_VALUE && (h2 = I0 - this.f1099r.h()) > 0) {
            int T0 = h2 - T0(h2, v0Var, a1Var);
            if (!z || T0 <= 0) {
                return;
            }
            this.f1099r.m(-T0);
        }
    }

    @Override // r0.o0
    public final int F(v0 v0Var, a1 a1Var) {
        return this.f1101t == 0 ? this.f1097p : super.F(v0Var, a1Var);
    }

    public final int F0() {
        if (v() == 0) {
            return 0;
        }
        return o0.D(u(0));
    }

    public final int G0() {
        int v2 = v();
        if (v2 == 0) {
            return 0;
        }
        return o0.D(u(v2 - 1));
    }

    @Override // r0.o0
    public final boolean H() {
        return this.C != 0;
    }

    public final int H0(int i2) {
        int f2 = this.f1098q[0].f(i2);
        for (int i3 = 1; i3 < this.f1097p; i3++) {
            int f3 = this.f1098q[i3].f(i2);
            if (f3 > f2) {
                f2 = f3;
            }
        }
        return f2;
    }

    public final int I0(int i2) {
        int i3 = this.f1098q[0].i(i2);
        for (int i4 = 1; i4 < this.f1097p; i4++) {
            int i5 = this.f1098q[i4].i(i2);
            if (i5 < i3) {
                i3 = i5;
            }
        }
        return i3;
    }

    /* JADX WARN: Removed duplicated region for block: B:15:0x0025  */
    /* JADX WARN: Removed duplicated region for block: B:21:0x0036  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x003b A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:24:0x003c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public final void J0(int r8, int r9, int r10) {
        /*
            r7 = this;
            boolean r0 = r7.f1105x
            if (r0 == 0) goto L9
            int r0 = r7.G0()
            goto Ld
        L9:
            int r0 = r7.F0()
        Ld:
            r1 = 8
            if (r10 != r1) goto L1a
            if (r8 >= r9) goto L16
            int r2 = r9 + 1
            goto L1c
        L16:
            int r2 = r8 + 1
            r3 = r9
            goto L1d
        L1a:
            int r2 = r8 + r9
        L1c:
            r3 = r8
        L1d:
            r0.p1 r4 = r7.B
            r4.g(r3)
            r5 = 1
            if (r10 == r5) goto L36
            r6 = 2
            if (r10 == r6) goto L32
            if (r10 == r1) goto L2b
            goto L39
        L2b:
            r4.j(r8, r5)
            r4.i(r9, r5)
            goto L39
        L32:
            r4.j(r8, r9)
            goto L39
        L36:
            r4.i(r8, r9)
        L39:
            if (r2 > r0) goto L3c
            return
        L3c:
            boolean r8 = r7.f1105x
            if (r8 == 0) goto L45
            int r8 = r7.F0()
            goto L49
        L45:
            int r8 = r7.G0()
        L49:
            if (r3 > r8) goto L4e
            r7.g0()
        L4e:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.StaggeredGridLayoutManager.J0(int, int, int):void");
    }

    @Override // r0.o0
    public final void K(int i2) {
        super.K(i2);
        for (int i3 = 0; i3 < this.f1097p; i3++) {
            l1 l1Var = this.f1098q[i3];
            int i4 = l1Var.f2979b;
            if (i4 != Integer.MIN_VALUE) {
                l1Var.f2979b = i4 + i2;
            }
            int i5 = l1Var.f2980c;
            if (i5 != Integer.MIN_VALUE) {
                l1Var.f2980c = i5 + i2;
            }
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:45:0x00cb, code lost:
        if (r10 == r11) goto L60;
     */
    /* JADX WARN: Code restructure failed: missing block: B:50:0x00dd, code lost:
        if (r10 == r11) goto L60;
     */
    /* JADX WARN: Code restructure failed: missing block: B:51:0x00df, code lost:
        r10 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:52:0x00e1, code lost:
        r10 = false;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public final android.view.View K0() {
        /*
            Method dump skipped, instructions count: 258
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.StaggeredGridLayoutManager.K0():android.view.View");
    }

    @Override // r0.o0
    public final void L(int i2) {
        super.L(i2);
        for (int i3 = 0; i3 < this.f1097p; i3++) {
            l1 l1Var = this.f1098q[i3];
            int i4 = l1Var.f2979b;
            if (i4 != Integer.MIN_VALUE) {
                l1Var.f2979b = i4 + i2;
            }
            int i5 = l1Var.f2980c;
            if (i5 != Integer.MIN_VALUE) {
                l1Var.f2980c = i5 + i2;
            }
        }
    }

    public final boolean L0() {
        RecyclerView recyclerView = this.f2999b;
        WeakHashMap weakHashMap = e0.o0.f1697a;
        return z.d(recyclerView) == 1;
    }

    @Override // r0.o0
    public final void M(RecyclerView recyclerView) {
        RecyclerView recyclerView2 = this.f2999b;
        if (recyclerView2 != null) {
            recyclerView2.removeCallbacks(this.K);
        }
        for (int i2 = 0; i2 < this.f1097p; i2++) {
            this.f1098q[i2].b();
        }
        recyclerView.requestLayout();
    }

    /* JADX WARN: Code restructure failed: missing block: B:253:0x03e9, code lost:
        if (w0() != false) goto L264;
     */
    /* JADX WARN: Removed duplicated region for block: B:118:0x01bc  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public final void M0(r0.v0 r17, r0.a1 r18, boolean r19) {
        /*
            Method dump skipped, instructions count: 1031
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.StaggeredGridLayoutManager.M0(r0.v0, r0.a1, boolean):void");
    }

    /* JADX WARN: Code restructure failed: missing block: B:36:0x004a, code lost:
        if (r8.f1101t == 1) goto L115;
     */
    /* JADX WARN: Code restructure failed: missing block: B:39:0x004f, code lost:
        if (r8.f1101t == 0) goto L115;
     */
    /* JADX WARN: Code restructure failed: missing block: B:46:0x005d, code lost:
        if (L0() == false) goto L24;
     */
    /* JADX WARN: Code restructure failed: missing block: B:52:0x0069, code lost:
        if (L0() == false) goto L115;
     */
    @Override // r0.o0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public final android.view.View N(android.view.View r9, int r10, r0.v0 r11, r0.a1 r12) {
        /*
            Method dump skipped, instructions count: 343
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.StaggeredGridLayoutManager.N(android.view.View, int, r0.v0, r0.a1):android.view.View");
    }

    public final boolean N0(int i2) {
        if (this.f1101t == 0) {
            return (i2 == -1) != this.f1105x;
        }
        return ((i2 == -1) == this.f1105x) == L0();
    }

    @Override // r0.o0
    public final void O(AccessibilityEvent accessibilityEvent) {
        super.O(accessibilityEvent);
        if (v() > 0) {
            View C0 = C0(false);
            View B0 = B0(false);
            if (C0 == null || B0 == null) {
                return;
            }
            int D = o0.D(C0);
            int D2 = o0.D(B0);
            if (D < D2) {
                accessibilityEvent.setFromIndex(D);
                accessibilityEvent.setToIndex(D2);
                return;
            }
            accessibilityEvent.setFromIndex(D2);
            accessibilityEvent.setToIndex(D);
        }
    }

    public final void O0(int i2, a1 a1Var) {
        int F0;
        int i3;
        if (i2 > 0) {
            F0 = G0();
            i3 = 1;
        } else {
            F0 = F0();
            i3 = -1;
        }
        u uVar = this.f1103v;
        uVar.f3068a = true;
        V0(F0, a1Var);
        U0(i3);
        uVar.f3070c = F0 + uVar.f3071d;
        uVar.f3069b = Math.abs(i2);
    }

    /* JADX WARN: Code restructure failed: missing block: B:10:0x0011, code lost:
        if (r6.f3072e == (-1)) goto L9;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public final void P0(r0.v0 r5, r0.u r6) {
        /*
            r4 = this;
            boolean r0 = r6.f3068a
            if (r0 == 0) goto L7c
            boolean r0 = r6.f3076i
            if (r0 == 0) goto La
            goto L7c
        La:
            int r0 = r6.f3069b
            r1 = -1
            if (r0 != 0) goto L1f
            int r0 = r6.f3072e
            if (r0 != r1) goto L19
        L13:
            int r6 = r6.f3074g
        L15:
            r4.Q0(r6, r5)
            goto L7c
        L19:
            int r6 = r6.f3073f
        L1b:
            r4.R0(r6, r5)
            goto L7c
        L1f:
            int r0 = r6.f3072e
            r2 = 0
            r3 = 1
            if (r0 != r1) goto L50
            int r0 = r6.f3073f
            r0.l1[] r1 = r4.f1098q
            r1 = r1[r2]
            int r1 = r1.i(r0)
        L2f:
            int r2 = r4.f1097p
            if (r3 >= r2) goto L41
            r0.l1[] r2 = r4.f1098q
            r2 = r2[r3]
            int r2 = r2.i(r0)
            if (r2 <= r1) goto L3e
            r1 = r2
        L3e:
            int r3 = r3 + 1
            goto L2f
        L41:
            int r0 = r0 - r1
            if (r0 >= 0) goto L45
            goto L13
        L45:
            int r1 = r6.f3074g
            int r6 = r6.f3069b
            int r6 = java.lang.Math.min(r0, r6)
            int r6 = r1 - r6
            goto L15
        L50:
            int r0 = r6.f3074g
            r0.l1[] r1 = r4.f1098q
            r1 = r1[r2]
            int r1 = r1.f(r0)
        L5a:
            int r2 = r4.f1097p
            if (r3 >= r2) goto L6c
            r0.l1[] r2 = r4.f1098q
            r2 = r2[r3]
            int r2 = r2.f(r0)
            if (r2 >= r1) goto L69
            r1 = r2
        L69:
            int r3 = r3 + 1
            goto L5a
        L6c:
            int r0 = r6.f3074g
            int r1 = r1 - r0
            if (r1 >= 0) goto L72
            goto L19
        L72:
            int r0 = r6.f3073f
            int r6 = r6.f3069b
            int r6 = java.lang.Math.min(r1, r6)
            int r6 = r6 + r0
            goto L1b
        L7c:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.StaggeredGridLayoutManager.P0(r0.v0, r0.u):void");
    }

    @Override // r0.o0
    public final void Q(v0 v0Var, a1 a1Var, View view, c cVar) {
        int i2;
        int i3;
        ViewGroup.LayoutParams layoutParams = view.getLayoutParams();
        if (!(layoutParams instanceof i1)) {
            P(view, cVar);
            return;
        }
        i1 i1Var = (i1) layoutParams;
        int i4 = 1;
        int i5 = -1;
        if (this.f1101t == 0) {
            l1 l1Var = i1Var.f2934e;
            i3 = l1Var == null ? -1 : l1Var.f2982e;
            i2 = -1;
        } else {
            l1 l1Var2 = i1Var.f2934e;
            i2 = l1Var2 == null ? -1 : l1Var2.f2982e;
            i3 = -1;
            i5 = 1;
            i4 = -1;
        }
        cVar.f(c0.a(i3, i4, i2, i5, false));
    }

    public final void Q0(int i2, v0 v0Var) {
        for (int v2 = v() - 1; v2 >= 0; v2--) {
            View u2 = u(v2);
            if (this.f1099r.d(u2) < i2 || this.f1099r.l(u2) < i2) {
                return;
            }
            i1 i1Var = (i1) u2.getLayoutParams();
            i1Var.getClass();
            if (i1Var.f2934e.f2978a.size() == 1) {
                return;
            }
            l1 l1Var = i1Var.f2934e;
            ArrayList arrayList = l1Var.f2978a;
            int size = arrayList.size();
            View view = (View) arrayList.remove(size - 1);
            i1 h2 = l1.h(view);
            h2.f2934e = null;
            if (h2.c() || h2.b()) {
                l1Var.f2981d -= l1Var.f2983f.f1099r.c(view);
            }
            if (size == 1) {
                l1Var.f2979b = Integer.MIN_VALUE;
            }
            l1Var.f2980c = Integer.MIN_VALUE;
            d0(u2, v0Var);
        }
    }

    @Override // r0.o0
    public final void R(int i2, int i3) {
        J0(i2, i3, 1);
    }

    public final void R0(int i2, v0 v0Var) {
        while (v() > 0) {
            View u2 = u(0);
            if (this.f1099r.b(u2) > i2 || this.f1099r.k(u2) > i2) {
                return;
            }
            i1 i1Var = (i1) u2.getLayoutParams();
            i1Var.getClass();
            if (i1Var.f2934e.f2978a.size() == 1) {
                return;
            }
            l1 l1Var = i1Var.f2934e;
            ArrayList arrayList = l1Var.f2978a;
            View view = (View) arrayList.remove(0);
            i1 h2 = l1.h(view);
            h2.f2934e = null;
            if (arrayList.size() == 0) {
                l1Var.f2980c = Integer.MIN_VALUE;
            }
            if (h2.c() || h2.b()) {
                l1Var.f2981d -= l1Var.f2983f.f1099r.c(view);
            }
            l1Var.f2979b = Integer.MIN_VALUE;
            d0(u2, v0Var);
        }
    }

    @Override // r0.o0
    public final void S() {
        this.B.d();
        g0();
    }

    public final void S0() {
        this.f1105x = (this.f1101t == 1 || !L0()) ? this.f1104w : !this.f1104w;
    }

    @Override // r0.o0
    public final void T(int i2, int i3) {
        J0(i2, i3, 8);
    }

    public final int T0(int i2, v0 v0Var, a1 a1Var) {
        if (v() == 0 || i2 == 0) {
            return 0;
        }
        O0(i2, a1Var);
        u uVar = this.f1103v;
        int A0 = A0(v0Var, uVar, a1Var);
        if (uVar.f3069b >= A0) {
            i2 = i2 < 0 ? -A0 : A0;
        }
        this.f1099r.m(-i2);
        this.D = this.f1105x;
        uVar.f3069b = 0;
        P0(v0Var, uVar);
        return i2;
    }

    @Override // r0.o0
    public final void U(int i2, int i3) {
        J0(i2, i3, 2);
    }

    public final void U0(int i2) {
        u uVar = this.f1103v;
        uVar.f3072e = i2;
        uVar.f3071d = this.f1105x != (i2 == -1) ? -1 : 1;
    }

    @Override // r0.o0
    public final void V(int i2, int i3) {
        J0(i2, i3, 4);
    }

    public final void V0(int i2, a1 a1Var) {
        int i3;
        int i4;
        int i5;
        u uVar = this.f1103v;
        boolean z = false;
        uVar.f3069b = 0;
        uVar.f3070c = i2;
        r0.z zVar = this.f3002e;
        if (!(zVar != null && zVar.f3122e) || (i5 = a1Var.f2835a) == -1) {
            i3 = 0;
            i4 = 0;
        } else {
            if (this.f1105x == (i5 < i2)) {
                i3 = this.f1099r.i();
                i4 = 0;
            } else {
                i4 = this.f1099r.i();
                i3 = 0;
            }
        }
        RecyclerView recyclerView = this.f2999b;
        if (recyclerView != null && recyclerView.f1067g) {
            uVar.f3073f = this.f1099r.h() - i4;
            uVar.f3074g = this.f1099r.f() + i3;
        } else {
            uVar.f3074g = this.f1099r.e() + i3;
            uVar.f3073f = -i4;
        }
        uVar.f3075h = false;
        uVar.f3068a = true;
        if (this.f1099r.g() == 0 && this.f1099r.e() == 0) {
            z = true;
        }
        uVar.f3076i = z;
    }

    @Override // r0.o0
    public final void W(v0 v0Var, a1 a1Var) {
        M0(v0Var, a1Var, true);
    }

    public final void W0(l1 l1Var, int i2, int i3) {
        int i4 = l1Var.f2981d;
        if (i2 == -1) {
            int i5 = l1Var.f2979b;
            if (i5 == Integer.MIN_VALUE) {
                View view = (View) l1Var.f2978a.get(0);
                i1 h2 = l1.h(view);
                l1Var.f2979b = l1Var.f2983f.f1099r.d(view);
                h2.getClass();
                i5 = l1Var.f2979b;
            }
            if (i5 + i4 > i3) {
                return;
            }
        } else {
            int i6 = l1Var.f2980c;
            if (i6 == Integer.MIN_VALUE) {
                l1Var.a();
                i6 = l1Var.f2980c;
            }
            if (i6 - i4 < i3) {
                return;
            }
        }
        this.f1106y.set(l1Var.f2982e, false);
    }

    @Override // r0.o0
    public final void X(a1 a1Var) {
        this.z = -1;
        this.A = Integer.MIN_VALUE;
        this.F = null;
        this.H.a();
    }

    @Override // r0.o0
    public final void Y(Parcelable parcelable) {
        if (parcelable instanceof k1) {
            this.F = (k1) parcelable;
            g0();
        }
    }

    @Override // r0.o0
    public final Parcelable Z() {
        int i2;
        int h2;
        int[] iArr;
        k1 k1Var = this.F;
        if (k1Var != null) {
            return new k1(k1Var);
        }
        k1 k1Var2 = new k1();
        k1Var2.f2967h = this.f1104w;
        k1Var2.f2968i = this.D;
        k1Var2.f2969j = this.E;
        p1 p1Var = this.B;
        if (p1Var == null || (iArr = (int[]) p1Var.f3045b) == null) {
            k1Var2.f2964e = 0;
        } else {
            k1Var2.f2965f = iArr;
            k1Var2.f2964e = iArr.length;
            k1Var2.f2966g = (List) p1Var.f3046c;
        }
        if (v() > 0) {
            k1Var2.f2960a = this.D ? G0() : F0();
            View B0 = this.f1105x ? B0(true) : C0(true);
            k1Var2.f2961b = B0 != null ? o0.D(B0) : -1;
            int i3 = this.f1097p;
            k1Var2.f2962c = i3;
            k1Var2.f2963d = new int[i3];
            for (int i4 = 0; i4 < this.f1097p; i4++) {
                if (this.D) {
                    i2 = this.f1098q[i4].f(Integer.MIN_VALUE);
                    if (i2 != Integer.MIN_VALUE) {
                        h2 = this.f1099r.f();
                        i2 -= h2;
                        k1Var2.f2963d[i4] = i2;
                    } else {
                        k1Var2.f2963d[i4] = i2;
                    }
                } else {
                    i2 = this.f1098q[i4].i(Integer.MIN_VALUE);
                    if (i2 != Integer.MIN_VALUE) {
                        h2 = this.f1099r.h();
                        i2 -= h2;
                        k1Var2.f2963d[i4] = i2;
                    } else {
                        k1Var2.f2963d[i4] = i2;
                    }
                }
            }
        } else {
            k1Var2.f2960a = -1;
            k1Var2.f2961b = -1;
            k1Var2.f2962c = 0;
        }
        return k1Var2;
    }

    @Override // r0.z0
    public final PointF a(int i2) {
        int v02 = v0(i2);
        PointF pointF = new PointF();
        if (v02 == 0) {
            return null;
        }
        if (this.f1101t == 0) {
            pointF.x = v02;
            pointF.y = 0.0f;
        } else {
            pointF.x = 0.0f;
            pointF.y = v02;
        }
        return pointF;
    }

    @Override // r0.o0
    public final void a0(int i2) {
        if (i2 == 0) {
            w0();
        }
    }

    @Override // r0.o0
    public final void c(String str) {
        RecyclerView recyclerView;
        if (this.F != null || (recyclerView = this.f2999b) == null) {
            return;
        }
        recyclerView.i(str);
    }

    @Override // r0.o0
    public final boolean d() {
        return this.f1101t == 0;
    }

    @Override // r0.o0
    public final boolean e() {
        return this.f1101t == 1;
    }

    @Override // r0.o0
    public final boolean f(p0 p0Var) {
        return p0Var instanceof i1;
    }

    @Override // r0.o0
    public final void h(int i2, int i3, a1 a1Var, q qVar) {
        u uVar;
        int f2;
        int i4;
        if (this.f1101t != 0) {
            i2 = i3;
        }
        if (v() == 0 || i2 == 0) {
            return;
        }
        O0(i2, a1Var);
        int[] iArr = this.J;
        if (iArr == null || iArr.length < this.f1097p) {
            this.J = new int[this.f1097p];
        }
        int i5 = 0;
        int i6 = 0;
        while (true) {
            int i7 = this.f1097p;
            uVar = this.f1103v;
            if (i5 >= i7) {
                break;
            }
            if (uVar.f3071d == -1) {
                f2 = uVar.f3073f;
                i4 = this.f1098q[i5].i(f2);
            } else {
                f2 = this.f1098q[i5].f(uVar.f3074g);
                i4 = uVar.f3074g;
            }
            int i8 = f2 - i4;
            if (i8 >= 0) {
                this.J[i6] = i8;
                i6++;
            }
            i5++;
        }
        Arrays.sort(this.J, 0, i6);
        for (int i9 = 0; i9 < i6; i9++) {
            int i10 = uVar.f3070c;
            if (!(i10 >= 0 && i10 < a1Var.b())) {
                return;
            }
            qVar.a(uVar.f3070c, this.J[i9]);
            uVar.f3070c += uVar.f3071d;
        }
    }

    @Override // r0.o0
    public final int h0(int i2, v0 v0Var, a1 a1Var) {
        return T0(i2, v0Var, a1Var);
    }

    @Override // r0.o0
    public final void i0(int i2) {
        k1 k1Var = this.F;
        if (k1Var != null && k1Var.f2960a != i2) {
            k1Var.f2963d = null;
            k1Var.f2962c = 0;
            k1Var.f2960a = -1;
            k1Var.f2961b = -1;
        }
        this.z = i2;
        this.A = Integer.MIN_VALUE;
        g0();
    }

    @Override // r0.o0
    public final int j(a1 a1Var) {
        return x0(a1Var);
    }

    @Override // r0.o0
    public final int j0(int i2, v0 v0Var, a1 a1Var) {
        return T0(i2, v0Var, a1Var);
    }

    @Override // r0.o0
    public final int k(a1 a1Var) {
        return y0(a1Var);
    }

    @Override // r0.o0
    public final int l(a1 a1Var) {
        return z0(a1Var);
    }

    @Override // r0.o0
    public final int m(a1 a1Var) {
        return x0(a1Var);
    }

    @Override // r0.o0
    public final void m0(Rect rect, int i2, int i3) {
        int g2;
        int g3;
        int B = B() + A();
        int z = z() + C();
        if (this.f1101t == 1) {
            int height = rect.height() + z;
            RecyclerView recyclerView = this.f2999b;
            WeakHashMap weakHashMap = e0.o0.f1697a;
            g3 = o0.g(i3, height, y.d(recyclerView));
            g2 = o0.g(i2, (this.f1102u * this.f1097p) + B, y.e(this.f2999b));
        } else {
            int width = rect.width() + B;
            RecyclerView recyclerView2 = this.f2999b;
            WeakHashMap weakHashMap2 = e0.o0.f1697a;
            g2 = o0.g(i2, width, y.e(recyclerView2));
            g3 = o0.g(i3, (this.f1102u * this.f1097p) + z, y.d(this.f2999b));
        }
        this.f2999b.setMeasuredDimension(g2, g3);
    }

    @Override // r0.o0
    public final int n(a1 a1Var) {
        return y0(a1Var);
    }

    @Override // r0.o0
    public final int o(a1 a1Var) {
        return z0(a1Var);
    }

    @Override // r0.o0
    public final p0 r() {
        return this.f1101t == 0 ? new i1(-2, -1) : new i1(-1, -2);
    }

    @Override // r0.o0
    public final p0 s(Context context, AttributeSet attributeSet) {
        return new i1(context, attributeSet);
    }

    @Override // r0.o0
    public final void s0(RecyclerView recyclerView, int i2) {
        r0.z zVar = new r0.z(recyclerView.getContext());
        zVar.f3118a = i2;
        t0(zVar);
    }

    @Override // r0.o0
    public final p0 t(ViewGroup.LayoutParams layoutParams) {
        return layoutParams instanceof ViewGroup.MarginLayoutParams ? new i1((ViewGroup.MarginLayoutParams) layoutParams) : new i1(layoutParams);
    }

    @Override // r0.o0
    public final boolean u0() {
        return this.F == null;
    }

    public final int v0(int i2) {
        if (v() == 0) {
            return this.f1105x ? 1 : -1;
        }
        return (i2 < F0()) != this.f1105x ? -1 : 1;
    }

    public final boolean w0() {
        int F0;
        if (v() != 0 && this.C != 0 && this.f3004g) {
            if (this.f1105x) {
                F0 = G0();
                F0();
            } else {
                F0 = F0();
                G0();
            }
            if (F0 == 0 && K0() != null) {
                this.B.d();
                this.f3003f = true;
                g0();
                return true;
            }
        }
        return false;
    }

    @Override // r0.o0
    public final int x(v0 v0Var, a1 a1Var) {
        return this.f1101t == 1 ? this.f1097p : super.x(v0Var, a1Var);
    }

    public final int x0(a1 a1Var) {
        if (v() == 0) {
            return 0;
        }
        b0 b0Var = this.f1099r;
        boolean z = this.I;
        return i.z(a1Var, b0Var, C0(!z), B0(!z), this, this.I);
    }

    public final int y0(a1 a1Var) {
        if (v() == 0) {
            return 0;
        }
        b0 b0Var = this.f1099r;
        boolean z = this.I;
        return i.A(a1Var, b0Var, C0(!z), B0(!z), this, this.I, this.f1105x);
    }

    public final int z0(a1 a1Var) {
        if (v() == 0) {
            return 0;
        }
        b0 b0Var = this.f1099r;
        boolean z = this.I;
        return i.B(a1Var, b0Var, C0(!z), B0(!z), this, this.I);
    }
}