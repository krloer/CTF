package androidx.recyclerview.widget;

import android.animation.LayoutTransition;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Rect;
import android.graphics.RectF;
import android.os.Parcelable;
import android.os.SystemClock;
import android.os.Trace;
import android.util.AttributeSet;
import android.util.Log;
import android.util.SparseArray;
import android.view.MotionEvent;
import android.view.VelocityTracker;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityManager;
import android.widget.EdgeEffect;
import android.widget.OverScroller;
import c0.e;
import com.example.dropper.R;
import e0.k;
import e0.l;
import e0.y;
import j.j;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.WeakHashMap;
import k0.c;
import r0.a;
import r0.a1;
import r0.b;
import r0.b1;
import r0.c1;
import r0.d;
import r0.d1;
import r0.e0;
import r0.f0;
import r0.f1;
import r0.g0;
import r0.i0;
import r0.j0;
import r0.k0;
import r0.l0;
import r0.m0;
import r0.o0;
import r0.o1;
import r0.p0;
import r0.p1;
import r0.q;
import r0.q0;
import r0.r0;
import r0.s;
import r0.s0;
import r0.t0;
import r0.u0;
import r0.v0;
import r0.w0;
import r0.x0;
import r0.z;

/* loaded from: classes.dex */
public class RecyclerView extends ViewGroup implements k {

    /* renamed from: s0  reason: collision with root package name */
    public static final int[] f1052s0 = {16843830};

    /* renamed from: t0  reason: collision with root package name */
    public static final Class[] f1053t0;

    /* renamed from: u0  reason: collision with root package name */
    public static final c f1054u0;
    public int A;
    public int B;
    public j0 C;
    public EdgeEffect D;
    public EdgeEffect E;
    public EdgeEffect F;
    public EdgeEffect G;
    public l0 H;
    public int I;
    public int J;
    public VelocityTracker K;
    public int L;
    public int M;
    public int N;
    public int O;
    public int P;
    public q0 Q;
    public final int R;
    public final int S;
    public final float T;
    public final float U;
    public boolean V;
    public final c1 W;

    /* renamed from: a  reason: collision with root package name */
    public final e f1055a;

    /* renamed from: a0  reason: collision with root package name */
    public s f1056a0;

    /* renamed from: b  reason: collision with root package name */
    public final v0 f1057b;

    /* renamed from: b0  reason: collision with root package name */
    public final q f1058b0;

    /* renamed from: c  reason: collision with root package name */
    public x0 f1059c;

    /* renamed from: c0  reason: collision with root package name */
    public final a1 f1060c0;

    /* renamed from: d  reason: collision with root package name */
    public b f1061d;

    /* renamed from: d0  reason: collision with root package name */
    public s0 f1062d0;

    /* renamed from: e  reason: collision with root package name */
    public d f1063e;

    /* renamed from: e0  reason: collision with root package name */
    public ArrayList f1064e0;

    /* renamed from: f  reason: collision with root package name */
    public final p1 f1065f;

    /* renamed from: f0  reason: collision with root package name */
    public boolean f1066f0;

    /* renamed from: g  reason: collision with root package name */
    public boolean f1067g;

    /* renamed from: g0  reason: collision with root package name */
    public boolean f1068g0;

    /* renamed from: h  reason: collision with root package name */
    public final Rect f1069h;

    /* renamed from: h0  reason: collision with root package name */
    public final f0 f1070h0;

    /* renamed from: i  reason: collision with root package name */
    public final Rect f1071i;

    /* renamed from: i0  reason: collision with root package name */
    public boolean f1072i0;

    /* renamed from: j  reason: collision with root package name */
    public final RectF f1073j;

    /* renamed from: j0  reason: collision with root package name */
    public f1 f1074j0;

    /* renamed from: k  reason: collision with root package name */
    public g0 f1075k;

    /* renamed from: k0  reason: collision with root package name */
    public final int[] f1076k0;
    public o0 l;

    /* renamed from: l0  reason: collision with root package name */
    public l f1077l0;

    /* renamed from: m  reason: collision with root package name */
    public final ArrayList f1078m;

    /* renamed from: m0  reason: collision with root package name */
    public final int[] f1079m0;

    /* renamed from: n  reason: collision with root package name */
    public final ArrayList f1080n;

    /* renamed from: n0  reason: collision with root package name */
    public final int[] f1081n0;

    /* renamed from: o  reason: collision with root package name */
    public r0 f1082o;

    /* renamed from: o0  reason: collision with root package name */
    public final int[] f1083o0;

    /* renamed from: p  reason: collision with root package name */
    public boolean f1084p;

    /* renamed from: p0  reason: collision with root package name */
    public final ArrayList f1085p0;

    /* renamed from: q  reason: collision with root package name */
    public boolean f1086q;

    /* renamed from: q0  reason: collision with root package name */
    public final e0 f1087q0;

    /* renamed from: r  reason: collision with root package name */
    public boolean f1088r;

    /* renamed from: r0  reason: collision with root package name */
    public final f0 f1089r0;

    /* renamed from: s  reason: collision with root package name */
    public int f1090s;

    /* renamed from: t  reason: collision with root package name */
    public boolean f1091t;

    /* renamed from: u  reason: collision with root package name */
    public boolean f1092u;

    /* renamed from: v  reason: collision with root package name */
    public boolean f1093v;

    /* renamed from: w  reason: collision with root package name */
    public int f1094w;

    /* renamed from: x  reason: collision with root package name */
    public final AccessibilityManager f1095x;

    /* renamed from: y  reason: collision with root package name */
    public boolean f1096y;
    public boolean z;

    static {
        Class cls = Integer.TYPE;
        f1053t0 = new Class[]{Context.class, AttributeSet.class, cls, cls};
        f1054u0 = new c(1);
    }

    public RecyclerView(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, R.attr.recyclerViewStyle);
    }

    public static RecyclerView D(View view) {
        if (view instanceof ViewGroup) {
            if (view instanceof RecyclerView) {
                return (RecyclerView) view;
            }
            ViewGroup viewGroup = (ViewGroup) view;
            int childCount = viewGroup.getChildCount();
            for (int i2 = 0; i2 < childCount; i2++) {
                RecyclerView D = D(viewGroup.getChildAt(i2));
                if (D != null) {
                    return D;
                }
            }
            return null;
        }
        return null;
    }

    public static d1 I(View view) {
        if (view == null) {
            return null;
        }
        return ((p0) view.getLayoutParams()).f3040a;
    }

    private l getScrollingChildHelper() {
        if (this.f1077l0 == null) {
            this.f1077l0 = new l(this);
        }
        return this.f1077l0;
    }

    public static void j(d1 d1Var) {
        WeakReference weakReference = d1Var.f2876b;
        if (weakReference != null) {
            Object obj = weakReference.get();
            while (true) {
                for (View view = (View) obj; view != null; view = null) {
                    if (view == d1Var.f2875a) {
                        return;
                    }
                    obj = view.getParent();
                    if (obj instanceof View) {
                        break;
                    }
                }
                d1Var.f2876b = null;
                return;
            }
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:15:?, code lost:
        return r3;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public final android.view.View A(android.view.View r3) {
        /*
            r2 = this;
        L0:
            android.view.ViewParent r0 = r3.getParent()
            if (r0 == 0) goto L10
            if (r0 == r2) goto L10
            boolean r1 = r0 instanceof android.view.View
            if (r1 == 0) goto L10
            r3 = r0
            android.view.View r3 = (android.view.View) r3
            goto L0
        L10:
            if (r0 != r2) goto L13
            goto L14
        L13:
            r3 = 0
        L14:
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.RecyclerView.A(android.view.View):android.view.View");
    }

    /* JADX WARN: Code restructure failed: missing block: B:15:0x005c, code lost:
        if (r7 == 2) goto L12;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public final boolean B(android.view.MotionEvent r13) {
        /*
            r12 = this;
            int r0 = r13.getAction()
            java.util.ArrayList r1 = r12.f1080n
            int r2 = r1.size()
            r3 = 0
            r4 = r3
        Lc:
            if (r4 >= r2) goto L6c
            java.lang.Object r5 = r1.get(r4)
            r0.r0 r5 = (r0.r0) r5
            r6 = r5
            r0.p r6 = (r0.p) r6
            int r7 = r6.f3036v
            r8 = 1
            r9 = 2
            if (r7 != r8) goto L5c
            float r7 = r13.getX()
            float r10 = r13.getY()
            boolean r7 = r6.d(r7, r10)
            float r10 = r13.getX()
            float r11 = r13.getY()
            boolean r10 = r6.c(r10, r11)
            int r11 = r13.getAction()
            if (r11 != 0) goto L60
            if (r7 != 0) goto L3f
            if (r10 == 0) goto L60
        L3f:
            if (r10 == 0) goto L4c
            r6.f3037w = r8
            float r7 = r13.getX()
            int r7 = (int) r7
            float r7 = (float) r7
            r6.f3030p = r7
            goto L58
        L4c:
            if (r7 == 0) goto L58
            r6.f3037w = r9
            float r7 = r13.getY()
            int r7 = (int) r7
            float r7 = (float) r7
            r6.f3027m = r7
        L58:
            r6.f(r9)
            goto L5e
        L5c:
            if (r7 != r9) goto L60
        L5e:
            r6 = r8
            goto L61
        L60:
            r6 = r3
        L61:
            if (r6 == 0) goto L69
            r6 = 3
            if (r0 == r6) goto L69
            r12.f1082o = r5
            return r8
        L69:
            int r4 = r4 + 1
            goto Lc
        L6c:
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.RecyclerView.B(android.view.MotionEvent):boolean");
    }

    public final void C(int[] iArr) {
        int e2 = this.f1063e.e();
        if (e2 == 0) {
            iArr[0] = -1;
            iArr[1] = -1;
            return;
        }
        int i2 = Integer.MAX_VALUE;
        int i3 = Integer.MIN_VALUE;
        for (int i4 = 0; i4 < e2; i4++) {
            d1 I = I(this.f1063e.d(i4));
            if (!I.o()) {
                int c2 = I.c();
                if (c2 < i2) {
                    i2 = c2;
                }
                if (c2 > i3) {
                    i3 = c2;
                }
            }
        }
        iArr[0] = i2;
        iArr[1] = i3;
    }

    public final d1 E(int i2) {
        d1 d1Var = null;
        if (this.f1096y) {
            return null;
        }
        int h2 = this.f1063e.h();
        for (int i3 = 0; i3 < h2; i3++) {
            d1 I = I(this.f1063e.g(i3));
            if (I != null && !I.i() && F(I) == i2) {
                if (!this.f1063e.j(I.f2875a)) {
                    return I;
                }
                d1Var = I;
            }
        }
        return d1Var;
    }

    public final int F(d1 d1Var) {
        if (!((d1Var.f2884j & 524) != 0) && d1Var.f()) {
            b bVar = this.f1061d;
            int i2 = d1Var.f2877c;
            ArrayList arrayList = bVar.f2849b;
            int size = arrayList.size();
            for (int i3 = 0; i3 < size; i3++) {
                a aVar = (a) arrayList.get(i3);
                int i4 = aVar.f2830a;
                if (i4 != 1) {
                    if (i4 == 2) {
                        int i5 = aVar.f2831b;
                        if (i5 <= i2) {
                            int i6 = aVar.f2833d;
                            if (i5 + i6 <= i2) {
                                i2 -= i6;
                            }
                        } else {
                            continue;
                        }
                    } else if (i4 == 8) {
                        int i7 = aVar.f2831b;
                        if (i7 == i2) {
                            i2 = aVar.f2833d;
                        } else {
                            if (i7 < i2) {
                                i2--;
                            }
                            if (aVar.f2833d <= i2) {
                                i2++;
                            }
                        }
                    }
                } else if (aVar.f2831b <= i2) {
                    i2 += aVar.f2833d;
                }
            }
            return i2;
        }
        return -1;
    }

    public final long G(d1 d1Var) {
        return this.f1075k.f2913b ? d1Var.f2879e : d1Var.f2877c;
    }

    public final d1 H(View view) {
        ViewParent parent = view.getParent();
        if (parent == null || parent == this) {
            return I(view);
        }
        throw new IllegalArgumentException("View " + view + " is not a direct child of " + this);
    }

    public final Rect J(View view) {
        p0 p0Var = (p0) view.getLayoutParams();
        boolean z = p0Var.f3042c;
        Rect rect = p0Var.f3041b;
        if (z) {
            if (this.f1060c0.f2841g && (p0Var.b() || p0Var.f3040a.g())) {
                return rect;
            }
            rect.set(0, 0, 0, 0);
            ArrayList arrayList = this.f1078m;
            int size = arrayList.size();
            for (int i2 = 0; i2 < size; i2++) {
                Rect rect2 = this.f1069h;
                rect2.set(0, 0, 0, 0);
                ((m0) arrayList.get(i2)).getClass();
                ((p0) view.getLayoutParams()).a();
                rect2.set(0, 0, 0, 0);
                rect.left += rect2.left;
                rect.top += rect2.top;
                rect.right += rect2.right;
                rect.bottom += rect2.bottom;
            }
            p0Var.f3042c = false;
            return rect;
        }
        return rect;
    }

    public final boolean K() {
        return this.A > 0;
    }

    public final void L(int i2) {
        if (this.l == null) {
            return;
        }
        setScrollState(2);
        this.l.i0(i2);
        awakenScrollBars();
    }

    public final void M() {
        int h2 = this.f1063e.h();
        for (int i2 = 0; i2 < h2; i2++) {
            ((p0) this.f1063e.g(i2).getLayoutParams()).f3042c = true;
        }
        ArrayList arrayList = this.f1057b.f3086c;
        int size = arrayList.size();
        for (int i3 = 0; i3 < size; i3++) {
            p0 p0Var = (p0) ((d1) arrayList.get(i3)).f2875a.getLayoutParams();
            if (p0Var != null) {
                p0Var.f3042c = true;
            }
        }
    }

    public final void N(int i2, int i3, boolean z) {
        int i4 = i2 + i3;
        int h2 = this.f1063e.h();
        for (int i5 = 0; i5 < h2; i5++) {
            d1 I = I(this.f1063e.g(i5));
            if (I != null && !I.o()) {
                int i6 = I.f2877c;
                if (i6 >= i4) {
                    I.l(-i3, z);
                } else if (i6 >= i2) {
                    I.b(8);
                    I.l(-i3, z);
                    I.f2877c = i2 - 1;
                }
                this.f1060c0.f2840f = true;
            }
        }
        v0 v0Var = this.f1057b;
        ArrayList arrayList = v0Var.f3086c;
        int size = arrayList.size();
        while (true) {
            size--;
            if (size < 0) {
                requestLayout();
                return;
            }
            d1 d1Var = (d1) arrayList.get(size);
            if (d1Var != null) {
                int i7 = d1Var.f2877c;
                if (i7 >= i4) {
                    d1Var.l(-i3, z);
                } else if (i7 >= i2) {
                    d1Var.b(8);
                    v0Var.e(size);
                }
            }
        }
    }

    public final void O() {
        this.A++;
    }

    public final void P(boolean z) {
        int i2;
        boolean z2 = true;
        int i3 = this.A - 1;
        this.A = i3;
        if (i3 < 1) {
            this.A = 0;
            if (z) {
                int i4 = this.f1094w;
                this.f1094w = 0;
                if (i4 != 0) {
                    AccessibilityManager accessibilityManager = this.f1095x;
                    if ((accessibilityManager == null || !accessibilityManager.isEnabled()) ? false : false) {
                        AccessibilityEvent obtain = AccessibilityEvent.obtain();
                        obtain.setEventType(2048);
                        obtain.setContentChangeTypes(i4);
                        sendAccessibilityEventUnchecked(obtain);
                    }
                }
                ArrayList arrayList = this.f1085p0;
                for (int size = arrayList.size() - 1; size >= 0; size--) {
                    d1 d1Var = (d1) arrayList.get(size);
                    if (d1Var.f2875a.getParent() == this && !d1Var.o() && (i2 = d1Var.f2890q) != -1) {
                        WeakHashMap weakHashMap = e0.o0.f1697a;
                        y.s(d1Var.f2875a, i2);
                        d1Var.f2890q = -1;
                    }
                }
                arrayList.clear();
            }
        }
    }

    public final void Q(MotionEvent motionEvent) {
        int actionIndex = motionEvent.getActionIndex();
        if (motionEvent.getPointerId(actionIndex) == this.J) {
            int i2 = actionIndex == 0 ? 1 : 0;
            this.J = motionEvent.getPointerId(i2);
            int x2 = (int) (motionEvent.getX(i2) + 0.5f);
            this.N = x2;
            this.L = x2;
            int y2 = (int) (motionEvent.getY(i2) + 0.5f);
            this.O = y2;
            this.M = y2;
        }
    }

    public final void R() {
        if (this.f1072i0 || !this.f1084p) {
            return;
        }
        WeakHashMap weakHashMap = e0.o0.f1697a;
        y.m(this, this.f1087q0);
        this.f1072i0 = true;
    }

    /* JADX WARN: Code restructure failed: missing block: B:48:0x007d, code lost:
        if ((r5.H != null && r5.l.u0()) != false) goto L42;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public final void S() {
        /*
            r5 = this;
            boolean r0 = r5.f1096y
            if (r0 == 0) goto L19
            r0.b r0 = r5.f1061d
            java.util.ArrayList r1 = r0.f2849b
            r0.l(r1)
            java.util.ArrayList r1 = r0.f2850c
            r0.l(r1)
            boolean r0 = r5.z
            if (r0 == 0) goto L19
            r0.o0 r0 = r5.l
            r0.S()
        L19:
            r0.l0 r0 = r5.H
            r1 = 1
            r2 = 0
            if (r0 == 0) goto L29
            r0.o0 r0 = r5.l
            boolean r0 = r0.u0()
            if (r0 == 0) goto L29
            r0 = r1
            goto L2a
        L29:
            r0 = r2
        L2a:
            if (r0 == 0) goto L32
            r0.b r0 = r5.f1061d
            r0.j()
            goto L37
        L32:
            r0.b r0 = r5.f1061d
            r0.c()
        L37:
            boolean r0 = r5.f1066f0
            if (r0 != 0) goto L42
            boolean r0 = r5.f1068g0
            if (r0 == 0) goto L40
            goto L42
        L40:
            r0 = r2
            goto L43
        L42:
            r0 = r1
        L43:
            boolean r3 = r5.f1088r
            if (r3 == 0) goto L61
            r0.l0 r3 = r5.H
            if (r3 == 0) goto L61
            boolean r3 = r5.f1096y
            if (r3 != 0) goto L57
            if (r0 != 0) goto L57
            r0.o0 r4 = r5.l
            boolean r4 = r4.f3003f
            if (r4 == 0) goto L61
        L57:
            if (r3 == 0) goto L5f
            r0.g0 r3 = r5.f1075k
            boolean r3 = r3.f2913b
            if (r3 == 0) goto L61
        L5f:
            r3 = r1
            goto L62
        L61:
            r3 = r2
        L62:
            r0.a1 r4 = r5.f1060c0
            r4.f2844j = r3
            if (r3 == 0) goto L80
            if (r0 == 0) goto L80
            boolean r0 = r5.f1096y
            if (r0 != 0) goto L80
            r0.l0 r0 = r5.H
            if (r0 == 0) goto L7c
            r0.o0 r5 = r5.l
            boolean r5 = r5.u0()
            if (r5 == 0) goto L7c
            r5 = r1
            goto L7d
        L7c:
            r5 = r2
        L7d:
            if (r5 == 0) goto L80
            goto L81
        L80:
            r1 = r2
        L81:
            r4.f2845k = r1
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.RecyclerView.S():void");
    }

    public final void T(boolean z) {
        this.z = z | this.z;
        this.f1096y = true;
        int h2 = this.f1063e.h();
        for (int i2 = 0; i2 < h2; i2++) {
            d1 I = I(this.f1063e.g(i2));
            if (I != null && !I.o()) {
                I.b(6);
            }
        }
        M();
        v0 v0Var = this.f1057b;
        ArrayList arrayList = v0Var.f3086c;
        int size = arrayList.size();
        for (int i3 = 0; i3 < size; i3++) {
            d1 d1Var = (d1) arrayList.get(i3);
            if (d1Var != null) {
                d1Var.b(6);
                d1Var.a(null);
            }
        }
        g0 g0Var = v0Var.f3091h.f1075k;
        if (g0Var == null || !g0Var.f2913b) {
            v0Var.d();
        }
    }

    public final void U(d1 d1Var, k0 k0Var) {
        int i2 = (d1Var.f2884j & (-8193)) | 0;
        d1Var.f2884j = i2;
        boolean z = this.f1060c0.f2842h;
        p1 p1Var = this.f1065f;
        if (z) {
            if (((i2 & 2) != 0) && !d1Var.i() && !d1Var.o()) {
                ((j.d) p1Var.f3046c).e(G(d1Var), d1Var);
            }
        }
        p1Var.c(d1Var, k0Var);
    }

    public final void V(View view, View view2) {
        View view3 = view2 != null ? view2 : view;
        int width = view3.getWidth();
        int height = view3.getHeight();
        Rect rect = this.f1069h;
        rect.set(0, 0, width, height);
        ViewGroup.LayoutParams layoutParams = view3.getLayoutParams();
        if (layoutParams instanceof p0) {
            p0 p0Var = (p0) layoutParams;
            if (!p0Var.f3042c) {
                int i2 = rect.left;
                Rect rect2 = p0Var.f3041b;
                rect.left = i2 - rect2.left;
                rect.right += rect2.right;
                rect.top -= rect2.top;
                rect.bottom += rect2.bottom;
            }
        }
        if (view2 != null) {
            offsetDescendantRectToMyCoords(view2, rect);
            offsetRectIntoDescendantCoords(view, rect);
        }
        this.l.f0(this, view, this.f1069h, !this.f1088r, view2 == null);
    }

    public final void W() {
        VelocityTracker velocityTracker = this.K;
        if (velocityTracker != null) {
            velocityTracker.clear();
        }
        boolean z = false;
        d0(0);
        EdgeEffect edgeEffect = this.D;
        if (edgeEffect != null) {
            edgeEffect.onRelease();
            z = this.D.isFinished();
        }
        EdgeEffect edgeEffect2 = this.E;
        if (edgeEffect2 != null) {
            edgeEffect2.onRelease();
            z |= this.E.isFinished();
        }
        EdgeEffect edgeEffect3 = this.F;
        if (edgeEffect3 != null) {
            edgeEffect3.onRelease();
            z |= this.F.isFinished();
        }
        EdgeEffect edgeEffect4 = this.G;
        if (edgeEffect4 != null) {
            edgeEffect4.onRelease();
            z |= this.G.isFinished();
        }
        if (z) {
            WeakHashMap weakHashMap = e0.o0.f1697a;
            y.k(this);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:33:0x00d5  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x00eb  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x0108  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public final boolean X(int r19, int r20, android.view.MotionEvent r21) {
        /*
            Method dump skipped, instructions count: 307
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.RecyclerView.X(int, int, android.view.MotionEvent):boolean");
    }

    public final void Y(int i2, int i3, int[] iArr) {
        d1 d1Var;
        b0();
        O();
        Trace.beginSection("RV Scroll");
        a1 a1Var = this.f1060c0;
        z(a1Var);
        v0 v0Var = this.f1057b;
        int h02 = i2 != 0 ? this.l.h0(i2, v0Var, a1Var) : 0;
        int j02 = i3 != 0 ? this.l.j0(i3, v0Var, a1Var) : 0;
        Trace.endSection();
        int e2 = this.f1063e.e();
        for (int i4 = 0; i4 < e2; i4++) {
            View d2 = this.f1063e.d(i4);
            d1 H = H(d2);
            if (H != null && (d1Var = H.f2883i) != null) {
                int left = d2.getLeft();
                int top = d2.getTop();
                View view = d1Var.f2875a;
                if (left != view.getLeft() || top != view.getTop()) {
                    view.layout(left, top, view.getWidth() + left, view.getHeight() + top);
                }
            }
        }
        P(true);
        c0(false);
        if (iArr != null) {
            iArr[0] = h02;
            iArr[1] = j02;
        }
    }

    public final void Z(int i2) {
        z zVar;
        if (this.f1092u) {
            return;
        }
        setScrollState(0);
        c1 c1Var = this.W;
        c1Var.f2866g.removeCallbacks(c1Var);
        c1Var.f2862c.abortAnimation();
        o0 o0Var = this.l;
        if (o0Var != null && (zVar = o0Var.f3002e) != null) {
            zVar.g();
        }
        o0 o0Var2 = this.l;
        if (o0Var2 == null) {
            Log.e("RecyclerView", "Cannot scroll to position a LayoutManager set. Call setLayoutManager with a non-null argument.");
            return;
        }
        o0Var2.i0(i2);
        awakenScrollBars();
    }

    public final void a0(int i2, int i3, boolean z) {
        o0 o0Var = this.l;
        if (o0Var == null) {
            Log.e("RecyclerView", "Cannot smooth scroll without a LayoutManager set. Call setLayoutManager with a non-null argument.");
        } else if (this.f1092u) {
        } else {
            if (!o0Var.d()) {
                i2 = 0;
            }
            if (!this.l.e()) {
                i3 = 0;
            }
            if (i2 == 0 && i3 == 0) {
                return;
            }
            if (z) {
                int i4 = i2 != 0 ? 1 : 0;
                if (i3 != 0) {
                    i4 |= 2;
                }
                getScrollingChildHelper().g(i4, 1);
            }
            this.W.b(i2, i3, Integer.MIN_VALUE, null);
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void addFocusables(ArrayList arrayList, int i2, int i3) {
        o0 o0Var = this.l;
        if (o0Var != null) {
            o0Var.getClass();
        }
        super.addFocusables(arrayList, i2, i3);
    }

    public final void b0() {
        int i2 = this.f1090s + 1;
        this.f1090s = i2;
        if (i2 != 1 || this.f1092u) {
            return;
        }
        this.f1091t = false;
    }

    public final void c0(boolean z) {
        if (this.f1090s < 1) {
            this.f1090s = 1;
        }
        if (!z && !this.f1092u) {
            this.f1091t = false;
        }
        if (this.f1090s == 1) {
            if (z && this.f1091t && !this.f1092u && this.l != null && this.f1075k != null) {
                o();
            }
            if (!this.f1092u) {
                this.f1091t = false;
            }
        }
        this.f1090s--;
    }

    @Override // android.view.ViewGroup
    public final boolean checkLayoutParams(ViewGroup.LayoutParams layoutParams) {
        return (layoutParams instanceof p0) && this.l.f((p0) layoutParams);
    }

    @Override // android.view.View
    public final int computeHorizontalScrollExtent() {
        o0 o0Var = this.l;
        if (o0Var != null && o0Var.d()) {
            return this.l.j(this.f1060c0);
        }
        return 0;
    }

    @Override // android.view.View
    public final int computeHorizontalScrollOffset() {
        o0 o0Var = this.l;
        if (o0Var != null && o0Var.d()) {
            return this.l.k(this.f1060c0);
        }
        return 0;
    }

    @Override // android.view.View
    public final int computeHorizontalScrollRange() {
        o0 o0Var = this.l;
        if (o0Var != null && o0Var.d()) {
            return this.l.l(this.f1060c0);
        }
        return 0;
    }

    @Override // android.view.View
    public final int computeVerticalScrollExtent() {
        o0 o0Var = this.l;
        if (o0Var != null && o0Var.e()) {
            return this.l.m(this.f1060c0);
        }
        return 0;
    }

    @Override // android.view.View
    public final int computeVerticalScrollOffset() {
        o0 o0Var = this.l;
        if (o0Var != null && o0Var.e()) {
            return this.l.n(this.f1060c0);
        }
        return 0;
    }

    @Override // android.view.View
    public final int computeVerticalScrollRange() {
        o0 o0Var = this.l;
        if (o0Var != null && o0Var.e()) {
            return this.l.o(this.f1060c0);
        }
        return 0;
    }

    public final void d0(int i2) {
        getScrollingChildHelper().h(i2);
    }

    @Override // android.view.View
    public final boolean dispatchNestedFling(float f2, float f3, boolean z) {
        return getScrollingChildHelper().a(f2, f3, z);
    }

    @Override // android.view.View
    public final boolean dispatchNestedPreFling(float f2, float f3) {
        return getScrollingChildHelper().b(f2, f3);
    }

    @Override // android.view.View
    public final boolean dispatchNestedPreScroll(int i2, int i3, int[] iArr, int[] iArr2) {
        return getScrollingChildHelper().c(i2, i3, iArr, iArr2, 0);
    }

    @Override // android.view.View
    public final boolean dispatchNestedScroll(int i2, int i3, int i4, int i5, int[] iArr) {
        return getScrollingChildHelper().e(i2, i3, i4, i5, iArr, 0, null);
    }

    @Override // android.view.View
    public final boolean dispatchPopulateAccessibilityEvent(AccessibilityEvent accessibilityEvent) {
        onPopulateAccessibilityEvent(accessibilityEvent);
        return true;
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void dispatchRestoreInstanceState(SparseArray sparseArray) {
        dispatchThawSelfOnly(sparseArray);
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void dispatchSaveInstanceState(SparseArray sparseArray) {
        dispatchFreezeSelfOnly(sparseArray);
    }

    @Override // android.view.View
    public final void draw(Canvas canvas) {
        boolean z;
        float f2;
        float f3;
        super.draw(canvas);
        ArrayList arrayList = this.f1078m;
        int size = arrayList.size();
        boolean z2 = false;
        for (int i2 = 0; i2 < size; i2++) {
            ((m0) arrayList.get(i2)).b(canvas);
        }
        EdgeEffect edgeEffect = this.D;
        boolean z3 = true;
        if (edgeEffect == null || edgeEffect.isFinished()) {
            z = false;
        } else {
            int save = canvas.save();
            int paddingBottom = this.f1067g ? getPaddingBottom() : 0;
            canvas.rotate(270.0f);
            canvas.translate((-getHeight()) + paddingBottom, 0.0f);
            EdgeEffect edgeEffect2 = this.D;
            z = edgeEffect2 != null && edgeEffect2.draw(canvas);
            canvas.restoreToCount(save);
        }
        EdgeEffect edgeEffect3 = this.E;
        if (edgeEffect3 != null && !edgeEffect3.isFinished()) {
            int save2 = canvas.save();
            if (this.f1067g) {
                canvas.translate(getPaddingLeft(), getPaddingTop());
            }
            EdgeEffect edgeEffect4 = this.E;
            z |= edgeEffect4 != null && edgeEffect4.draw(canvas);
            canvas.restoreToCount(save2);
        }
        EdgeEffect edgeEffect5 = this.F;
        if (edgeEffect5 != null && !edgeEffect5.isFinished()) {
            int save3 = canvas.save();
            int width = getWidth();
            int paddingTop = this.f1067g ? getPaddingTop() : 0;
            canvas.rotate(90.0f);
            canvas.translate(-paddingTop, -width);
            EdgeEffect edgeEffect6 = this.F;
            z |= edgeEffect6 != null && edgeEffect6.draw(canvas);
            canvas.restoreToCount(save3);
        }
        EdgeEffect edgeEffect7 = this.G;
        if (edgeEffect7 != null && !edgeEffect7.isFinished()) {
            int save4 = canvas.save();
            canvas.rotate(180.0f);
            if (this.f1067g) {
                f2 = getPaddingRight() + (-getWidth());
                f3 = getPaddingBottom() + (-getHeight());
            } else {
                f2 = -getWidth();
                f3 = -getHeight();
            }
            canvas.translate(f2, f3);
            EdgeEffect edgeEffect8 = this.G;
            if (edgeEffect8 != null && edgeEffect8.draw(canvas)) {
                z2 = true;
            }
            z |= z2;
            canvas.restoreToCount(save4);
        }
        if (z || this.H == null || arrayList.size() <= 0 || !this.H.f()) {
            z3 = z;
        }
        if (z3) {
            WeakHashMap weakHashMap = e0.o0.f1697a;
            y.k(this);
        }
    }

    @Override // android.view.ViewGroup
    public final boolean drawChild(Canvas canvas, View view, long j2) {
        return super.drawChild(canvas, view, j2);
    }

    public final void f(d1 d1Var) {
        View view = d1Var.f2875a;
        boolean z = view.getParent() == this;
        this.f1057b.j(H(view));
        boolean k2 = d1Var.k();
        d dVar = this.f1063e;
        if (k2) {
            dVar.b(view, -1, view.getLayoutParams(), true);
        } else if (!z) {
            dVar.a(view, -1, true);
        } else {
            int indexOfChild = dVar.f2867a.f2903a.indexOfChild(view);
            if (indexOfChild >= 0) {
                dVar.f2868b.h(indexOfChild);
                dVar.i(view);
                return;
            }
            throw new IllegalArgumentException("view is not a child, cannot hide " + view);
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:115:0x0160, code lost:
        if (r4 > 0) goto L60;
     */
    /* JADX WARN: Code restructure failed: missing block: B:119:0x017e, code lost:
        if (r3 > 0) goto L60;
     */
    /* JADX WARN: Code restructure failed: missing block: B:121:0x0181, code lost:
        if (r4 < 0) goto L60;
     */
    /* JADX WARN: Code restructure failed: missing block: B:123:0x0184, code lost:
        if (r3 < 0) goto L60;
     */
    /* JADX WARN: Code restructure failed: missing block: B:128:0x018c, code lost:
        if ((r3 * r2) < 0) goto L119;
     */
    /* JADX WARN: Code restructure failed: missing block: B:133:0x0194, code lost:
        if ((r3 * r2) > 0) goto L119;
     */
    /* JADX WARN: Removed duplicated region for block: B:138:0x019b  */
    /* JADX WARN: Removed duplicated region for block: B:140:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:30:0x005d  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x005f  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x0062  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x0064  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x0068  */
    /* JADX WARN: Removed duplicated region for block: B:38:0x006b  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x0072  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x0074  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x0077  */
    @Override // android.view.ViewGroup, android.view.ViewParent
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public final android.view.View focusSearch(android.view.View r14, int r15) {
        /*
            Method dump skipped, instructions count: 416
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.RecyclerView.focusSearch(android.view.View, int):android.view.View");
    }

    public final void g(m0 m0Var) {
        o0 o0Var = this.l;
        if (o0Var != null) {
            o0Var.c("Cannot add item decoration during a scroll  or layout");
        }
        ArrayList arrayList = this.f1078m;
        if (arrayList.isEmpty()) {
            setWillNotDraw(false);
        }
        arrayList.add(m0Var);
        M();
        requestLayout();
    }

    @Override // android.view.ViewGroup
    public final ViewGroup.LayoutParams generateDefaultLayoutParams() {
        o0 o0Var = this.l;
        if (o0Var != null) {
            return o0Var.r();
        }
        throw new IllegalStateException("RecyclerView has no LayoutManager" + y());
    }

    @Override // android.view.ViewGroup
    public final ViewGroup.LayoutParams generateLayoutParams(AttributeSet attributeSet) {
        o0 o0Var = this.l;
        if (o0Var != null) {
            return o0Var.s(getContext(), attributeSet);
        }
        throw new IllegalStateException("RecyclerView has no LayoutManager" + y());
    }

    @Override // android.view.ViewGroup, android.view.View
    public CharSequence getAccessibilityClassName() {
        return "androidx.recyclerview.widget.RecyclerView";
    }

    public g0 getAdapter() {
        return this.f1075k;
    }

    @Override // android.view.View
    public int getBaseline() {
        o0 o0Var = this.l;
        if (o0Var != null) {
            o0Var.getClass();
            return -1;
        }
        return super.getBaseline();
    }

    @Override // android.view.ViewGroup
    public final int getChildDrawingOrder(int i2, int i3) {
        return super.getChildDrawingOrder(i2, i3);
    }

    @Override // android.view.ViewGroup
    public boolean getClipToPadding() {
        return this.f1067g;
    }

    public f1 getCompatAccessibilityDelegate() {
        return this.f1074j0;
    }

    public j0 getEdgeEffectFactory() {
        return this.C;
    }

    public l0 getItemAnimator() {
        return this.H;
    }

    public int getItemDecorationCount() {
        return this.f1078m.size();
    }

    public o0 getLayoutManager() {
        return this.l;
    }

    public int getMaxFlingVelocity() {
        return this.S;
    }

    public int getMinFlingVelocity() {
        return this.R;
    }

    public long getNanoTime() {
        return System.nanoTime();
    }

    public q0 getOnFlingListener() {
        return this.Q;
    }

    public boolean getPreserveFocusAfterLayout() {
        return this.V;
    }

    public u0 getRecycledViewPool() {
        return this.f1057b.c();
    }

    public int getScrollState() {
        return this.I;
    }

    public final void h(s0 s0Var) {
        if (this.f1064e0 == null) {
            this.f1064e0 = new ArrayList();
        }
        this.f1064e0.add(s0Var);
    }

    @Override // android.view.View
    public final boolean hasNestedScrollingParent() {
        return getScrollingChildHelper().f(0) != null;
    }

    public final void i(String str) {
        if (K()) {
            if (str != null) {
                throw new IllegalStateException(str);
            }
            throw new IllegalStateException("Cannot call this method while RecyclerView is computing a layout or scrolling" + y());
        } else if (this.B > 0) {
            Log.w("RecyclerView", "Cannot call this method in a scroll callback. Scroll callbacks mightbe run during a measure & layout pass where you cannot change theRecyclerView data. Any method call that might change the structureof the RecyclerView or the adapter contents should be postponed tothe next frame.", new IllegalStateException("" + y()));
        }
    }

    @Override // android.view.View
    public final boolean isAttachedToWindow() {
        return this.f1084p;
    }

    @Override // android.view.ViewGroup
    public final boolean isLayoutSuppressed() {
        return this.f1092u;
    }

    @Override // android.view.View
    public final boolean isNestedScrollingEnabled() {
        return getScrollingChildHelper().f1692d;
    }

    public final void k() {
        int h2 = this.f1063e.h();
        for (int i2 = 0; i2 < h2; i2++) {
            d1 I = I(this.f1063e.g(i2));
            if (!I.o()) {
                I.f2878d = -1;
                I.f2881g = -1;
            }
        }
        v0 v0Var = this.f1057b;
        ArrayList arrayList = v0Var.f3086c;
        int size = arrayList.size();
        for (int i3 = 0; i3 < size; i3++) {
            d1 d1Var = (d1) arrayList.get(i3);
            d1Var.f2878d = -1;
            d1Var.f2881g = -1;
        }
        ArrayList arrayList2 = v0Var.f3084a;
        int size2 = arrayList2.size();
        for (int i4 = 0; i4 < size2; i4++) {
            d1 d1Var2 = (d1) arrayList2.get(i4);
            d1Var2.f2878d = -1;
            d1Var2.f2881g = -1;
        }
        ArrayList arrayList3 = v0Var.f3085b;
        if (arrayList3 != null) {
            int size3 = arrayList3.size();
            for (int i5 = 0; i5 < size3; i5++) {
                d1 d1Var3 = (d1) v0Var.f3085b.get(i5);
                d1Var3.f2878d = -1;
                d1Var3.f2881g = -1;
            }
        }
    }

    public final void l(int i2, int i3) {
        boolean z;
        EdgeEffect edgeEffect = this.D;
        if (edgeEffect == null || edgeEffect.isFinished() || i2 <= 0) {
            z = false;
        } else {
            this.D.onRelease();
            z = this.D.isFinished();
        }
        EdgeEffect edgeEffect2 = this.F;
        if (edgeEffect2 != null && !edgeEffect2.isFinished() && i2 < 0) {
            this.F.onRelease();
            z |= this.F.isFinished();
        }
        EdgeEffect edgeEffect3 = this.E;
        if (edgeEffect3 != null && !edgeEffect3.isFinished() && i3 > 0) {
            this.E.onRelease();
            z |= this.E.isFinished();
        }
        EdgeEffect edgeEffect4 = this.G;
        if (edgeEffect4 != null && !edgeEffect4.isFinished() && i3 < 0) {
            this.G.onRelease();
            z |= this.G.isFinished();
        }
        if (z) {
            WeakHashMap weakHashMap = e0.o0.f1697a;
            y.k(this);
        }
    }

    public final void m() {
        if (!this.f1088r || this.f1096y) {
            Trace.beginSection("RV FullInvalidate");
            o();
            Trace.endSection();
        } else if (this.f1061d.g()) {
            this.f1061d.getClass();
            if (this.f1061d.g()) {
                Trace.beginSection("RV FullInvalidate");
                o();
                Trace.endSection();
            }
        }
    }

    public final void n(int i2, int i3) {
        int paddingRight = getPaddingRight() + getPaddingLeft();
        WeakHashMap weakHashMap = e0.o0.f1697a;
        setMeasuredDimension(o0.g(i2, paddingRight, y.e(this)), o0.g(i3, getPaddingBottom() + getPaddingTop(), y.d(this)));
    }

    /* JADX WARN: Code restructure failed: missing block: B:176:0x037a, code lost:
        if (r17.f1063e.j(getFocusedChild()) == false) goto L242;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:144:0x02df  */
    /* JADX WARN: Removed duplicated region for block: B:148:0x030b  */
    /* JADX WARN: Removed duplicated region for block: B:151:0x0314  */
    /* JADX WARN: Removed duplicated region for block: B:159:0x033f  */
    /* JADX WARN: Removed duplicated region for block: B:175:0x0370  */
    /* JADX WARN: Removed duplicated region for block: B:199:0x03c3  */
    /* JADX WARN: Removed duplicated region for block: B:207:0x03de  */
    /* JADX WARN: Removed duplicated region for block: B:229:0x0419  */
    /* JADX WARN: Removed duplicated region for block: B:258:0x02e2 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:29:0x0072  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public final void o() {
        /*
            Method dump skipped, instructions count: 1080
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.RecyclerView.o():void");
    }

    /* JADX WARN: Code restructure failed: missing block: B:17:0x0049, code lost:
        if (r1 >= 30.0f) goto L16;
     */
    @Override // android.view.ViewGroup, android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public final void onAttachedToWindow() {
        /*
            r5 = this;
            super.onAttachedToWindow()
            r0 = 0
            r5.A = r0
            r1 = 1
            r5.f1084p = r1
            boolean r2 = r5.f1088r
            if (r2 == 0) goto L15
            boolean r2 = r5.isLayoutRequested()
            if (r2 != 0) goto L15
            r2 = r1
            goto L16
        L15:
            r2 = r0
        L16:
            r5.f1088r = r2
            r0.o0 r2 = r5.l
            if (r2 == 0) goto L1e
            r2.f3004g = r1
        L1e:
            r5.f1072i0 = r0
            java.lang.ThreadLocal r0 = r0.s.f3056e
            java.lang.Object r1 = r0.get()
            r0.s r1 = (r0.s) r1
            r5.f1056a0 = r1
            if (r1 != 0) goto L5a
            r0.s r1 = new r0.s
            r1.<init>()
            r5.f1056a0 = r1
            java.util.WeakHashMap r1 = e0.o0.f1697a
            android.view.Display r1 = e0.z.b(r5)
            boolean r2 = r5.isInEditMode()
            if (r2 != 0) goto L4c
            if (r1 == 0) goto L4c
            float r1 = r1.getRefreshRate()
            r2 = 1106247680(0x41f00000, float:30.0)
            int r2 = (r1 > r2 ? 1 : (r1 == r2 ? 0 : -1))
            if (r2 < 0) goto L4c
            goto L4e
        L4c:
            r1 = 1114636288(0x42700000, float:60.0)
        L4e:
            r0.s r2 = r5.f1056a0
            r3 = 1315859240(0x4e6e6b28, float:1.0E9)
            float r3 = r3 / r1
            long r3 = (long) r3
            r2.f3060c = r3
            r0.set(r2)
        L5a:
            r0.s r0 = r5.f1056a0
            java.util.ArrayList r0 = r0.f3058a
            r0.add(r5)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.RecyclerView.onAttachedToWindow():void");
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void onDetachedFromWindow() {
        z zVar;
        super.onDetachedFromWindow();
        l0 l0Var = this.H;
        if (l0Var != null) {
            l0Var.e();
        }
        setScrollState(0);
        c1 c1Var = this.W;
        c1Var.f2866g.removeCallbacks(c1Var);
        c1Var.f2862c.abortAnimation();
        o0 o0Var = this.l;
        if (o0Var != null && (zVar = o0Var.f3002e) != null) {
            zVar.g();
        }
        this.f1084p = false;
        o0 o0Var2 = this.l;
        if (o0Var2 != null) {
            o0Var2.f3004g = false;
            o0Var2.M(this);
        }
        this.f1085p0.clear();
        removeCallbacks(this.f1087q0);
        this.f1065f.getClass();
        do {
        } while (o1.f3012d.a() != null);
        s sVar = this.f1056a0;
        if (sVar != null) {
            sVar.f3058a.remove(this);
            this.f1056a0 = null;
        }
    }

    @Override // android.view.View
    public final void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        ArrayList arrayList = this.f1078m;
        int size = arrayList.size();
        for (int i2 = 0; i2 < size; i2++) {
            ((m0) arrayList.get(i2)).a(this);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:31:0x0068  */
    @Override // android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public final boolean onGenericMotionEvent(android.view.MotionEvent r6) {
        /*
            r5 = this;
            r0.o0 r0 = r5.l
            r1 = 0
            if (r0 != 0) goto L6
            return r1
        L6:
            boolean r0 = r5.f1092u
            if (r0 == 0) goto Lb
            return r1
        Lb:
            int r0 = r6.getAction()
            r2 = 8
            if (r0 != r2) goto L77
            int r0 = r6.getSource()
            r0 = r0 & 2
            r2 = 0
            if (r0 == 0) goto L3e
            r0.o0 r0 = r5.l
            boolean r0 = r0.e()
            if (r0 == 0) goto L2c
            r0 = 9
            float r0 = r6.getAxisValue(r0)
            float r0 = -r0
            goto L2d
        L2c:
            r0 = r2
        L2d:
            r0.o0 r3 = r5.l
            boolean r3 = r3.d()
            if (r3 == 0) goto L3c
            r3 = 10
            float r3 = r6.getAxisValue(r3)
            goto L64
        L3c:
            r3 = r2
            goto L64
        L3e:
            int r0 = r6.getSource()
            r3 = 4194304(0x400000, float:5.877472E-39)
            r0 = r0 & r3
            if (r0 == 0) goto L62
            r0 = 26
            float r0 = r6.getAxisValue(r0)
            r0.o0 r3 = r5.l
            boolean r3 = r3.e()
            if (r3 == 0) goto L57
            float r0 = -r0
            goto L3c
        L57:
            r0.o0 r3 = r5.l
            boolean r3 = r3.d()
            if (r3 == 0) goto L62
            r3 = r0
            r0 = r2
            goto L64
        L62:
            r0 = r2
            r3 = r0
        L64:
            int r4 = (r0 > r2 ? 1 : (r0 == r2 ? 0 : -1))
            if (r4 != 0) goto L6c
            int r2 = (r3 > r2 ? 1 : (r3 == r2 ? 0 : -1))
            if (r2 == 0) goto L77
        L6c:
            float r2 = r5.T
            float r3 = r3 * r2
            int r2 = (int) r3
            float r3 = r5.U
            float r0 = r0 * r3
            int r0 = (int) r0
            r5.X(r2, r0, r6)
        L77:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.RecyclerView.onGenericMotionEvent(android.view.MotionEvent):boolean");
    }

    @Override // android.view.ViewGroup
    public final boolean onInterceptTouchEvent(MotionEvent motionEvent) {
        boolean z;
        if (this.f1092u) {
            return false;
        }
        this.f1082o = null;
        if (B(motionEvent)) {
            W();
            setScrollState(0);
            return true;
        }
        o0 o0Var = this.l;
        if (o0Var == null) {
            return false;
        }
        boolean d2 = o0Var.d();
        boolean e2 = this.l.e();
        if (this.K == null) {
            this.K = VelocityTracker.obtain();
        }
        this.K.addMovement(motionEvent);
        int actionMasked = motionEvent.getActionMasked();
        int actionIndex = motionEvent.getActionIndex();
        if (actionMasked == 0) {
            if (this.f1093v) {
                this.f1093v = false;
            }
            this.J = motionEvent.getPointerId(0);
            int x2 = (int) (motionEvent.getX() + 0.5f);
            this.N = x2;
            this.L = x2;
            int y2 = (int) (motionEvent.getY() + 0.5f);
            this.O = y2;
            this.M = y2;
            if (this.I == 2) {
                getParent().requestDisallowInterceptTouchEvent(true);
                setScrollState(1);
                d0(1);
            }
            int[] iArr = this.f1081n0;
            iArr[1] = 0;
            iArr[0] = 0;
            int i2 = d2;
            if (e2) {
                i2 = (d2 ? 1 : 0) | 2;
            }
            getScrollingChildHelper().g(i2, 0);
        } else if (actionMasked == 1) {
            this.K.clear();
            d0(0);
        } else if (actionMasked == 2) {
            int findPointerIndex = motionEvent.findPointerIndex(this.J);
            if (findPointerIndex < 0) {
                Log.e("RecyclerView", "Error processing scroll; pointer index for id " + this.J + " not found. Did any MotionEvents get skipped?");
                return false;
            }
            int x3 = (int) (motionEvent.getX(findPointerIndex) + 0.5f);
            int y3 = (int) (motionEvent.getY(findPointerIndex) + 0.5f);
            if (this.I != 1) {
                int i3 = x3 - this.L;
                int i4 = y3 - this.M;
                if (!d2 || Math.abs(i3) <= this.P) {
                    z = false;
                } else {
                    this.N = x3;
                    z = true;
                }
                if (e2 && Math.abs(i4) > this.P) {
                    this.O = y3;
                    z = true;
                }
                if (z) {
                    setScrollState(1);
                }
            }
        } else if (actionMasked == 3) {
            W();
            setScrollState(0);
        } else if (actionMasked == 5) {
            this.J = motionEvent.getPointerId(actionIndex);
            int x4 = (int) (motionEvent.getX(actionIndex) + 0.5f);
            this.N = x4;
            this.L = x4;
            int y4 = (int) (motionEvent.getY(actionIndex) + 0.5f);
            this.O = y4;
            this.M = y4;
        } else if (actionMasked == 6) {
            Q(motionEvent);
        }
        return this.I == 1;
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void onLayout(boolean z, int i2, int i3, int i4, int i5) {
        Trace.beginSection("RV OnLayout");
        o();
        Trace.endSection();
        this.f1088r = true;
    }

    @Override // android.view.View
    public final void onMeasure(int i2, int i3) {
        o0 o0Var = this.l;
        if (o0Var == null) {
            n(i2, i3);
            return;
        }
        boolean H = o0Var.H();
        boolean z = false;
        a1 a1Var = this.f1060c0;
        if (!H) {
            if (this.f1086q) {
                this.l.f2999b.n(i2, i3);
                return;
            } else if (a1Var.f2845k) {
                setMeasuredDimension(getMeasuredWidth(), getMeasuredHeight());
                return;
            } else {
                g0 g0Var = this.f1075k;
                if (g0Var != null) {
                    a1Var.f2839e = g0Var.a();
                } else {
                    a1Var.f2839e = 0;
                }
                b0();
                this.l.f2999b.n(i2, i3);
                c0(false);
                a1Var.f2841g = false;
                return;
            }
        }
        int mode = View.MeasureSpec.getMode(i2);
        int mode2 = View.MeasureSpec.getMode(i3);
        this.l.f2999b.n(i2, i3);
        if (mode == 1073741824 && mode2 == 1073741824) {
            z = true;
        }
        if (z || this.f1075k == null) {
            return;
        }
        if (a1Var.f2838d == 1) {
            p();
        }
        this.l.l0(i2, i3);
        a1Var.f2843i = true;
        q();
        this.l.n0(i2, i3);
        if (this.l.q0()) {
            this.l.l0(View.MeasureSpec.makeMeasureSpec(getMeasuredWidth(), 1073741824), View.MeasureSpec.makeMeasureSpec(getMeasuredHeight(), 1073741824));
            a1Var.f2843i = true;
            q();
            this.l.n0(i2, i3);
        }
    }

    @Override // android.view.ViewGroup
    public final boolean onRequestFocusInDescendants(int i2, Rect rect) {
        if (K()) {
            return false;
        }
        return super.onRequestFocusInDescendants(i2, rect);
    }

    @Override // android.view.View
    public final void onRestoreInstanceState(Parcelable parcelable) {
        Parcelable parcelable2;
        if (!(parcelable instanceof x0)) {
            super.onRestoreInstanceState(parcelable);
            return;
        }
        x0 x0Var = (x0) parcelable;
        this.f1059c = x0Var;
        super.onRestoreInstanceState(x0Var.f2163a);
        o0 o0Var = this.l;
        if (o0Var == null || (parcelable2 = this.f1059c.f3107c) == null) {
            return;
        }
        o0Var.Y(parcelable2);
    }

    @Override // android.view.View
    public final Parcelable onSaveInstanceState() {
        x0 x0Var = new x0(super.onSaveInstanceState());
        x0 x0Var2 = this.f1059c;
        if (x0Var2 != null) {
            x0Var.f3107c = x0Var2.f3107c;
        } else {
            o0 o0Var = this.l;
            x0Var.f3107c = o0Var != null ? o0Var.Z() : null;
        }
        return x0Var;
    }

    @Override // android.view.View
    public final void onSizeChanged(int i2, int i3, int i4, int i5) {
        super.onSizeChanged(i2, i3, i4, i5);
        if (i2 == i4 && i3 == i5) {
            return;
        }
        this.G = null;
        this.E = null;
        this.F = null;
        this.D = null;
    }

    /* JADX WARN: Code restructure failed: missing block: B:274:0x0451, code lost:
        if (r1 < r3) goto L189;
     */
    /* JADX WARN: Code restructure failed: missing block: B:45:0x00e2, code lost:
        if (r15 >= 0) goto L276;
     */
    /* JADX WARN: Code restructure failed: missing block: B:59:0x0139, code lost:
        if (r12 >= 0) goto L289;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:109:0x021a  */
    /* JADX WARN: Removed duplicated region for block: B:116:0x022e  */
    /* JADX WARN: Removed duplicated region for block: B:279:0x0459  */
    /* JADX WARN: Removed duplicated region for block: B:281:0x0461  */
    /* JADX WARN: Removed duplicated region for block: B:297:0x04cc  */
    /* JADX WARN: Removed duplicated region for block: B:306:0x0502  */
    /* JADX WARN: Removed duplicated region for block: B:307:0x050a  */
    /* JADX WARN: Type inference failed for: r5v32, types: [boolean] */
    /* JADX WARN: Type inference failed for: r5v35 */
    @Override // android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public final boolean onTouchEvent(android.view.MotionEvent r27) {
        /*
            Method dump skipped, instructions count: 1299
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.RecyclerView.onTouchEvent(android.view.MotionEvent):boolean");
    }

    public final void p() {
        int F;
        View view;
        int id;
        View A;
        a1 a1Var = this.f1060c0;
        a1Var.a(1);
        z(a1Var);
        a1Var.f2843i = false;
        b0();
        p1 p1Var = this.f1065f;
        p1Var.d();
        O();
        S();
        View focusedChild = (this.V && hasFocus() && this.f1075k != null) ? getFocusedChild() : null;
        d1 H = (focusedChild == null || (A = A(focusedChild)) == null) ? null : H(A);
        if (H == null) {
            a1Var.f2846m = -1L;
            a1Var.l = -1;
            a1Var.f2847n = -1;
        } else {
            a1Var.f2846m = this.f1075k.f2913b ? H.f2879e : -1L;
            if (!this.f1096y) {
                if (H.i()) {
                    F = H.f2878d;
                } else {
                    RecyclerView recyclerView = H.f2891r;
                    if (recyclerView != null) {
                        F = recyclerView.F(H);
                    }
                }
                a1Var.l = F;
                view = H.f2875a;
                loop3: while (true) {
                    id = view.getId();
                    while (!view.isFocused() && (view instanceof ViewGroup) && view.hasFocus()) {
                        view = ((ViewGroup) view).getFocusedChild();
                        if (view.getId() != -1) {
                            break;
                        }
                    }
                }
                a1Var.f2847n = id;
            }
            F = -1;
            a1Var.l = F;
            view = H.f2875a;
            loop3: while (true) {
                id = view.getId();
                while (!view.isFocused()) {
                    view = ((ViewGroup) view).getFocusedChild();
                    if (view.getId() != -1) {
                        break;
                    }
                }
            }
            a1Var.f2847n = id;
        }
        a1Var.f2842h = a1Var.f2844j && this.f1068g0;
        this.f1068g0 = false;
        this.f1066f0 = false;
        a1Var.f2841g = a1Var.f2845k;
        a1Var.f2839e = this.f1075k.a();
        C(this.f1076k0);
        if (a1Var.f2844j) {
            int e2 = this.f1063e.e();
            for (int i2 = 0; i2 < e2; i2++) {
                d1 I = I(this.f1063e.d(i2));
                if (!I.o() && (!I.g() || this.f1075k.f2913b)) {
                    l0 l0Var = this.H;
                    l0.b(I);
                    I.d();
                    l0Var.getClass();
                    k0 k0Var = new k0();
                    k0Var.a(I);
                    p1Var.c(I, k0Var);
                    if (a1Var.f2842h) {
                        if (((I.f2884j & 2) != 0) && !I.i() && !I.o() && !I.g()) {
                            ((j.d) p1Var.f3046c).e(G(I), I);
                        }
                    }
                }
            }
        }
        if (a1Var.f2845k) {
            int h2 = this.f1063e.h();
            for (int i3 = 0; i3 < h2; i3++) {
                d1 I2 = I(this.f1063e.g(i3));
                if (!I2.o() && I2.f2878d == -1) {
                    I2.f2878d = I2.f2877c;
                }
            }
            boolean z = a1Var.f2840f;
            a1Var.f2840f = false;
            this.l.W(this.f1057b, a1Var);
            a1Var.f2840f = z;
            for (int i4 = 0; i4 < this.f1063e.e(); i4++) {
                d1 I3 = I(this.f1063e.d(i4));
                if (!I3.o()) {
                    o1 o1Var = (o1) ((j) p1Var.f3045b).getOrDefault(I3, null);
                    if (!((o1Var == null || (o1Var.f3013a & 4) == 0) ? false : true)) {
                        l0.b(I3);
                        boolean z2 = (I3.f2884j & 8192) != 0;
                        l0 l0Var2 = this.H;
                        I3.d();
                        l0Var2.getClass();
                        k0 k0Var2 = new k0();
                        k0Var2.a(I3);
                        if (z2) {
                            U(I3, k0Var2);
                        } else {
                            o1 o1Var2 = (o1) ((j) p1Var.f3045b).getOrDefault(I3, null);
                            if (o1Var2 == null) {
                                o1Var2 = o1.a();
                                ((j) p1Var.f3045b).put(I3, o1Var2);
                            }
                            o1Var2.f3013a |= 2;
                            o1Var2.f3014b = k0Var2;
                        }
                    }
                }
            }
        }
        k();
        P(true);
        c0(false);
        a1Var.f2838d = 2;
    }

    public final void q() {
        b0();
        O();
        a1 a1Var = this.f1060c0;
        a1Var.a(6);
        this.f1061d.c();
        a1Var.f2839e = this.f1075k.a();
        a1Var.f2837c = 0;
        a1Var.f2841g = false;
        this.l.W(this.f1057b, a1Var);
        a1Var.f2840f = false;
        this.f1059c = null;
        a1Var.f2844j = a1Var.f2844j && this.H != null;
        a1Var.f2838d = 4;
        P(true);
        c0(false);
    }

    public final boolean r(int i2, int i3, int[] iArr, int[] iArr2, int i4) {
        return getScrollingChildHelper().c(i2, i3, iArr, iArr2, i4);
    }

    @Override // android.view.ViewGroup
    public final void removeDetachedView(View view, boolean z) {
        d1 I = I(view);
        if (I != null) {
            if (I.k()) {
                I.f2884j &= -257;
            } else if (!I.o()) {
                throw new IllegalArgumentException("Called removeDetachedView with a view which is not flagged as tmp detached." + I + y());
            }
        }
        view.clearAnimation();
        I(view);
        super.removeDetachedView(view, z);
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public final void requestChildFocus(View view, View view2) {
        z zVar = this.l.f3002e;
        boolean z = true;
        if (!(zVar != null && zVar.f3122e) && !K()) {
            z = false;
        }
        if (!z && view2 != null) {
            V(view, view2);
        }
        super.requestChildFocus(view, view2);
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public final boolean requestChildRectangleOnScreen(View view, Rect rect, boolean z) {
        return this.l.f0(this, view, rect, z, false);
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public final void requestDisallowInterceptTouchEvent(boolean z) {
        ArrayList arrayList = this.f1080n;
        int size = arrayList.size();
        for (int i2 = 0; i2 < size; i2++) {
            ((r0) arrayList.get(i2)).getClass();
        }
        super.requestDisallowInterceptTouchEvent(z);
    }

    @Override // android.view.View, android.view.ViewParent
    public final void requestLayout() {
        if (this.f1090s != 0 || this.f1092u) {
            this.f1091t = true;
        } else {
            super.requestLayout();
        }
    }

    public final void s(int i2, int i3, int i4, int i5, int[] iArr, int i6, int[] iArr2) {
        getScrollingChildHelper().e(i2, i3, i4, i5, iArr, i6, iArr2);
    }

    @Override // android.view.View
    public final void scrollBy(int i2, int i3) {
        o0 o0Var = this.l;
        if (o0Var == null) {
            Log.e("RecyclerView", "Cannot scroll without a LayoutManager set. Call setLayoutManager with a non-null argument.");
        } else if (this.f1092u) {
        } else {
            boolean d2 = o0Var.d();
            boolean e2 = this.l.e();
            if (d2 || e2) {
                if (!d2) {
                    i2 = 0;
                }
                if (!e2) {
                    i3 = 0;
                }
                X(i2, i3, null);
            }
        }
    }

    @Override // android.view.View
    public final void scrollTo(int i2, int i3) {
        Log.w("RecyclerView", "RecyclerView does not support scrolling to an absolute position. Use scrollToPosition instead");
    }

    @Override // android.view.View, android.view.accessibility.AccessibilityEventSource
    public final void sendAccessibilityEventUnchecked(AccessibilityEvent accessibilityEvent) {
        if (K()) {
            int contentChangeTypes = accessibilityEvent != null ? accessibilityEvent.getContentChangeTypes() : 0;
            this.f1094w |= contentChangeTypes != 0 ? contentChangeTypes : 0;
            r1 = 1;
        }
        if (r1 != 0) {
            return;
        }
        super.sendAccessibilityEventUnchecked(accessibilityEvent);
    }

    public void setAccessibilityDelegateCompat(f1 f1Var) {
        this.f1074j0 = f1Var;
        e0.o0.h(this, f1Var);
    }

    public void setAdapter(g0 g0Var) {
        setLayoutFrozen(false);
        g0 g0Var2 = this.f1075k;
        e eVar = this.f1055a;
        if (g0Var2 != null) {
            g0Var2.f2912a.unregisterObserver(eVar);
            this.f1075k.getClass();
        }
        l0 l0Var = this.H;
        if (l0Var != null) {
            l0Var.e();
        }
        o0 o0Var = this.l;
        v0 v0Var = this.f1057b;
        if (o0Var != null) {
            o0Var.b0(v0Var);
            this.l.c0(v0Var);
        }
        v0Var.f3084a.clear();
        v0Var.d();
        b bVar = this.f1061d;
        bVar.l(bVar.f2849b);
        bVar.l(bVar.f2850c);
        g0 g0Var3 = this.f1075k;
        this.f1075k = g0Var;
        if (g0Var != null) {
            g0Var.f2912a.registerObserver(eVar);
        }
        g0 g0Var4 = this.f1075k;
        v0Var.f3084a.clear();
        v0Var.d();
        u0 c2 = v0Var.c();
        if (g0Var3 != null) {
            c2.f3078b--;
        }
        if (c2.f3078b == 0) {
            int i2 = 0;
            while (true) {
                SparseArray sparseArray = c2.f3077a;
                if (i2 >= sparseArray.size()) {
                    break;
                }
                ((t0) sparseArray.valueAt(i2)).f3064a.clear();
                i2++;
            }
        }
        if (g0Var4 != null) {
            c2.f3078b++;
        }
        this.f1060c0.f2840f = true;
        T(false);
        requestLayout();
    }

    public void setChildDrawingOrderCallback(i0 i0Var) {
        if (i0Var == null) {
            return;
        }
        setChildrenDrawingOrderEnabled(false);
    }

    @Override // android.view.ViewGroup
    public void setClipToPadding(boolean z) {
        if (z != this.f1067g) {
            this.G = null;
            this.E = null;
            this.F = null;
            this.D = null;
        }
        this.f1067g = z;
        super.setClipToPadding(z);
        if (this.f1088r) {
            requestLayout();
        }
    }

    public void setEdgeEffectFactory(j0 j0Var) {
        j0Var.getClass();
        this.C = j0Var;
        this.G = null;
        this.E = null;
        this.F = null;
        this.D = null;
    }

    public void setHasFixedSize(boolean z) {
        this.f1086q = z;
    }

    public void setItemAnimator(l0 l0Var) {
        l0 l0Var2 = this.H;
        if (l0Var2 != null) {
            l0Var2.e();
            this.H.f2972a = null;
        }
        this.H = l0Var;
        if (l0Var != null) {
            l0Var.f2972a = this.f1070h0;
        }
    }

    public void setItemViewCacheSize(int i2) {
        v0 v0Var = this.f1057b;
        v0Var.f3088e = i2;
        v0Var.k();
    }

    @Deprecated
    public void setLayoutFrozen(boolean z) {
        suppressLayout(z);
    }

    public void setLayoutManager(o0 o0Var) {
        f0 f0Var;
        RecyclerView recyclerView;
        z zVar;
        if (o0Var == this.l) {
            return;
        }
        int i2 = 0;
        setScrollState(0);
        c1 c1Var = this.W;
        c1Var.f2866g.removeCallbacks(c1Var);
        c1Var.f2862c.abortAnimation();
        o0 o0Var2 = this.l;
        if (o0Var2 != null && (zVar = o0Var2.f3002e) != null) {
            zVar.g();
        }
        o0 o0Var3 = this.l;
        v0 v0Var = this.f1057b;
        if (o0Var3 != null) {
            l0 l0Var = this.H;
            if (l0Var != null) {
                l0Var.e();
            }
            this.l.b0(v0Var);
            this.l.c0(v0Var);
            v0Var.f3084a.clear();
            v0Var.d();
            if (this.f1084p) {
                o0 o0Var4 = this.l;
                o0Var4.f3004g = false;
                o0Var4.M(this);
            }
            this.l.o0(null);
            this.l = null;
        } else {
            v0Var.f3084a.clear();
            v0Var.d();
        }
        d dVar = this.f1063e;
        dVar.f2868b.g();
        ArrayList arrayList = dVar.f2869c;
        int size = arrayList.size();
        while (true) {
            size--;
            f0Var = dVar.f2867a;
            if (size < 0) {
                break;
            }
            f0Var.getClass();
            d1 I = I((View) arrayList.get(size));
            if (I != null) {
                int i3 = I.f2889p;
                RecyclerView recyclerView2 = f0Var.f2903a;
                if (recyclerView2.K()) {
                    I.f2890q = i3;
                    recyclerView2.f1085p0.add(I);
                } else {
                    WeakHashMap weakHashMap = e0.o0.f1697a;
                    y.s(I.f2875a, i3);
                }
                I.f2889p = 0;
            }
            arrayList.remove(size);
        }
        int c2 = f0Var.c();
        while (true) {
            recyclerView = f0Var.f2903a;
            if (i2 >= c2) {
                break;
            }
            View childAt = recyclerView.getChildAt(i2);
            recyclerView.getClass();
            I(childAt);
            g0 g0Var = recyclerView.f1075k;
            childAt.clearAnimation();
            i2++;
        }
        recyclerView.removeAllViews();
        this.l = o0Var;
        if (o0Var != null) {
            if (o0Var.f2999b != null) {
                throw new IllegalArgumentException("LayoutManager " + o0Var + " is already attached to a RecyclerView:" + o0Var.f2999b.y());
            }
            o0Var.o0(this);
            if (this.f1084p) {
                this.l.f3004g = true;
            }
        }
        v0Var.k();
        requestLayout();
    }

    @Override // android.view.ViewGroup
    @Deprecated
    public void setLayoutTransition(LayoutTransition layoutTransition) {
        if (layoutTransition != null) {
            throw new IllegalArgumentException("Providing a LayoutTransition into RecyclerView is not supported. Please use setItemAnimator() instead for animating changes to the items in this RecyclerView");
        }
        super.setLayoutTransition(null);
    }

    @Override // android.view.View
    public void setNestedScrollingEnabled(boolean z) {
        l scrollingChildHelper = getScrollingChildHelper();
        if (scrollingChildHelper.f1692d) {
            WeakHashMap weakHashMap = e0.o0.f1697a;
            e0.e0.z(scrollingChildHelper.f1691c);
        }
        scrollingChildHelper.f1692d = z;
    }

    public void setOnFlingListener(q0 q0Var) {
        this.Q = q0Var;
    }

    @Deprecated
    public void setOnScrollListener(s0 s0Var) {
        this.f1062d0 = s0Var;
    }

    public void setPreserveFocusAfterLayout(boolean z) {
        this.V = z;
    }

    public void setRecycledViewPool(u0 u0Var) {
        u0 u0Var2;
        v0 v0Var = this.f1057b;
        if (v0Var.f3090g != null) {
            u0Var2.f3078b--;
        }
        v0Var.f3090g = u0Var;
        if (u0Var == null || v0Var.f3091h.getAdapter() == null) {
            return;
        }
        v0Var.f3090g.f3078b++;
    }

    public void setRecyclerListener(w0 w0Var) {
    }

    public void setScrollState(int i2) {
        z zVar;
        if (i2 == this.I) {
            return;
        }
        this.I = i2;
        if (i2 != 2) {
            c1 c1Var = this.W;
            c1Var.f2866g.removeCallbacks(c1Var);
            c1Var.f2862c.abortAnimation();
            o0 o0Var = this.l;
            if (o0Var != null && (zVar = o0Var.f3002e) != null) {
                zVar.g();
            }
        }
        o0 o0Var2 = this.l;
        if (o0Var2 != null) {
            o0Var2.a0(i2);
        }
        s0 s0Var = this.f1062d0;
        if (s0Var != null) {
            s0Var.a(this, i2);
        }
        ArrayList arrayList = this.f1064e0;
        if (arrayList == null) {
            return;
        }
        int size = arrayList.size();
        while (true) {
            size--;
            if (size < 0) {
                return;
            }
            ((s0) this.f1064e0.get(size)).a(this, i2);
        }
    }

    public void setScrollingTouchSlop(int i2) {
        int scaledTouchSlop;
        ViewConfiguration viewConfiguration = ViewConfiguration.get(getContext());
        if (i2 != 0) {
            if (i2 == 1) {
                scaledTouchSlop = viewConfiguration.getScaledPagingTouchSlop();
                this.P = scaledTouchSlop;
            }
            Log.w("RecyclerView", "setScrollingTouchSlop(): bad argument constant " + i2 + "; using default value");
        }
        scaledTouchSlop = viewConfiguration.getScaledTouchSlop();
        this.P = scaledTouchSlop;
    }

    public void setViewCacheExtension(b1 b1Var) {
        this.f1057b.getClass();
    }

    @Override // android.view.View
    public final boolean startNestedScroll(int i2) {
        return getScrollingChildHelper().g(i2, 0);
    }

    @Override // android.view.View
    public final void stopNestedScroll() {
        getScrollingChildHelper().h(0);
    }

    @Override // android.view.ViewGroup
    public final void suppressLayout(boolean z) {
        z zVar;
        if (z != this.f1092u) {
            i("Do not suppressLayout in layout or scroll");
            if (!z) {
                this.f1092u = false;
                if (this.f1091t && this.l != null && this.f1075k != null) {
                    requestLayout();
                }
                this.f1091t = false;
                return;
            }
            long uptimeMillis = SystemClock.uptimeMillis();
            onTouchEvent(MotionEvent.obtain(uptimeMillis, uptimeMillis, 3, 0.0f, 0.0f, 0));
            this.f1092u = true;
            this.f1093v = true;
            setScrollState(0);
            c1 c1Var = this.W;
            c1Var.f2866g.removeCallbacks(c1Var);
            c1Var.f2862c.abortAnimation();
            o0 o0Var = this.l;
            if (o0Var == null || (zVar = o0Var.f3002e) == null) {
                return;
            }
            zVar.g();
        }
    }

    public final void t(int i2, int i3) {
        this.B++;
        int scrollX = getScrollX();
        int scrollY = getScrollY();
        onScrollChanged(scrollX, scrollY, scrollX - i2, scrollY - i3);
        s0 s0Var = this.f1062d0;
        if (s0Var != null) {
            s0Var.b(this, i2, i3);
        }
        ArrayList arrayList = this.f1064e0;
        if (arrayList != null) {
            int size = arrayList.size();
            while (true) {
                size--;
                if (size < 0) {
                    break;
                }
                ((s0) this.f1064e0.get(size)).b(this, i2, i3);
            }
        }
        this.B--;
    }

    public final void u() {
        if (this.G != null) {
            return;
        }
        this.C.getClass();
        EdgeEffect edgeEffect = new EdgeEffect(getContext());
        this.G = edgeEffect;
        if (this.f1067g) {
            edgeEffect.setSize((getMeasuredWidth() - getPaddingLeft()) - getPaddingRight(), (getMeasuredHeight() - getPaddingTop()) - getPaddingBottom());
        } else {
            edgeEffect.setSize(getMeasuredWidth(), getMeasuredHeight());
        }
    }

    public final void v() {
        if (this.D != null) {
            return;
        }
        this.C.getClass();
        EdgeEffect edgeEffect = new EdgeEffect(getContext());
        this.D = edgeEffect;
        if (this.f1067g) {
            edgeEffect.setSize((getMeasuredHeight() - getPaddingTop()) - getPaddingBottom(), (getMeasuredWidth() - getPaddingLeft()) - getPaddingRight());
        } else {
            edgeEffect.setSize(getMeasuredHeight(), getMeasuredWidth());
        }
    }

    public final void w() {
        if (this.F != null) {
            return;
        }
        this.C.getClass();
        EdgeEffect edgeEffect = new EdgeEffect(getContext());
        this.F = edgeEffect;
        if (this.f1067g) {
            edgeEffect.setSize((getMeasuredHeight() - getPaddingTop()) - getPaddingBottom(), (getMeasuredWidth() - getPaddingLeft()) - getPaddingRight());
        } else {
            edgeEffect.setSize(getMeasuredHeight(), getMeasuredWidth());
        }
    }

    public final void x() {
        if (this.E != null) {
            return;
        }
        this.C.getClass();
        EdgeEffect edgeEffect = new EdgeEffect(getContext());
        this.E = edgeEffect;
        if (this.f1067g) {
            edgeEffect.setSize((getMeasuredWidth() - getPaddingLeft()) - getPaddingRight(), (getMeasuredHeight() - getPaddingTop()) - getPaddingBottom());
        } else {
            edgeEffect.setSize(getMeasuredWidth(), getMeasuredHeight());
        }
    }

    public final String y() {
        return " " + super.toString() + ", adapter:" + this.f1075k + ", layout:" + this.l + ", context:" + getContext();
    }

    public final void z(a1 a1Var) {
        if (getScrollState() != 2) {
            a1Var.getClass();
            return;
        }
        OverScroller overScroller = this.W.f2862c;
        overScroller.getFinalX();
        overScroller.getCurrX();
        a1Var.getClass();
        overScroller.getFinalY();
        overScroller.getCurrY();
    }

    /* JADX WARN: Can't wrap try/catch for region: R(11:28|(1:30)(10:67|(1:69)|32|33|34|(1:36)(1:51)|37|38|39|40)|31|32|33|34|(0)(0)|37|38|39|40) */
    /* JADX WARN: Code restructure failed: missing block: B:44:0x0249, code lost:
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:46:0x024c, code lost:
        r0 = r4.getConstructor(new java.lang.Class[0]);
     */
    /* JADX WARN: Code restructure failed: missing block: B:47:0x0252, code lost:
        r1 = null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:49:0x0261, code lost:
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:50:0x0262, code lost:
        r0.initCause(r0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:51:0x0282, code lost:
        throw new java.lang.IllegalStateException(r20.getPositionDescription() + ": Error creating LayoutManager " + r3, r0);
     */
    /* JADX WARN: Removed duplicated region for block: B:39:0x0216 A[Catch: ClassCastException -> 0x0283, IllegalAccessException -> 0x02a2, InstantiationException -> 0x02c1, InvocationTargetException -> 0x02de, ClassNotFoundException -> 0x02fb, TryCatch #4 {ClassCastException -> 0x0283, ClassNotFoundException -> 0x02fb, IllegalAccessException -> 0x02a2, InstantiationException -> 0x02c1, InvocationTargetException -> 0x02de, blocks: (B:37:0x0210, B:39:0x0216, B:41:0x0223, B:42:0x022e, B:48:0x0253, B:46:0x024c, B:50:0x0262, B:51:0x0282, B:40:0x021f), top: B:73:0x0210 }] */
    /* JADX WARN: Removed duplicated region for block: B:40:0x021f A[Catch: ClassCastException -> 0x0283, IllegalAccessException -> 0x02a2, InstantiationException -> 0x02c1, InvocationTargetException -> 0x02de, ClassNotFoundException -> 0x02fb, TryCatch #4 {ClassCastException -> 0x0283, ClassNotFoundException -> 0x02fb, IllegalAccessException -> 0x02a2, InstantiationException -> 0x02c1, InvocationTargetException -> 0x02de, blocks: (B:37:0x0210, B:39:0x0216, B:41:0x0223, B:42:0x022e, B:48:0x0253, B:46:0x024c, B:50:0x0262, B:51:0x0282, B:40:0x021f), top: B:73:0x0210 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public RecyclerView(android.content.Context r19, android.util.AttributeSet r20, int r21) {
        /*
            Method dump skipped, instructions count: 825
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.RecyclerView.<init>(android.content.Context, android.util.AttributeSet, int):void");
    }

    @Override // android.view.ViewGroup
    public final ViewGroup.LayoutParams generateLayoutParams(ViewGroup.LayoutParams layoutParams) {
        o0 o0Var = this.l;
        if (o0Var != null) {
            return o0Var.t(layoutParams);
        }
        throw new IllegalStateException("RecyclerView has no LayoutManager" + y());
    }
}