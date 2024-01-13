package androidx.fragment.app;

import android.content.res.Configuration;
import android.os.Bundle;
import android.os.Looper;
import android.os.Parcelable;
import android.util.Log;
import android.view.View;
import android.view.ViewGroup;
import com.example.dropper.R;
import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

/* loaded from: classes.dex */
public final class l0 {
    public boolean A;
    public boolean B;
    public boolean C;
    public boolean D;
    public ArrayList E;
    public ArrayList F;
    public ArrayList G;
    public n0 H;
    public final w I;

    /* renamed from: b  reason: collision with root package name */
    public boolean f825b;

    /* renamed from: d  reason: collision with root package name */
    public ArrayList f827d;

    /* renamed from: e  reason: collision with root package name */
    public ArrayList f828e;

    /* renamed from: g  reason: collision with root package name */
    public androidx.activity.j f830g;

    /* renamed from: k  reason: collision with root package name */
    public final Map f834k;
    public final e0 l;

    /* renamed from: m  reason: collision with root package name */
    public final d0 f835m;

    /* renamed from: n  reason: collision with root package name */
    public final CopyOnWriteArrayList f836n;

    /* renamed from: o  reason: collision with root package name */
    public int f837o;

    /* renamed from: p  reason: collision with root package name */
    public u f838p;

    /* renamed from: q  reason: collision with root package name */
    public androidx.emoji2.text.i f839q;

    /* renamed from: r  reason: collision with root package name */
    public r f840r;

    /* renamed from: s  reason: collision with root package name */
    public r f841s;

    /* renamed from: t  reason: collision with root package name */
    public final g0 f842t;

    /* renamed from: u  reason: collision with root package name */
    public final e0 f843u;

    /* renamed from: v  reason: collision with root package name */
    public androidx.activity.result.d f844v;

    /* renamed from: w  reason: collision with root package name */
    public androidx.activity.result.d f845w;

    /* renamed from: x  reason: collision with root package name */
    public androidx.activity.result.d f846x;

    /* renamed from: y  reason: collision with root package name */
    public ArrayDeque f847y;
    public boolean z;

    /* renamed from: a  reason: collision with root package name */
    public final ArrayList f824a = new ArrayList();

    /* renamed from: c  reason: collision with root package name */
    public final r0 f826c = new r0();

    /* renamed from: f  reason: collision with root package name */
    public final c0 f829f = new c0(this);

    /* renamed from: h  reason: collision with root package name */
    public final f0 f831h = new f0(this);

    /* renamed from: i  reason: collision with root package name */
    public final AtomicInteger f832i = new AtomicInteger();

    /* renamed from: j  reason: collision with root package name */
    public final Map f833j = Collections.synchronizedMap(new HashMap());

    public l0() {
        Collections.synchronizedMap(new HashMap());
        this.f834k = Collections.synchronizedMap(new HashMap());
        this.l = new e0(this, 2);
        this.f835m = new d0(this);
        this.f836n = new CopyOnWriteArrayList();
        this.f837o = -1;
        this.f842t = new g0(this);
        this.f843u = new e0(this, 3);
        this.f847y = new ArrayDeque();
        this.I = new w(3, this);
    }

    public static boolean F(int i2) {
        return Log.isLoggable("FragmentManager", i2);
    }

    public static boolean G(r rVar) {
        rVar.getClass();
        Iterator it = rVar.f922t.f826c.e().iterator();
        boolean z = false;
        while (it.hasNext()) {
            r rVar2 = (r) it.next();
            if (rVar2 != null) {
                z = G(rVar2);
                continue;
            }
            if (z) {
                return true;
            }
        }
        return false;
    }

    public static boolean H(r rVar) {
        return rVar == null || (rVar.B && (rVar.f920r == null || H(rVar.f923u)));
    }

    public static boolean I(r rVar) {
        if (rVar != null) {
            l0 l0Var = rVar.f920r;
            if (!rVar.equals(l0Var.f841s) || !I(l0Var.f840r)) {
                return false;
            }
        }
        return true;
    }

    public static void X(r rVar) {
        if (F(2)) {
            Log.v("FragmentManager", "show: " + rVar);
        }
        if (rVar.f927y) {
            rVar.f927y = false;
            rVar.I = !rVar.I;
        }
    }

    public final r A(int i2) {
        r0 r0Var = this.f826c;
        ArrayList arrayList = r0Var.f928a;
        int size = arrayList.size();
        while (true) {
            size--;
            if (size < 0) {
                for (q0 q0Var : r0Var.f929b.values()) {
                    if (q0Var != null) {
                        r rVar = q0Var.f901c;
                        if (rVar.f924v == i2) {
                            return rVar;
                        }
                    }
                }
                return null;
            }
            r rVar2 = (r) arrayList.get(size);
            if (rVar2 != null && rVar2.f924v == i2) {
                return rVar2;
            }
        }
    }

    public final ViewGroup B(r rVar) {
        ViewGroup viewGroup = rVar.D;
        if (viewGroup != null) {
            return viewGroup;
        }
        if (rVar.f925w > 0 && this.f839q.n0()) {
            View j02 = this.f839q.j0(rVar.f925w);
            if (j02 instanceof ViewGroup) {
                return (ViewGroup) j02;
            }
        }
        return null;
    }

    public final g0 C() {
        r rVar = this.f840r;
        return rVar != null ? rVar.f920r.C() : this.f842t;
    }

    public final e0 D() {
        r rVar = this.f840r;
        return rVar != null ? rVar.f920r.D() : this.f843u;
    }

    public final void E(r rVar) {
        if (F(2)) {
            Log.v("FragmentManager", "hide: " + rVar);
        }
        if (rVar.f927y) {
            return;
        }
        rVar.f927y = true;
        rVar.I = true ^ rVar.I;
        W(rVar);
    }

    /* JADX WARN: Code restructure failed: missing block: B:31:0x0092, code lost:
        if (r0 != 5) goto L33;
     */
    /* JADX WARN: Removed duplicated region for block: B:109:0x01dc  */
    /* JADX WARN: Removed duplicated region for block: B:115:0x01ea  */
    /* JADX WARN: Removed duplicated region for block: B:38:0x00a2  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x00a7  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x00ac  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x00b1  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x00b6  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public final void J(int r18, androidx.fragment.app.r r19) {
        /*
            Method dump skipped, instructions count: 543
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.fragment.app.l0.J(int, androidx.fragment.app.r):void");
    }

    public final void K(int i2, boolean z) {
        HashMap hashMap;
        u uVar;
        if (this.f838p == null && i2 != -1) {
            throw new IllegalStateException("No activity");
        }
        if (z || i2 != this.f837o) {
            this.f837o = i2;
            r0 r0Var = this.f826c;
            Iterator it = r0Var.f928a.iterator();
            while (true) {
                boolean hasNext = it.hasNext();
                hashMap = r0Var.f929b;
                if (!hasNext) {
                    break;
                }
                q0 q0Var = (q0) hashMap.get(((r) it.next()).f908e);
                if (q0Var != null) {
                    q0Var.k();
                }
            }
            Iterator it2 = hashMap.values().iterator();
            while (true) {
                boolean z2 = false;
                if (!it2.hasNext()) {
                    break;
                }
                q0 q0Var2 = (q0) it2.next();
                if (q0Var2 != null) {
                    q0Var2.k();
                    r rVar = q0Var2.f901c;
                    if (rVar.l) {
                        if (!(rVar.f919q > 0)) {
                            z2 = true;
                        }
                    }
                    if (z2) {
                        r0Var.h(q0Var2);
                    }
                }
            }
            Y();
            if (this.z && (uVar = this.f838p) != null && this.f837o == 7) {
                d.y yVar = (d.y) ((d.l) uVar.f949u).k();
                yVar.w();
                yVar.T |= 1;
                if (!yVar.S) {
                    View decorView = yVar.f1600e.getDecorView();
                    WeakHashMap weakHashMap = e0.o0.f1697a;
                    e0.y.m(decorView, yVar.U);
                    yVar.S = true;
                }
                this.z = false;
            }
        }
    }

    public final void L() {
        if (this.f838p == null) {
            return;
        }
        this.A = false;
        this.B = false;
        this.H.f871g = false;
        for (r rVar : this.f826c.f()) {
            if (rVar != null) {
                rVar.f922t.L();
            }
        }
    }

    public final boolean M() {
        x(false);
        w(true);
        r rVar = this.f841s;
        if (rVar == null || !rVar.g().M()) {
            boolean N = N(this.E, this.F, -1, 0);
            if (N) {
                this.f825b = true;
                try {
                    P(this.E, this.F);
                } finally {
                    d();
                }
            }
            a0();
            t();
            this.f826c.f929b.values().removeAll(Collections.singleton(null));
            return N;
        }
        return true;
    }

    public final boolean N(ArrayList arrayList, ArrayList arrayList2, int i2, int i3) {
        a aVar;
        ArrayList arrayList3 = this.f827d;
        if (arrayList3 != null) {
            if (i2 >= 0 || (i3 & 1) != 0) {
                int i4 = -1;
                if (i2 >= 0) {
                    int size = arrayList3.size() - 1;
                    while (size >= 0) {
                        a aVar2 = (a) this.f827d.get(size);
                        if (i2 >= 0 && i2 == aVar2.f735r) {
                            break;
                        }
                        size--;
                    }
                    if (size >= 0) {
                        if ((i3 & 1) != 0) {
                            do {
                                size--;
                                if (size < 0) {
                                    break;
                                }
                                aVar = (a) this.f827d.get(size);
                                if (i2 < 0) {
                                    break;
                                }
                            } while (i2 == aVar.f735r);
                        }
                        i4 = size;
                    }
                }
                if (i4 != this.f827d.size() - 1) {
                    for (int size2 = this.f827d.size() - 1; size2 > i4; size2--) {
                        arrayList.add(this.f827d.remove(size2));
                        arrayList2.add(Boolean.TRUE);
                    }
                    return true;
                }
            } else {
                int size3 = arrayList3.size() - 1;
                if (size3 >= 0) {
                    arrayList.add(this.f827d.remove(size3));
                    arrayList2.add(Boolean.TRUE);
                    return true;
                }
            }
        }
        return false;
    }

    public final void O(r rVar) {
        if (F(2)) {
            Log.v("FragmentManager", "remove: " + rVar + " nesting=" + rVar.f919q);
        }
        boolean z = !(rVar.f919q > 0);
        if (!rVar.z || z) {
            r0 r0Var = this.f826c;
            synchronized (r0Var.f928a) {
                r0Var.f928a.remove(rVar);
            }
            rVar.f914k = false;
            if (G(rVar)) {
                this.z = true;
            }
            rVar.l = true;
            W(rVar);
        }
    }

    public final void P(ArrayList arrayList, ArrayList arrayList2) {
        if (arrayList.isEmpty()) {
            return;
        }
        if (arrayList.size() != arrayList2.size()) {
            throw new IllegalStateException("Internal error with the back stack records");
        }
        int size = arrayList.size();
        int i2 = 0;
        int i3 = 0;
        while (i2 < size) {
            if (!((a) arrayList.get(i2)).f732o) {
                if (i3 != i2) {
                    y(arrayList, arrayList2, i3, i2);
                }
                i3 = i2 + 1;
                if (((Boolean) arrayList2.get(i2)).booleanValue()) {
                    while (i3 < size && ((Boolean) arrayList2.get(i3)).booleanValue() && !((a) arrayList.get(i3)).f732o) {
                        i3++;
                    }
                }
                y(arrayList, arrayList2, i2, i3);
                i2 = i3 - 1;
            }
            i2++;
        }
        if (i3 != size) {
            y(arrayList, arrayList2, i3, size);
        }
    }

    public final void Q(Parcelable parcelable) {
        d0 d0Var;
        int i2;
        q0 q0Var;
        if (parcelable == null) {
            return;
        }
        m0 m0Var = (m0) parcelable;
        if (m0Var.f850a == null) {
            return;
        }
        r0 r0Var = this.f826c;
        r0Var.f929b.clear();
        Iterator it = m0Var.f850a.iterator();
        while (true) {
            boolean hasNext = it.hasNext();
            d0Var = this.f835m;
            if (!hasNext) {
                break;
            }
            p0 p0Var = (p0) it.next();
            if (p0Var != null) {
                r rVar = (r) this.H.f866b.get(p0Var.f888b);
                if (rVar != null) {
                    if (F(2)) {
                        Log.v("FragmentManager", "restoreSaveState: re-attaching retained " + rVar);
                    }
                    q0Var = new q0(d0Var, r0Var, rVar, p0Var);
                } else {
                    q0Var = new q0(this.f835m, this.f826c, this.f838p.f946r.getClassLoader(), C(), p0Var);
                }
                r rVar2 = q0Var.f901c;
                rVar2.f920r = this;
                if (F(2)) {
                    Log.v("FragmentManager", "restoreSaveState: active (" + rVar2.f908e + "): " + rVar2);
                }
                q0Var.m(this.f838p.f946r.getClassLoader());
                r0Var.g(q0Var);
                q0Var.f903e = this.f837o;
            }
        }
        n0 n0Var = this.H;
        n0Var.getClass();
        Iterator it2 = new ArrayList(n0Var.f866b.values()).iterator();
        while (true) {
            if (!it2.hasNext()) {
                break;
            }
            r rVar3 = (r) it2.next();
            if ((r0Var.f929b.get(rVar3.f908e) != null ? 1 : 0) == 0) {
                if (F(2)) {
                    Log.v("FragmentManager", "Discarding retained Fragment " + rVar3 + " that was not found in the set of active Fragments " + m0Var.f850a);
                }
                this.H.b(rVar3);
                rVar3.f920r = this;
                q0 q0Var2 = new q0(d0Var, r0Var, rVar3);
                q0Var2.f903e = 1;
                q0Var2.k();
                rVar3.l = true;
                q0Var2.k();
            }
        }
        ArrayList<String> arrayList = m0Var.f851b;
        r0Var.f928a.clear();
        if (arrayList != null) {
            for (String str : arrayList) {
                r b2 = r0Var.b(str);
                if (b2 == null) {
                    throw new IllegalStateException("No instantiated fragment for (" + str + ")");
                }
                if (F(2)) {
                    Log.v("FragmentManager", "restoreSaveState: added (" + str + "): " + b2);
                }
                r0Var.a(b2);
            }
        }
        if (m0Var.f852c != null) {
            this.f827d = new ArrayList(m0Var.f852c.length);
            int i3 = 0;
            while (true) {
                b[] bVarArr = m0Var.f852c;
                if (i3 >= bVarArr.length) {
                    break;
                }
                b bVar = bVarArr[i3];
                bVar.getClass();
                a aVar = new a(this);
                int i4 = 0;
                int i5 = 0;
                while (true) {
                    int[] iArr = bVar.f745a;
                    if (i4 >= iArr.length) {
                        break;
                    }
                    s0 s0Var = new s0();
                    int i6 = i4 + 1;
                    s0Var.f932a = iArr[i4];
                    if (F(2)) {
                        Log.v("FragmentManager", "Instantiate " + aVar + " op #" + i5 + " base fragment #" + iArr[i6]);
                    }
                    String str2 = (String) bVar.f746b.get(i5);
                    s0Var.f933b = str2 != null ? z(str2) : null;
                    s0Var.f938g = androidx.lifecycle.j.values()[bVar.f747c[i5]];
                    s0Var.f939h = androidx.lifecycle.j.values()[bVar.f748d[i5]];
                    int i7 = i6 + 1;
                    int i8 = iArr[i6];
                    s0Var.f934c = i8;
                    int i9 = i7 + 1;
                    int i10 = iArr[i7];
                    s0Var.f935d = i10;
                    int i11 = i9 + 1;
                    int i12 = iArr[i9];
                    s0Var.f936e = i12;
                    int i13 = iArr[i11];
                    s0Var.f937f = i13;
                    aVar.f720b = i8;
                    aVar.f721c = i10;
                    aVar.f722d = i12;
                    aVar.f723e = i13;
                    aVar.b(s0Var);
                    i5++;
                    i4 = i11 + 1;
                }
                aVar.f724f = bVar.f749e;
                aVar.f726h = bVar.f750f;
                aVar.f735r = bVar.f751g;
                aVar.f725g = true;
                aVar.f727i = bVar.f752h;
                aVar.f728j = bVar.f753i;
                aVar.f729k = bVar.f754j;
                aVar.l = bVar.f755k;
                aVar.f730m = bVar.l;
                aVar.f731n = bVar.f756m;
                aVar.f732o = bVar.f757n;
                aVar.c(1);
                if (F(2)) {
                    Log.v("FragmentManager", "restoreAllState: back stack #" + i3 + " (index " + aVar.f735r + "): " + aVar);
                    PrintWriter printWriter = new PrintWriter(new d1());
                    aVar.e("  ", printWriter, false);
                    printWriter.close();
                }
                this.f827d.add(aVar);
                i3++;
            }
        } else {
            this.f827d = null;
        }
        this.f832i.set(m0Var.f853d);
        String str3 = m0Var.f854e;
        if (str3 != null) {
            r z = z(str3);
            this.f841s = z;
            p(z);
        }
        ArrayList arrayList2 = m0Var.f855f;
        if (arrayList2 != null) {
            while (i2 < arrayList2.size()) {
                Bundle bundle = (Bundle) m0Var.f856g.get(i2);
                bundle.setClassLoader(this.f838p.f946r.getClassLoader());
                this.f833j.put(arrayList2.get(i2), bundle);
                i2++;
            }
        }
        this.f847y = new ArrayDeque(m0Var.f857h);
    }

    public final m0 R() {
        int i2;
        b[] bVarArr;
        ArrayList arrayList;
        int size;
        Iterator it = e().iterator();
        while (true) {
            if (!it.hasNext()) {
                break;
            }
            g1 g1Var = (g1) it.next();
            if (g1Var.f810e) {
                g1Var.f810e = false;
                g1Var.c();
            }
        }
        Iterator it2 = e().iterator();
        while (it2.hasNext()) {
            ((g1) it2.next()).e();
        }
        x(true);
        this.A = true;
        this.H.f871g = true;
        r0 r0Var = this.f826c;
        r0Var.getClass();
        HashMap hashMap = r0Var.f929b;
        ArrayList arrayList2 = new ArrayList(hashMap.size());
        Iterator it3 = hashMap.values().iterator();
        while (true) {
            bVarArr = null;
            bVarArr = null;
            if (!it3.hasNext()) {
                break;
            }
            q0 q0Var = (q0) it3.next();
            if (q0Var != null) {
                r rVar = q0Var.f901c;
                p0 p0Var = new p0(rVar);
                if (rVar.f904a <= -1 || p0Var.f898m != null) {
                    p0Var.f898m = rVar.f905b;
                } else {
                    Bundle bundle = new Bundle();
                    rVar.v(bundle);
                    rVar.P.b(bundle);
                    m0 R = rVar.f922t.R();
                    if (R != null) {
                        bundle.putParcelable("android:support:fragments", R);
                    }
                    q0Var.f899a.k(false);
                    Bundle bundle2 = bundle.isEmpty() ? null : bundle;
                    if (rVar.E != null) {
                        q0Var.o();
                    }
                    if (rVar.f906c != null) {
                        if (bundle2 == null) {
                            bundle2 = new Bundle();
                        }
                        bundle2.putSparseParcelableArray("android:view_state", rVar.f906c);
                    }
                    if (rVar.f907d != null) {
                        if (bundle2 == null) {
                            bundle2 = new Bundle();
                        }
                        bundle2.putBundle("android:view_registry_state", rVar.f907d);
                    }
                    if (!rVar.G) {
                        if (bundle2 == null) {
                            bundle2 = new Bundle();
                        }
                        bundle2.putBoolean("android:user_visible_hint", rVar.G);
                    }
                    p0Var.f898m = bundle2;
                    if (rVar.f911h != null) {
                        if (bundle2 == null) {
                            p0Var.f898m = new Bundle();
                        }
                        p0Var.f898m.putString("android:target_state", rVar.f911h);
                        int i3 = rVar.f912i;
                        if (i3 != 0) {
                            p0Var.f898m.putInt("android:target_req_state", i3);
                        }
                    }
                }
                arrayList2.add(p0Var);
                if (F(2)) {
                    Log.v("FragmentManager", "Saved state of " + rVar + ": " + p0Var.f898m);
                }
            }
        }
        if (arrayList2.isEmpty()) {
            if (F(2)) {
                Log.v("FragmentManager", "saveAllState: no fragments!");
                return null;
            }
            return null;
        }
        r0 r0Var2 = this.f826c;
        synchronized (r0Var2.f928a) {
            if (r0Var2.f928a.isEmpty()) {
                arrayList = null;
            } else {
                arrayList = new ArrayList(r0Var2.f928a.size());
                Iterator it4 = r0Var2.f928a.iterator();
                while (it4.hasNext()) {
                    r rVar2 = (r) it4.next();
                    arrayList.add(rVar2.f908e);
                    if (F(2)) {
                        Log.v("FragmentManager", "saveAllState: adding fragment (" + rVar2.f908e + "): " + rVar2);
                    }
                }
            }
        }
        ArrayList arrayList3 = this.f827d;
        if (arrayList3 != null && (size = arrayList3.size()) > 0) {
            bVarArr = new b[size];
            for (i2 = 0; i2 < size; i2++) {
                bVarArr[i2] = new b((a) this.f827d.get(i2));
                if (F(2)) {
                    Log.v("FragmentManager", "saveAllState: adding back stack #" + i2 + ": " + this.f827d.get(i2));
                }
            }
        }
        m0 m0Var = new m0();
        m0Var.f850a = arrayList2;
        m0Var.f851b = arrayList;
        m0Var.f852c = bVarArr;
        m0Var.f853d = this.f832i.get();
        r rVar3 = this.f841s;
        if (rVar3 != null) {
            m0Var.f854e = rVar3.f908e;
        }
        m0Var.f855f.addAll(this.f833j.keySet());
        m0Var.f856g.addAll(this.f833j.values());
        m0Var.f857h = new ArrayList(this.f847y);
        return m0Var;
    }

    public final void S() {
        synchronized (this.f824a) {
            boolean z = true;
            if (this.f824a.size() != 1) {
                z = false;
            }
            if (z) {
                this.f838p.f947s.removeCallbacks(this.I);
                this.f838p.f947s.post(this.I);
                a0();
            }
        }
    }

    public final void T(r rVar, boolean z) {
        ViewGroup B = B(rVar);
        if (B == null || !(B instanceof a0)) {
            return;
        }
        ((a0) B).setDrawDisappearingViewsLast(!z);
    }

    public final void U(r rVar, androidx.lifecycle.j jVar) {
        if (rVar.equals(z(rVar.f908e)) && (rVar.f921s == null || rVar.f920r == this)) {
            rVar.L = jVar;
            return;
        }
        throw new IllegalArgumentException("Fragment " + rVar + " is not an active fragment of FragmentManager " + this);
    }

    public final void V(r rVar) {
        if (rVar == null || (rVar.equals(z(rVar.f908e)) && (rVar.f921s == null || rVar.f920r == this))) {
            r rVar2 = this.f841s;
            this.f841s = rVar;
            p(rVar2);
            p(this.f841s);
            return;
        }
        throw new IllegalArgumentException("Fragment " + rVar + " is not an active fragment of FragmentManager " + this);
    }

    public final void W(r rVar) {
        ViewGroup B = B(rVar);
        if (B != null) {
            p pVar = rVar.H;
            if ((pVar == null ? 0 : pVar.f879g) + (pVar == null ? 0 : pVar.f878f) + (pVar == null ? 0 : pVar.f877e) + (pVar == null ? 0 : pVar.f876d) > 0) {
                if (B.getTag(R.id.visible_removing_fragment_view_tag) == null) {
                    B.setTag(R.id.visible_removing_fragment_view_tag, rVar);
                }
                r rVar2 = (r) B.getTag(R.id.visible_removing_fragment_view_tag);
                p pVar2 = rVar.H;
                boolean z = pVar2 != null ? pVar2.f875c : false;
                if (rVar2.H == null) {
                    return;
                }
                rVar2.e().f875c = z;
            }
        }
    }

    public final void Y() {
        Iterator it = this.f826c.d().iterator();
        while (it.hasNext()) {
            q0 q0Var = (q0) it.next();
            r rVar = q0Var.f901c;
            if (rVar.F) {
                if (this.f825b) {
                    this.D = true;
                } else {
                    rVar.F = false;
                    q0Var.k();
                }
            }
        }
    }

    /* renamed from: Z */
    public final String toString() {
        Object obj;
        StringBuilder sb = new StringBuilder(128);
        sb.append("FragmentManager{");
        sb.append(Integer.toHexString(System.identityHashCode(this)));
        sb.append(" in ");
        r rVar = this.f840r;
        if (rVar != null) {
            sb.append(rVar.getClass().getSimpleName());
            sb.append("{");
            obj = this.f840r;
        } else {
            u uVar = this.f838p;
            if (uVar == null) {
                sb.append("null");
                sb.append("}}");
                return sb.toString();
            }
            sb.append(uVar.getClass().getSimpleName());
            sb.append("{");
            obj = this.f838p;
        }
        sb.append(Integer.toHexString(System.identityHashCode(obj)));
        sb.append("}");
        sb.append("}}");
        return sb.toString();
    }

    public final q0 a(r rVar) {
        if (F(2)) {
            Log.v("FragmentManager", "add: " + rVar);
        }
        q0 f2 = f(rVar);
        rVar.f920r = this;
        r0 r0Var = this.f826c;
        r0Var.g(f2);
        if (!rVar.z) {
            r0Var.a(rVar);
            rVar.l = false;
            if (rVar.E == null) {
                rVar.I = false;
            }
            if (G(rVar)) {
                this.z = true;
            }
        }
        return f2;
    }

    public final void a0() {
        synchronized (this.f824a) {
            boolean z = true;
            if (!this.f824a.isEmpty()) {
                this.f831h.f790a = true;
                return;
            }
            f0 f0Var = this.f831h;
            ArrayList arrayList = this.f827d;
            if ((arrayList != null ? arrayList.size() : 0) <= 0 || !I(this.f840r)) {
                z = false;
            }
            f0Var.f790a = z;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final void b(u uVar, androidx.emoji2.text.i iVar, r rVar) {
        String str;
        if (this.f838p != null) {
            throw new IllegalStateException("Already attached");
        }
        this.f838p = uVar;
        this.f839q = iVar;
        this.f840r = rVar;
        CopyOnWriteArrayList copyOnWriteArrayList = this.f836n;
        if (rVar != 0) {
            copyOnWriteArrayList.add(new h0(rVar));
        } else if (uVar instanceof o0) {
            copyOnWriteArrayList.add(uVar);
        }
        if (this.f840r != null) {
            a0();
        }
        if (uVar instanceof androidx.activity.k) {
            androidx.activity.j jVar = uVar.f949u.f45f;
            this.f830g = jVar;
            jVar.a(rVar != 0 ? rVar : uVar, this.f831h);
        }
        if (rVar != 0) {
            n0 n0Var = rVar.f920r.H;
            HashMap hashMap = n0Var.f867c;
            n0 n0Var2 = (n0) hashMap.get(rVar.f908e);
            if (n0Var2 == null) {
                n0Var2 = new n0(n0Var.f869e);
                hashMap.put(rVar.f908e, n0Var2);
            }
            this.H = n0Var2;
        } else {
            this.H = uVar instanceof androidx.lifecycle.f0 ? (n0) new androidx.appcompat.widget.z(uVar.b(), n0.f865h).a(n0.class) : new n0(false);
        }
        n0 n0Var3 = this.H;
        n0Var3.f871g = this.A || this.B;
        this.f826c.f930c = n0Var3;
        u uVar2 = this.f838p;
        if (uVar2 instanceof androidx.activity.result.f) {
            androidx.activity.d dVar = uVar2.f949u.f46g;
            if (rVar != 0) {
                str = rVar.f908e + ":";
            } else {
                str = "";
            }
            String str2 = "FragmentManager:" + str;
            this.f844v = dVar.b(str2 + "StartActivityForResult", new b.a(1), new e0(this, 4));
            this.f845w = dVar.b(str2 + "StartIntentSenderForResult", new b.a(2), new e0(this, 0));
            this.f846x = dVar.b(str2 + "RequestPermissions", new b.a(0), new e0(this, 1));
        }
    }

    public final void c(r rVar) {
        if (F(2)) {
            Log.v("FragmentManager", "attach: " + rVar);
        }
        if (rVar.z) {
            rVar.z = false;
            if (rVar.f914k) {
                return;
            }
            this.f826c.a(rVar);
            if (F(2)) {
                Log.v("FragmentManager", "add from attach: " + rVar);
            }
            if (G(rVar)) {
                this.z = true;
            }
        }
    }

    public final void d() {
        this.f825b = false;
        this.F.clear();
        this.E.clear();
    }

    public final HashSet e() {
        HashSet hashSet = new HashSet();
        Iterator it = this.f826c.d().iterator();
        while (it.hasNext()) {
            ViewGroup viewGroup = ((q0) it.next()).f901c.D;
            if (viewGroup != null) {
                hashSet.add(g1.f(viewGroup, D()));
            }
        }
        return hashSet;
    }

    public final q0 f(r rVar) {
        String str = rVar.f908e;
        r0 r0Var = this.f826c;
        q0 q0Var = (q0) r0Var.f929b.get(str);
        if (q0Var != null) {
            return q0Var;
        }
        q0 q0Var2 = new q0(this.f835m, r0Var, rVar);
        q0Var2.m(this.f838p.f946r.getClassLoader());
        q0Var2.f903e = this.f837o;
        return q0Var2;
    }

    public final void g(r rVar) {
        if (F(2)) {
            Log.v("FragmentManager", "detach: " + rVar);
        }
        if (rVar.z) {
            return;
        }
        rVar.z = true;
        if (rVar.f914k) {
            if (F(2)) {
                Log.v("FragmentManager", "remove from detach: " + rVar);
            }
            r0 r0Var = this.f826c;
            synchronized (r0Var.f928a) {
                r0Var.f928a.remove(rVar);
            }
            rVar.f914k = false;
            if (G(rVar)) {
                this.z = true;
            }
            W(rVar);
        }
    }

    public final void h(Configuration configuration) {
        for (r rVar : this.f826c.f()) {
            if (rVar != null) {
                rVar.onConfigurationChanged(configuration);
                rVar.f922t.h(configuration);
            }
        }
    }

    public final boolean i() {
        if (this.f837o < 1) {
            return false;
        }
        for (r rVar : this.f826c.f()) {
            if (rVar != null) {
                if (!rVar.f927y ? rVar.f922t.i() : false) {
                    return true;
                }
            }
        }
        return false;
    }

    public final boolean j() {
        if (this.f837o < 1) {
            return false;
        }
        ArrayList arrayList = null;
        boolean z = false;
        for (r rVar : this.f826c.f()) {
            if (rVar != null && H(rVar)) {
                if (!rVar.f927y ? rVar.f922t.j() | false : false) {
                    if (arrayList == null) {
                        arrayList = new ArrayList();
                    }
                    arrayList.add(rVar);
                    z = true;
                }
            }
        }
        if (this.f828e != null) {
            for (int i2 = 0; i2 < this.f828e.size(); i2++) {
                r rVar2 = (r) this.f828e.get(i2);
                if (arrayList == null || !arrayList.contains(rVar2)) {
                    rVar2.getClass();
                }
            }
        }
        this.f828e = arrayList;
        return z;
    }

    public final void k() {
        Integer num;
        Integer num2;
        Integer num3;
        this.C = true;
        x(true);
        Iterator it = e().iterator();
        while (it.hasNext()) {
            ((g1) it.next()).e();
        }
        s(-1);
        this.f838p = null;
        this.f839q = null;
        this.f840r = null;
        if (this.f830g != null) {
            Iterator it2 = this.f831h.f791b.iterator();
            while (it2.hasNext()) {
                ((androidx.activity.a) it2.next()).cancel();
            }
            this.f830g = null;
        }
        androidx.activity.result.d dVar = this.f844v;
        if (dVar != null) {
            androidx.activity.d dVar2 = dVar.f55b;
            ArrayList arrayList = dVar2.f33e;
            String str = dVar.f54a;
            if (!arrayList.contains(str) && (num3 = (Integer) dVar2.f31c.remove(str)) != null) {
                dVar2.f30b.remove(num3);
            }
            dVar2.f34f.remove(str);
            HashMap hashMap = dVar2.f35g;
            if (hashMap.containsKey(str)) {
                Log.w("ActivityResultRegistry", "Dropping pending result for request " + str + ": " + hashMap.get(str));
                hashMap.remove(str);
            }
            Bundle bundle = dVar2.f36h;
            if (bundle.containsKey(str)) {
                Log.w("ActivityResultRegistry", "Dropping pending result for request " + str + ": " + bundle.getParcelable(str));
                bundle.remove(str);
            }
            androidx.activity.c.g(dVar2.f32d.get(str));
            androidx.activity.result.d dVar3 = this.f845w;
            androidx.activity.d dVar4 = dVar3.f55b;
            ArrayList arrayList2 = dVar4.f33e;
            String str2 = dVar3.f54a;
            if (!arrayList2.contains(str2) && (num2 = (Integer) dVar4.f31c.remove(str2)) != null) {
                dVar4.f30b.remove(num2);
            }
            dVar4.f34f.remove(str2);
            HashMap hashMap2 = dVar4.f35g;
            if (hashMap2.containsKey(str2)) {
                Log.w("ActivityResultRegistry", "Dropping pending result for request " + str2 + ": " + hashMap2.get(str2));
                hashMap2.remove(str2);
            }
            Bundle bundle2 = dVar4.f36h;
            if (bundle2.containsKey(str2)) {
                Log.w("ActivityResultRegistry", "Dropping pending result for request " + str2 + ": " + bundle2.getParcelable(str2));
                bundle2.remove(str2);
            }
            androidx.activity.c.g(dVar4.f32d.get(str2));
            androidx.activity.result.d dVar5 = this.f846x;
            androidx.activity.d dVar6 = dVar5.f55b;
            ArrayList arrayList3 = dVar6.f33e;
            String str3 = dVar5.f54a;
            if (!arrayList3.contains(str3) && (num = (Integer) dVar6.f31c.remove(str3)) != null) {
                dVar6.f30b.remove(num);
            }
            dVar6.f34f.remove(str3);
            HashMap hashMap3 = dVar6.f35g;
            if (hashMap3.containsKey(str3)) {
                Log.w("ActivityResultRegistry", "Dropping pending result for request " + str3 + ": " + hashMap3.get(str3));
                hashMap3.remove(str3);
            }
            Bundle bundle3 = dVar6.f36h;
            if (bundle3.containsKey(str3)) {
                Log.w("ActivityResultRegistry", "Dropping pending result for request " + str3 + ": " + bundle3.getParcelable(str3));
                bundle3.remove(str3);
            }
            androidx.activity.c.g(dVar6.f32d.get(str3));
        }
    }

    public final void l() {
        for (r rVar : this.f826c.f()) {
            if (rVar != null) {
                rVar.onLowMemory();
                rVar.f922t.l();
            }
        }
    }

    public final void m(boolean z) {
        for (r rVar : this.f826c.f()) {
            if (rVar != null) {
                rVar.f922t.m(z);
            }
        }
    }

    public final boolean n() {
        if (this.f837o < 1) {
            return false;
        }
        for (r rVar : this.f826c.f()) {
            if (rVar != null) {
                if (!rVar.f927y ? rVar.f922t.n() : false) {
                    return true;
                }
            }
        }
        return false;
    }

    public final void o() {
        if (this.f837o < 1) {
            return;
        }
        for (r rVar : this.f826c.f()) {
            if (rVar != null && !rVar.f927y) {
                rVar.f922t.o();
            }
        }
    }

    public final void p(r rVar) {
        if (rVar == null || !rVar.equals(z(rVar.f908e))) {
            return;
        }
        rVar.f920r.getClass();
        boolean I = I(rVar);
        Boolean bool = rVar.f913j;
        if (bool == null || bool.booleanValue() != I) {
            rVar.f913j = Boolean.valueOf(I);
            l0 l0Var = rVar.f922t;
            l0Var.a0();
            l0Var.p(l0Var.f841s);
        }
    }

    public final void q(boolean z) {
        for (r rVar : this.f826c.f()) {
            if (rVar != null) {
                rVar.f922t.q(z);
            }
        }
    }

    public final boolean r() {
        if (this.f837o < 1) {
            return false;
        }
        boolean z = false;
        for (r rVar : this.f826c.f()) {
            if (rVar != null && H(rVar)) {
                if (!rVar.f927y ? rVar.f922t.r() | false : false) {
                    z = true;
                }
            }
        }
        return z;
    }

    public final void s(int i2) {
        try {
            this.f825b = true;
            for (q0 q0Var : this.f826c.f929b.values()) {
                if (q0Var != null) {
                    q0Var.f903e = i2;
                }
            }
            K(i2, false);
            Iterator it = e().iterator();
            while (it.hasNext()) {
                ((g1) it.next()).e();
            }
            this.f825b = false;
            x(true);
        } catch (Throwable th) {
            this.f825b = false;
            throw th;
        }
    }

    public final void t() {
        if (this.D) {
            this.D = false;
            Y();
        }
    }

    public final void u(String str, FileDescriptor fileDescriptor, PrintWriter printWriter, String[] strArr) {
        int size;
        int size2;
        String str2 = str + "    ";
        r0 r0Var = this.f826c;
        r0Var.getClass();
        String str3 = str + "    ";
        HashMap hashMap = r0Var.f929b;
        if (!hashMap.isEmpty()) {
            printWriter.print(str);
            printWriter.println("Active Fragments:");
            for (q0 q0Var : hashMap.values()) {
                printWriter.print(str);
                if (q0Var != null) {
                    r rVar = q0Var.f901c;
                    printWriter.println(rVar);
                    rVar.d(str3, fileDescriptor, printWriter, strArr);
                } else {
                    printWriter.println("null");
                }
            }
        }
        ArrayList arrayList = r0Var.f928a;
        int size3 = arrayList.size();
        if (size3 > 0) {
            printWriter.print(str);
            printWriter.println("Added Fragments:");
            for (int i2 = 0; i2 < size3; i2++) {
                printWriter.print(str);
                printWriter.print("  #");
                printWriter.print(i2);
                printWriter.print(": ");
                printWriter.println(((r) arrayList.get(i2)).toString());
            }
        }
        ArrayList arrayList2 = this.f828e;
        if (arrayList2 != null && (size2 = arrayList2.size()) > 0) {
            printWriter.print(str);
            printWriter.println("Fragments Created Menus:");
            for (int i3 = 0; i3 < size2; i3++) {
                printWriter.print(str);
                printWriter.print("  #");
                printWriter.print(i3);
                printWriter.print(": ");
                printWriter.println(((r) this.f828e.get(i3)).toString());
            }
        }
        ArrayList arrayList3 = this.f827d;
        if (arrayList3 != null && (size = arrayList3.size()) > 0) {
            printWriter.print(str);
            printWriter.println("Back Stack:");
            for (int i4 = 0; i4 < size; i4++) {
                a aVar = (a) this.f827d.get(i4);
                printWriter.print(str);
                printWriter.print("  #");
                printWriter.print(i4);
                printWriter.print(": ");
                printWriter.println(aVar.toString());
                aVar.e(str2, printWriter, true);
            }
        }
        printWriter.print(str);
        printWriter.println("Back Stack Index: " + this.f832i.get());
        synchronized (this.f824a) {
            int size4 = this.f824a.size();
            if (size4 > 0) {
                printWriter.print(str);
                printWriter.println("Pending Actions:");
                for (int i5 = 0; i5 < size4; i5++) {
                    printWriter.print(str);
                    printWriter.print("  #");
                    printWriter.print(i5);
                    printWriter.print(": ");
                    printWriter.println((j0) this.f824a.get(i5));
                }
            }
        }
        printWriter.print(str);
        printWriter.println("FragmentManager misc state:");
        printWriter.print(str);
        printWriter.print("  mHost=");
        printWriter.println(this.f838p);
        printWriter.print(str);
        printWriter.print("  mContainer=");
        printWriter.println(this.f839q);
        if (this.f840r != null) {
            printWriter.print(str);
            printWriter.print("  mParent=");
            printWriter.println(this.f840r);
        }
        printWriter.print(str);
        printWriter.print("  mCurState=");
        printWriter.print(this.f837o);
        printWriter.print(" mStateSaved=");
        printWriter.print(this.A);
        printWriter.print(" mStopped=");
        printWriter.print(this.B);
        printWriter.print(" mDestroyed=");
        printWriter.println(this.C);
        if (this.z) {
            printWriter.print(str);
            printWriter.print("  mNeedMenuInvalidate=");
            printWriter.println(this.z);
        }
    }

    public final void v(j0 j0Var, boolean z) {
        if (!z) {
            if (this.f838p == null) {
                if (!this.C) {
                    throw new IllegalStateException("FragmentManager has not been attached to a host.");
                }
                throw new IllegalStateException("FragmentManager has been destroyed");
            }
            if (this.A || this.B) {
                throw new IllegalStateException("Can not perform this action after onSaveInstanceState");
            }
        }
        synchronized (this.f824a) {
            if (this.f838p != null) {
                this.f824a.add(j0Var);
                S();
            } else if (!z) {
                throw new IllegalStateException("Activity has been destroyed");
            }
        }
    }

    public final void w(boolean z) {
        if (this.f825b) {
            throw new IllegalStateException("FragmentManager is already executing transactions");
        }
        if (this.f838p == null) {
            if (!this.C) {
                throw new IllegalStateException("FragmentManager has not been attached to a host.");
            }
            throw new IllegalStateException("FragmentManager has been destroyed");
        } else if (Looper.myLooper() != this.f838p.f947s.getLooper()) {
            throw new IllegalStateException("Must be called from main thread of fragment host");
        } else {
            if (!z) {
                if (this.A || this.B) {
                    throw new IllegalStateException("Can not perform this action after onSaveInstanceState");
                }
            }
            if (this.E == null) {
                this.E = new ArrayList();
                this.F = new ArrayList();
            }
            this.f825b = false;
        }
    }

    public final boolean x(boolean z) {
        boolean z2;
        w(z);
        boolean z3 = false;
        while (true) {
            ArrayList arrayList = this.E;
            ArrayList arrayList2 = this.F;
            synchronized (this.f824a) {
                if (this.f824a.isEmpty()) {
                    z2 = false;
                } else {
                    int size = this.f824a.size();
                    z2 = false;
                    for (int i2 = 0; i2 < size; i2++) {
                        z2 |= ((j0) this.f824a.get(i2)).a(arrayList, arrayList2);
                    }
                    this.f824a.clear();
                    this.f838p.f947s.removeCallbacks(this.I);
                }
            }
            if (!z2) {
                a0();
                t();
                this.f826c.f929b.values().removeAll(Collections.singleton(null));
                return z3;
            }
            z3 = true;
            this.f825b = true;
            try {
                P(this.E, this.F);
            } finally {
                d();
            }
        }
    }

    public final void y(ArrayList arrayList, ArrayList arrayList2, int i2, int i3) {
        ViewGroup viewGroup;
        r0 r0Var;
        r0 r0Var2;
        r0 r0Var3;
        int i4;
        ArrayList arrayList3 = arrayList;
        ArrayList arrayList4 = arrayList2;
        boolean z = ((a) arrayList3.get(i2)).f732o;
        ArrayList arrayList5 = this.G;
        if (arrayList5 == null) {
            this.G = new ArrayList();
        } else {
            arrayList5.clear();
        }
        ArrayList arrayList6 = this.G;
        r0 r0Var4 = this.f826c;
        arrayList6.addAll(r0Var4.f());
        r rVar = this.f841s;
        int i5 = i2;
        boolean z2 = false;
        while (true) {
            int i6 = 1;
            if (i5 >= i3) {
                r0 r0Var5 = r0Var4;
                this.G.clear();
                if (!z && this.f837o >= 1) {
                    for (int i7 = i2; i7 < i3; i7++) {
                        Iterator it = ((a) arrayList.get(i7)).f719a.iterator();
                        while (it.hasNext()) {
                            r rVar2 = ((s0) it.next()).f933b;
                            if (rVar2 == null || rVar2.f920r == null) {
                                r0Var = r0Var5;
                            } else {
                                r0Var = r0Var5;
                                r0Var.g(f(rVar2));
                            }
                            r0Var5 = r0Var;
                        }
                    }
                }
                for (int i8 = i2; i8 < i3; i8++) {
                    a aVar = (a) arrayList.get(i8);
                    if (((Boolean) arrayList2.get(i8)).booleanValue()) {
                        aVar.c(-1);
                        aVar.g();
                    } else {
                        aVar.c(1);
                        aVar.f();
                    }
                }
                boolean booleanValue = ((Boolean) arrayList2.get(i3 - 1)).booleanValue();
                for (int i9 = i2; i9 < i3; i9++) {
                    a aVar2 = (a) arrayList.get(i9);
                    if (booleanValue) {
                        for (int size = aVar2.f719a.size() - 1; size >= 0; size--) {
                            r rVar3 = ((s0) aVar2.f719a.get(size)).f933b;
                            if (rVar3 != null) {
                                f(rVar3).k();
                            }
                        }
                    } else {
                        Iterator it2 = aVar2.f719a.iterator();
                        while (it2.hasNext()) {
                            r rVar4 = ((s0) it2.next()).f933b;
                            if (rVar4 != null) {
                                f(rVar4).k();
                            }
                        }
                    }
                }
                K(this.f837o, true);
                HashSet hashSet = new HashSet();
                for (int i10 = i2; i10 < i3; i10++) {
                    Iterator it3 = ((a) arrayList.get(i10)).f719a.iterator();
                    while (it3.hasNext()) {
                        r rVar5 = ((s0) it3.next()).f933b;
                        if (rVar5 != null && (viewGroup = rVar5.D) != null) {
                            hashSet.add(g1.f(viewGroup, D()));
                        }
                    }
                }
                Iterator it4 = hashSet.iterator();
                while (it4.hasNext()) {
                    g1 g1Var = (g1) it4.next();
                    g1Var.f809d = booleanValue;
                    g1Var.g();
                    g1Var.c();
                }
                for (int i11 = i2; i11 < i3; i11++) {
                    a aVar3 = (a) arrayList.get(i11);
                    if (((Boolean) arrayList2.get(i11)).booleanValue() && aVar3.f735r >= 0) {
                        aVar3.f735r = -1;
                    }
                    aVar3.getClass();
                }
                return;
            }
            a aVar4 = (a) arrayList3.get(i5);
            if (((Boolean) arrayList4.get(i5)).booleanValue()) {
                r0Var2 = r0Var4;
                int i12 = 1;
                ArrayList arrayList7 = this.G;
                ArrayList arrayList8 = aVar4.f719a;
                int size2 = arrayList8.size() - 1;
                while (size2 >= 0) {
                    s0 s0Var = (s0) arrayList8.get(size2);
                    int i13 = s0Var.f932a;
                    if (i13 != i12) {
                        if (i13 != 3) {
                            switch (i13) {
                                case 8:
                                    rVar = null;
                                    break;
                                case 9:
                                    rVar = s0Var.f933b;
                                    break;
                                case 10:
                                    s0Var.f939h = s0Var.f938g;
                                    break;
                            }
                            size2--;
                            i12 = 1;
                        }
                        arrayList7.add(s0Var.f933b);
                        size2--;
                        i12 = 1;
                    }
                    arrayList7.remove(s0Var.f933b);
                    size2--;
                    i12 = 1;
                }
            } else {
                ArrayList arrayList9 = this.G;
                int i14 = 0;
                while (true) {
                    ArrayList arrayList10 = aVar4.f719a;
                    if (i14 < arrayList10.size()) {
                        s0 s0Var2 = (s0) arrayList10.get(i14);
                        int i15 = s0Var2.f932a;
                        if (i15 != i6) {
                            if (i15 != 2) {
                                if (i15 == 3 || i15 == 6) {
                                    arrayList9.remove(s0Var2.f933b);
                                    r rVar6 = s0Var2.f933b;
                                    if (rVar6 == rVar) {
                                        arrayList10.add(i14, new s0(9, rVar6));
                                        i14++;
                                        r0Var3 = r0Var4;
                                        i4 = 1;
                                        rVar = null;
                                    }
                                } else if (i15 == 7) {
                                    r0Var3 = r0Var4;
                                    i4 = 1;
                                } else if (i15 == 8) {
                                    arrayList10.add(i14, new s0(9, rVar));
                                    i14++;
                                    rVar = s0Var2.f933b;
                                }
                                r0Var3 = r0Var4;
                                i4 = 1;
                            } else {
                                r rVar7 = s0Var2.f933b;
                                int i16 = rVar7.f925w;
                                int size3 = arrayList9.size() - 1;
                                boolean z3 = false;
                                while (size3 >= 0) {
                                    r0 r0Var6 = r0Var4;
                                    r rVar8 = (r) arrayList9.get(size3);
                                    if (rVar8.f925w == i16) {
                                        if (rVar8 == rVar7) {
                                            z3 = true;
                                        } else {
                                            if (rVar8 == rVar) {
                                                arrayList10.add(i14, new s0(9, rVar8));
                                                i14++;
                                                rVar = null;
                                            }
                                            s0 s0Var3 = new s0(3, rVar8);
                                            s0Var3.f934c = s0Var2.f934c;
                                            s0Var3.f936e = s0Var2.f936e;
                                            s0Var3.f935d = s0Var2.f935d;
                                            s0Var3.f937f = s0Var2.f937f;
                                            arrayList10.add(i14, s0Var3);
                                            arrayList9.remove(rVar8);
                                            i14++;
                                            rVar = rVar;
                                        }
                                    }
                                    size3--;
                                    r0Var4 = r0Var6;
                                }
                                r0Var3 = r0Var4;
                                i4 = 1;
                                if (z3) {
                                    arrayList10.remove(i14);
                                    i14--;
                                } else {
                                    s0Var2.f932a = 1;
                                    arrayList9.add(rVar7);
                                }
                            }
                            i14 += i4;
                            i6 = i4;
                            r0Var4 = r0Var3;
                        } else {
                            r0Var3 = r0Var4;
                            i4 = i6;
                        }
                        arrayList9.add(s0Var2.f933b);
                        i14 += i4;
                        i6 = i4;
                        r0Var4 = r0Var3;
                    } else {
                        r0Var2 = r0Var4;
                    }
                }
            }
            z2 = z2 || aVar4.f725g;
            i5++;
            arrayList3 = arrayList;
            arrayList4 = arrayList2;
            r0Var4 = r0Var2;
        }
    }

    public final r z(String str) {
        return this.f826c.b(str);
    }
}