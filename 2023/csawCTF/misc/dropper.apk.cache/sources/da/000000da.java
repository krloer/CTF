package androidx.fragment.app;

import android.util.Log;
import android.view.View;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;

/* loaded from: classes.dex */
public final class f1 {

    /* renamed from: a  reason: collision with root package name */
    public int f793a;

    /* renamed from: b  reason: collision with root package name */
    public int f794b;

    /* renamed from: c  reason: collision with root package name */
    public final r f795c;

    /* renamed from: d  reason: collision with root package name */
    public final ArrayList f796d;

    /* renamed from: e  reason: collision with root package name */
    public final HashSet f797e;

    /* renamed from: f  reason: collision with root package name */
    public boolean f798f;

    /* renamed from: g  reason: collision with root package name */
    public boolean f799g;

    /* renamed from: h  reason: collision with root package name */
    public final q0 f800h;

    public f1(int i2, int i3, q0 q0Var, a0.b bVar) {
        r rVar = q0Var.f901c;
        this.f796d = new ArrayList();
        this.f797e = new HashSet();
        this.f798f = false;
        this.f799g = false;
        this.f793a = i2;
        this.f794b = i3;
        this.f795c = rVar;
        bVar.b(new l(3, this));
        this.f800h = q0Var;
    }

    public final void a() {
        if (this.f798f) {
            return;
        }
        this.f798f = true;
        HashSet hashSet = this.f797e;
        if (hashSet.isEmpty()) {
            b();
            return;
        }
        Iterator it = new ArrayList(hashSet).iterator();
        while (it.hasNext()) {
            ((a0.b) it.next()).a();
        }
    }

    public final void b() {
        if (!this.f799g) {
            if (l0.F(2)) {
                Log.v("FragmentManager", "SpecialEffectsController: " + this + " has called complete.");
            }
            this.f799g = true;
            Iterator it = this.f796d.iterator();
            while (it.hasNext()) {
                ((Runnable) it.next()).run();
            }
        }
        this.f800h.k();
    }

    public final void c(int i2, int i3) {
        if (i3 == 0) {
            throw null;
        }
        int i4 = i3 - 1;
        r rVar = this.f795c;
        if (i4 == 0) {
            if (this.f793a != 1) {
                if (l0.F(2)) {
                    Log.v("FragmentManager", "SpecialEffectsController: For fragment " + rVar + " mFinalState = " + androidx.activity.c.k(this.f793a) + " -> " + androidx.activity.c.k(i2) + ". ");
                }
                this.f793a = i2;
            }
        } else if (i4 == 1) {
            if (this.f793a == 1) {
                if (l0.F(2)) {
                    Log.v("FragmentManager", "SpecialEffectsController: For fragment " + rVar + " mFinalState = REMOVED -> VISIBLE. mLifecycleImpact = " + androidx.activity.c.j(this.f794b) + " to ADDING.");
                }
                this.f793a = 2;
                this.f794b = 2;
            }
        } else if (i4 != 2) {
        } else {
            if (l0.F(2)) {
                Log.v("FragmentManager", "SpecialEffectsController: For fragment " + rVar + " mFinalState = " + androidx.activity.c.k(this.f793a) + " -> REMOVED. mLifecycleImpact  = " + androidx.activity.c.j(this.f794b) + " to REMOVING.");
            }
            this.f793a = 1;
            this.f794b = 3;
        }
    }

    public final void d() {
        if (this.f794b == 2) {
            q0 q0Var = this.f800h;
            r rVar = q0Var.f901c;
            View findFocus = rVar.E.findFocus();
            if (findFocus != null) {
                rVar.e().f886o = findFocus;
                if (l0.F(2)) {
                    Log.v("FragmentManager", "requestFocus: Saved focused view " + findFocus + " for Fragment " + rVar);
                }
            }
            View C = this.f795c.C();
            if (C.getParent() == null) {
                q0Var.b();
                C.setAlpha(0.0f);
            }
            if (C.getAlpha() == 0.0f && C.getVisibility() == 0) {
                C.setVisibility(4);
            }
            p pVar = rVar.H;
            C.setAlpha(pVar == null ? 1.0f : pVar.f885n);
        }
    }

    /* renamed from: e */
    public final String toString() {
        return "Operation {" + Integer.toHexString(System.identityHashCode(this)) + "} {mFinalState = " + androidx.activity.c.k(this.f793a) + "} {mLifecycleImpact = " + androidx.activity.c.j(this.f794b) + "} {mFragment = " + this.f795c + "}";
    }
}