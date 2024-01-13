package androidx.fragment.app;

import android.animation.LayoutTransition;
import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.widget.FrameLayout;
import com.example.dropper.R;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.WeakHashMap;

/* loaded from: classes.dex */
public final class a0 extends FrameLayout {

    /* renamed from: a  reason: collision with root package name */
    public ArrayList f736a;

    /* renamed from: b  reason: collision with root package name */
    public ArrayList f737b;

    /* renamed from: c  reason: collision with root package name */
    public View.OnApplyWindowInsetsListener f738c;

    /* renamed from: d  reason: collision with root package name */
    public boolean f739d;

    public a0(Context context, AttributeSet attributeSet, l0 l0Var) {
        super(context, attributeSet);
        View view;
        this.f739d = true;
        String classAttribute = attributeSet.getClassAttribute();
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, n0.a.f2553b);
        classAttribute = classAttribute == null ? obtainStyledAttributes.getString(0) : classAttribute;
        String string = obtainStyledAttributes.getString(1);
        obtainStyledAttributes.recycle();
        int id = getId();
        r A = l0Var.A(id);
        if (classAttribute != null && A == null) {
            if (id <= 0) {
                String concat = string != null ? " with tag ".concat(string) : "";
                throw new IllegalStateException("FragmentContainerView must have an android:id to add Fragment " + classAttribute + concat);
            }
            g0 C = l0Var.C();
            context.getClassLoader();
            r a2 = C.a(classAttribute);
            a2.C = true;
            u uVar = a2.f921s;
            if ((uVar == null ? null : uVar.f945q) != null) {
                a2.C = true;
            }
            a aVar = new a(l0Var);
            aVar.f732o = true;
            a2.D = this;
            int id2 = getId();
            Class<?> cls = a2.getClass();
            int modifiers = cls.getModifiers();
            if (cls.isAnonymousClass() || !Modifier.isPublic(modifiers) || (cls.isMemberClass() && !Modifier.isStatic(modifiers))) {
                throw new IllegalStateException("Fragment " + cls.getCanonicalName() + " must be a public static class to be  properly recreated from instance state.");
            }
            if (string != null) {
                String str = a2.f926x;
                if (str != null && !string.equals(str)) {
                    throw new IllegalStateException("Can't change tag of fragment " + a2 + ": was " + a2.f926x + " now " + string);
                }
                a2.f926x = string;
            }
            if (id2 != 0) {
                if (id2 == -1) {
                    throw new IllegalArgumentException("Can't add fragment " + a2 + " with tag " + string + " to container view with no id");
                }
                int i2 = a2.f924v;
                if (i2 != 0 && i2 != id2) {
                    throw new IllegalStateException("Can't change container ID of fragment " + a2 + ": was " + a2.f924v + " now " + id2);
                }
                a2.f924v = id2;
                a2.f925w = id2;
            }
            aVar.b(new s0(1, a2));
            l0 l0Var2 = aVar.f733p;
            a2.f920r = l0Var2;
            if (aVar.f725g) {
                throw new IllegalStateException("This transaction is already being added to the back stack");
            }
            if (l0Var2.f838p != null && !l0Var2.C) {
                l0Var2.w(true);
                aVar.a(l0Var2.E, l0Var2.F);
                l0Var2.f825b = true;
                try {
                    l0Var2.P(l0Var2.E, l0Var2.F);
                    l0Var2.d();
                    l0Var2.a0();
                    l0Var2.t();
                    l0Var2.f826c.f929b.values().removeAll(Collections.singleton(null));
                } catch (Throwable th) {
                    l0Var2.d();
                    throw th;
                }
            }
        }
        Iterator it = l0Var.f826c.d().iterator();
        while (it.hasNext()) {
            q0 q0Var = (q0) it.next();
            r rVar = q0Var.f901c;
            if (rVar.f925w == getId() && (view = rVar.E) != null && view.getParent() == null) {
                rVar.D = this;
                q0Var.b();
            }
        }
    }

    public final void a(View view) {
        ArrayList arrayList = this.f737b;
        if (arrayList == null || !arrayList.contains(view)) {
            return;
        }
        if (this.f736a == null) {
            this.f736a = new ArrayList();
        }
        this.f736a.add(view);
    }

    @Override // android.view.ViewGroup
    public final void addView(View view, int i2, ViewGroup.LayoutParams layoutParams) {
        Object tag = view.getTag(R.id.fragment_container_view_tag);
        if ((tag instanceof r ? (r) tag : null) != null) {
            super.addView(view, i2, layoutParams);
            return;
        }
        throw new IllegalStateException("Views added to a FragmentContainerView must be associated with a Fragment. View " + view + " is not associated with a Fragment.");
    }

    @Override // android.view.ViewGroup
    public final boolean addViewInLayout(View view, int i2, ViewGroup.LayoutParams layoutParams, boolean z) {
        Object tag = view.getTag(R.id.fragment_container_view_tag);
        if ((tag instanceof r ? (r) tag : null) != null) {
            return super.addViewInLayout(view, i2, layoutParams, z);
        }
        throw new IllegalStateException("Views added to a FragmentContainerView must be associated with a Fragment. View " + view + " is not associated with a Fragment.");
    }

    @Override // android.view.ViewGroup, android.view.View
    public final WindowInsets dispatchApplyWindowInsets(WindowInsets windowInsets) {
        e0.d1 d1Var;
        e0.d1 f2 = e0.d1.f(windowInsets, null);
        View.OnApplyWindowInsetsListener onApplyWindowInsetsListener = this.f738c;
        if (onApplyWindowInsetsListener != null) {
            d1Var = e0.d1.f(onApplyWindowInsetsListener.onApplyWindowInsets(this, windowInsets), null);
        } else {
            WeakHashMap weakHashMap = e0.o0.f1697a;
            WindowInsets e2 = f2.e();
            if (e2 != null) {
                WindowInsets b2 = e0.c0.b(this, e2);
                if (!b2.equals(e2)) {
                    f2 = e0.d1.f(b2, this);
                }
            }
            d1Var = f2;
        }
        if (!d1Var.f1680a.j()) {
            int childCount = getChildCount();
            for (int i2 = 0; i2 < childCount; i2++) {
                View childAt = getChildAt(i2);
                WeakHashMap weakHashMap2 = e0.o0.f1697a;
                WindowInsets e3 = d1Var.e();
                if (e3 != null) {
                    WindowInsets a2 = e0.c0.a(childAt, e3);
                    if (!a2.equals(e3)) {
                        e0.d1.f(a2, childAt);
                    }
                }
            }
        }
        return windowInsets;
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void dispatchDraw(Canvas canvas) {
        if (this.f739d && this.f736a != null) {
            for (int i2 = 0; i2 < this.f736a.size(); i2++) {
                super.drawChild(canvas, (View) this.f736a.get(i2), getDrawingTime());
            }
        }
        super.dispatchDraw(canvas);
    }

    @Override // android.view.ViewGroup
    public final boolean drawChild(Canvas canvas, View view, long j2) {
        ArrayList arrayList;
        if (!this.f739d || (arrayList = this.f736a) == null || arrayList.size() <= 0 || !this.f736a.contains(view)) {
            return super.drawChild(canvas, view, j2);
        }
        return false;
    }

    @Override // android.view.ViewGroup
    public final void endViewTransition(View view) {
        ArrayList arrayList = this.f737b;
        if (arrayList != null) {
            arrayList.remove(view);
            ArrayList arrayList2 = this.f736a;
            if (arrayList2 != null && arrayList2.remove(view)) {
                this.f739d = true;
            }
        }
        super.endViewTransition(view);
    }

    @Override // android.view.View
    public final WindowInsets onApplyWindowInsets(WindowInsets windowInsets) {
        return windowInsets;
    }

    @Override // android.view.ViewGroup
    public final void removeAllViewsInLayout() {
        for (int childCount = getChildCount() - 1; childCount >= 0; childCount--) {
            a(getChildAt(childCount));
        }
        super.removeAllViewsInLayout();
    }

    @Override // android.view.ViewGroup
    public final void removeDetachedView(View view, boolean z) {
        if (z) {
            a(view);
        }
        super.removeDetachedView(view, z);
    }

    @Override // android.view.ViewGroup, android.view.ViewManager
    public final void removeView(View view) {
        a(view);
        super.removeView(view);
    }

    @Override // android.view.ViewGroup
    public final void removeViewAt(int i2) {
        a(getChildAt(i2));
        super.removeViewAt(i2);
    }

    @Override // android.view.ViewGroup
    public final void removeViewInLayout(View view) {
        a(view);
        super.removeViewInLayout(view);
    }

    @Override // android.view.ViewGroup
    public final void removeViews(int i2, int i3) {
        for (int i4 = i2; i4 < i2 + i3; i4++) {
            a(getChildAt(i4));
        }
        super.removeViews(i2, i3);
    }

    @Override // android.view.ViewGroup
    public final void removeViewsInLayout(int i2, int i3) {
        for (int i4 = i2; i4 < i2 + i3; i4++) {
            a(getChildAt(i4));
        }
        super.removeViewsInLayout(i2, i3);
    }

    public void setDrawDisappearingViewsLast(boolean z) {
        this.f739d = z;
    }

    @Override // android.view.ViewGroup
    public void setLayoutTransition(LayoutTransition layoutTransition) {
        throw new UnsupportedOperationException("FragmentContainerView does not support Layout Transitions or animateLayoutChanges=\"true\".");
    }

    @Override // android.view.View
    public void setOnApplyWindowInsetsListener(View.OnApplyWindowInsetsListener onApplyWindowInsetsListener) {
        this.f738c = onApplyWindowInsetsListener;
    }

    @Override // android.view.ViewGroup
    public final void startViewTransition(View view) {
        if (view.getParent() == this) {
            if (this.f737b == null) {
                this.f737b = new ArrayList();
            }
            this.f737b.add(view);
        }
        super.startViewTransition(view);
    }
}