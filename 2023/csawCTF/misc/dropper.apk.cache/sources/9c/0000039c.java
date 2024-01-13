package z0;

import android.view.View;
import com.google.android.material.behavior.SwipeDismissBehavior;
import e0.o0;
import e0.y;
import java.util.WeakHashMap;
import k0.d;

/* loaded from: classes.dex */
public final class b implements Runnable {

    /* renamed from: a  reason: collision with root package name */
    public final View f3341a;

    /* renamed from: b  reason: collision with root package name */
    public final /* synthetic */ SwipeDismissBehavior f3342b;

    public b(SwipeDismissBehavior swipeDismissBehavior, View view, boolean z) {
        this.f3342b = swipeDismissBehavior;
        this.f3341a = view;
    }

    @Override // java.lang.Runnable
    public final void run() {
        d dVar = this.f3342b.f1229a;
        if (dVar == null || !dVar.g()) {
            return;
        }
        WeakHashMap weakHashMap = o0.f1697a;
        y.m(this.f3341a, this);
    }
}