package a1;

import android.view.View;
import com.google.android.material.bottomsheet.BottomSheetBehavior;
import e0.o0;
import e0.y;
import java.util.WeakHashMap;

/* loaded from: classes.dex */
public final class e implements Runnable {

    /* renamed from: a  reason: collision with root package name */
    public final View f15a;

    /* renamed from: b  reason: collision with root package name */
    public boolean f16b;

    /* renamed from: c  reason: collision with root package name */
    public int f17c;

    /* renamed from: d  reason: collision with root package name */
    public final /* synthetic */ BottomSheetBehavior f18d;

    public e(BottomSheetBehavior bottomSheetBehavior, View view, int i2) {
        this.f18d = bottomSheetBehavior;
        this.f15a = view;
        this.f17c = i2;
    }

    @Override // java.lang.Runnable
    public final void run() {
        BottomSheetBehavior bottomSheetBehavior = this.f18d;
        k0.d dVar = bottomSheetBehavior.H;
        if (dVar == null || !dVar.g()) {
            bottomSheetBehavior.C(this.f17c);
        } else {
            WeakHashMap weakHashMap = o0.f1697a;
            y.m(this.f15a, this);
        }
        this.f16b = false;
    }
}