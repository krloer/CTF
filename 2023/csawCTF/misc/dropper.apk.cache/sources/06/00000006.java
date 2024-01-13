package a1;

import android.view.View;
import androidx.emoji2.text.i;
import com.google.android.material.bottomsheet.BottomSheetBehavior;
import java.lang.ref.WeakReference;

/* loaded from: classes.dex */
public final class c extends i {

    /* renamed from: q  reason: collision with root package name */
    public final /* synthetic */ BottomSheetBehavior f9q;

    public c(BottomSheetBehavior bottomSheetBehavior) {
        this.f9q = bottomSheetBehavior;
    }

    @Override // androidx.emoji2.text.i
    public final boolean J0(View view, int i2) {
        BottomSheetBehavior bottomSheetBehavior = this.f9q;
        int i3 = bottomSheetBehavior.G;
        if (i3 == 1 || bottomSheetBehavior.U) {
            return false;
        }
        if (i3 == 3 && bottomSheetBehavior.S == i2) {
            WeakReference weakReference = bottomSheetBehavior.P;
            View view2 = weakReference != null ? (View) weakReference.get() : null;
            if (view2 != null && view2.canScrollVertically(-1)) {
                return false;
            }
        }
        System.currentTimeMillis();
        WeakReference weakReference2 = bottomSheetBehavior.O;
        return weakReference2 != null && weakReference2.get() == view;
    }

    @Override // androidx.emoji2.text.i
    public final int U() {
        BottomSheetBehavior bottomSheetBehavior = this.f9q;
        return bottomSheetBehavior.D ? bottomSheetBehavior.N : bottomSheetBehavior.B;
    }

    @Override // androidx.emoji2.text.i
    public final void r0(int i2) {
        if (i2 == 1) {
            BottomSheetBehavior bottomSheetBehavior = this.f9q;
            if (bottomSheetBehavior.F) {
                bottomSheetBehavior.C(1);
            }
        }
    }

    @Override // androidx.emoji2.text.i
    public final void s0(View view, int i2, int i3) {
        this.f9q.u(i3);
    }

    /* JADX WARN: Code restructure failed: missing block: B:28:0x006e, code lost:
        if (java.lang.Math.abs(r5.getTop() - r4.x()) < java.lang.Math.abs(r5.getTop() - r4.z)) goto L7;
     */
    /* JADX WARN: Code restructure failed: missing block: B:39:0x009a, code lost:
        if (java.lang.Math.abs(r6 - r4.z) < java.lang.Math.abs(r6 - r4.B)) goto L31;
     */
    /* JADX WARN: Code restructure failed: missing block: B:44:0x00b4, code lost:
        if (java.lang.Math.abs(r6 - r4.f1259y) < java.lang.Math.abs(r6 - r4.B)) goto L13;
     */
    /* JADX WARN: Code restructure failed: missing block: B:50:0x00c6, code lost:
        if (r6 < java.lang.Math.abs(r6 - r4.B)) goto L7;
     */
    /* JADX WARN: Code restructure failed: missing block: B:51:0x00c8, code lost:
        r6 = r4.x();
     */
    /* JADX WARN: Code restructure failed: missing block: B:54:0x00dc, code lost:
        if (java.lang.Math.abs(r6 - r7) < java.lang.Math.abs(r6 - r4.B)) goto L31;
     */
    /* JADX WARN: Code restructure failed: missing block: B:8:0x0018, code lost:
        if (r6 > r7) goto L10;
     */
    @Override // androidx.emoji2.text.i
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public final void t0(android.view.View r5, float r6, float r7) {
        /*
            Method dump skipped, instructions count: 235
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: a1.c.t0(android.view.View, float, float):void");
    }

    @Override // androidx.emoji2.text.i
    public final int x(View view, int i2) {
        return view.getLeft();
    }

    @Override // androidx.emoji2.text.i
    public final int y(View view, int i2) {
        BottomSheetBehavior bottomSheetBehavior = this.f9q;
        int x2 = bottomSheetBehavior.x();
        int i3 = bottomSheetBehavior.D ? bottomSheetBehavior.N : bottomSheetBehavior.B;
        return i2 < x2 ? x2 : i2 > i3 ? i3 : i2;
    }
}