package a1;

import android.animation.ValueAnimator;
import com.google.android.material.bottomsheet.BottomSheetBehavior;
import com.google.android.material.textfield.TextInputLayout;
import l1.f;
import l1.g;
import n1.l;

/* loaded from: classes.dex */
public final class a implements ValueAnimator.AnimatorUpdateListener {

    /* renamed from: a  reason: collision with root package name */
    public final /* synthetic */ int f5a;

    /* renamed from: b  reason: collision with root package name */
    public final /* synthetic */ Object f6b;

    public /* synthetic */ a(int i2, Object obj) {
        this.f5a = i2;
        this.f6b = obj;
    }

    @Override // android.animation.ValueAnimator.AnimatorUpdateListener
    public final void onAnimationUpdate(ValueAnimator valueAnimator) {
        int i2 = this.f5a;
        Object obj = this.f6b;
        switch (i2) {
            case 0:
                float floatValue = ((Float) valueAnimator.getAnimatedValue()).floatValue();
                g gVar = ((BottomSheetBehavior) obj).f1244i;
                if (gVar != null) {
                    f fVar = gVar.f2283a;
                    if (fVar.f2271j != floatValue) {
                        fVar.f2271j = floatValue;
                        gVar.f2287e = true;
                        gVar.invalidateSelf();
                        return;
                    }
                    return;
                }
                return;
            case 1:
                ((l) obj).f2591c.setAlpha(((Float) valueAnimator.getAnimatedValue()).floatValue());
                return;
            default:
                ((TextInputLayout) obj).H0.j(((Float) valueAnimator.getAnimatedValue()).floatValue());
                return;
        }
    }
}