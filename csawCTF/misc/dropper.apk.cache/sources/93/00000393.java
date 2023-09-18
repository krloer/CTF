package x0;

import android.animation.Animator;
import android.animation.AnimatorInflater;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.animation.TimeInterpolator;
import android.content.Context;
import android.util.Log;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.view.animation.AccelerateInterpolator;
import android.view.animation.DecelerateInterpolator;
import j.j;
import java.util.ArrayList;

/* loaded from: classes.dex */
public final class b {

    /* renamed from: a  reason: collision with root package name */
    public final j f3316a = new j();

    /* renamed from: b  reason: collision with root package name */
    public final j f3317b = new j();

    public static b a(Context context, int i2) {
        try {
            Animator loadAnimator = AnimatorInflater.loadAnimator(context, i2);
            if (loadAnimator instanceof AnimatorSet) {
                return b(((AnimatorSet) loadAnimator).getChildAnimations());
            }
            if (loadAnimator != null) {
                ArrayList arrayList = new ArrayList();
                arrayList.add(loadAnimator);
                return b(arrayList);
            }
            return null;
        } catch (Exception e2) {
            Log.w("MotionSpec", "Can't load animation resource ID #0x" + Integer.toHexString(i2), e2);
            return null;
        }
    }

    public static b b(ArrayList arrayList) {
        b bVar = new b();
        int size = arrayList.size();
        for (int i2 = 0; i2 < size; i2++) {
            Animator animator = (Animator) arrayList.get(i2);
            if (!(animator instanceof ObjectAnimator)) {
                throw new IllegalArgumentException("Animator must be an ObjectAnimator: " + animator);
            }
            ObjectAnimator objectAnimator = (ObjectAnimator) animator;
            bVar.f3317b.put(objectAnimator.getPropertyName(), objectAnimator.getValues());
            String propertyName = objectAnimator.getPropertyName();
            long startDelay = objectAnimator.getStartDelay();
            long duration = objectAnimator.getDuration();
            TimeInterpolator interpolator = objectAnimator.getInterpolator();
            if ((interpolator instanceof AccelerateDecelerateInterpolator) || interpolator == null) {
                interpolator = a.f3313b;
            } else if (interpolator instanceof AccelerateInterpolator) {
                interpolator = a.f3314c;
            } else if (interpolator instanceof DecelerateInterpolator) {
                interpolator = a.f3315d;
            }
            c cVar = new c(startDelay, duration, interpolator);
            cVar.f3321d = objectAnimator.getRepeatCount();
            cVar.f3322e = objectAnimator.getRepeatMode();
            bVar.f3316a.put(propertyName, cVar);
        }
        return bVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof b) {
            return this.f3316a.equals(((b) obj).f3316a);
        }
        return false;
    }

    public final int hashCode() {
        return this.f3316a.hashCode();
    }

    public final String toString() {
        return "\n" + b.class.getName() + '{' + Integer.toHexString(System.identityHashCode(this)) + " timings: " + this.f3316a + "}\n";
    }
}