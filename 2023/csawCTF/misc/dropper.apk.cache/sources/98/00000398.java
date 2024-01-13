package y0;

import android.view.MotionEvent;
import android.view.VelocityTracker;
import android.view.View;
import android.view.ViewConfiguration;
import androidx.coordinatorlayout.widget.CoordinatorLayout;

/* loaded from: classes.dex */
public abstract class b extends c {

    /* renamed from: c  reason: collision with root package name */
    public boolean f3327c;

    /* renamed from: d  reason: collision with root package name */
    public int f3328d;

    /* renamed from: e  reason: collision with root package name */
    public int f3329e;

    /* renamed from: f  reason: collision with root package name */
    public int f3330f;

    /* renamed from: g  reason: collision with root package name */
    public VelocityTracker f3331g;

    public b() {
        this.f3328d = -1;
        this.f3330f = -1;
    }

    @Override // r.a
    public final boolean f(CoordinatorLayout coordinatorLayout, View view, MotionEvent motionEvent) {
        int findPointerIndex;
        if (this.f3330f < 0) {
            this.f3330f = ViewConfiguration.get(coordinatorLayout.getContext()).getScaledTouchSlop();
        }
        if (motionEvent.getActionMasked() == 2 && this.f3327c) {
            int i2 = this.f3328d;
            if (i2 == -1 || (findPointerIndex = motionEvent.findPointerIndex(i2)) == -1) {
                return false;
            }
            int y2 = (int) motionEvent.getY(findPointerIndex);
            if (Math.abs(y2 - this.f3329e) > this.f3330f) {
                this.f3329e = y2;
                return true;
            }
        }
        if (motionEvent.getActionMasked() != 0) {
            VelocityTracker velocityTracker = this.f3331g;
            if (velocityTracker != null) {
                velocityTracker.addMovement(motionEvent);
            }
            return false;
        }
        this.f3328d = -1;
        motionEvent.getX();
        motionEvent.getY();
        androidx.activity.c.i(view);
        throw null;
    }

    /* JADX WARN: Removed duplicated region for block: B:28:0x0056  */
    @Override // r.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public final boolean q(android.view.View r7, android.view.MotionEvent r8) {
        /*
            r6 = this;
            int r0 = r8.getActionMasked()
            r1 = -1
            r2 = 0
            r3 = 1
            r4 = 0
            if (r0 == r3) goto L41
            r5 = 2
            if (r0 == r5) goto L2d
            r7 = 3
            if (r0 == r7) goto L45
            r7 = 6
            if (r0 == r7) goto L14
            goto L52
        L14:
            int r7 = r8.getActionIndex()
            if (r7 != 0) goto L1b
            goto L1c
        L1b:
            r3 = r4
        L1c:
            int r7 = r8.getPointerId(r3)
            r6.f3328d = r7
            float r7 = r8.getY(r3)
            r0 = 1056964608(0x3f000000, float:0.5)
            float r7 = r7 + r0
            int r7 = (int) r7
            r6.f3329e = r7
            goto L52
        L2d:
            int r0 = r6.f3328d
            int r0 = r8.findPointerIndex(r0)
            if (r0 != r1) goto L36
            return r4
        L36:
            float r8 = r8.getY(r0)
            int r8 = (int) r8
            r6.f3329e = r8
            androidx.activity.c.g(r7)
            throw r2
        L41:
            android.view.VelocityTracker r0 = r6.f3331g
            if (r0 != 0) goto L5c
        L45:
            r6.f3327c = r4
            r6.f3328d = r1
            android.view.VelocityTracker r7 = r6.f3331g
            if (r7 == 0) goto L52
            r7.recycle()
            r6.f3331g = r2
        L52:
            android.view.VelocityTracker r7 = r6.f3331g
            if (r7 == 0) goto L59
            r7.addMovement(r8)
        L59:
            boolean r6 = r6.f3327c
            return r6
        L5c:
            r0.addMovement(r8)
            android.view.VelocityTracker r8 = r6.f3331g
            r0 = 1000(0x3e8, float:1.401E-42)
            r8.computeCurrentVelocity(r0)
            android.view.VelocityTracker r8 = r6.f3331g
            int r6 = r6.f3328d
            r8.getYVelocity(r6)
            androidx.activity.c.g(r7)
            throw r2
        */
        throw new UnsupportedOperationException("Method not decompiled: y0.b.q(android.view.View, android.view.MotionEvent):boolean");
    }

    public b(int i2) {
        super(0);
        this.f3328d = -1;
        this.f3330f = -1;
    }
}