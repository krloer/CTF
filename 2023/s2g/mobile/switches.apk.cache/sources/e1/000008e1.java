package kotlin.math;

import kotlin.Metadata;
import s2g.project.game.BuildConfig;

/* compiled from: MathJVM.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0010\u0006\n\u0002\b\u0006\bÂ\u0002\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002R\u0010\u0010\u0003\u001a\u00020\u00048\u0000X\u0081\u0004¢\u0006\u0002\n\u0000R\u0010\u0010\u0005\u001a\u00020\u00048\u0000X\u0081\u0004¢\u0006\u0002\n\u0000R\u0010\u0010\u0006\u001a\u00020\u00048\u0000X\u0081\u0004¢\u0006\u0002\n\u0000R\u0010\u0010\u0007\u001a\u00020\u00048\u0000X\u0081\u0004¢\u0006\u0002\n\u0000R\u0010\u0010\b\u001a\u00020\u00048\u0000X\u0081\u0004¢\u0006\u0002\n\u0000R\u0010\u0010\t\u001a\u00020\u00048\u0000X\u0081\u0004¢\u0006\u0002\n\u0000¨\u0006\n"}, d2 = {"Lkotlin/math/Constants;", BuildConfig.FLAVOR, "()V", "LN2", BuildConfig.FLAVOR, "epsilon", "taylor_2_bound", "taylor_n_bound", "upper_taylor_2_bound", "upper_taylor_n_bound", "kotlin-stdlib"}, k = 1, mv = {1, 1, 15})
/* loaded from: classes.dex */
final class Constants {
    public static final Constants INSTANCE = new Constants();
    public static final double LN2 = Math.log(2.0d);
    public static final double epsilon = Math.ulp(1.0d);
    public static final double taylor_2_bound = Math.sqrt(epsilon);
    public static final double taylor_n_bound = Math.sqrt(taylor_2_bound);
    public static final double upper_taylor_2_bound;
    public static final double upper_taylor_n_bound;

    static {
        double d = 1;
        double d2 = taylor_2_bound;
        Double.isNaN(d);
        upper_taylor_2_bound = d / d2;
        double d3 = taylor_n_bound;
        Double.isNaN(d);
        upper_taylor_n_bound = d / d3;
    }

    private Constants() {
    }
}