package kotlin.system;

import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import s2g.project.game.BuildConfig;

/* compiled from: Timing.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000\u0014\n\u0000\n\u0002\u0010\t\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\u001a\u0017\u0010\u0000\u001a\u00020\u00012\f\u0010\u0002\u001a\b\u0012\u0004\u0012\u00020\u00040\u0003H\u0086\b\u001a\u0017\u0010\u0005\u001a\u00020\u00012\f\u0010\u0002\u001a\b\u0012\u0004\u0012\u00020\u00040\u0003H\u0086\b¨\u0006\u0006"}, d2 = {"measureNanoTime", BuildConfig.FLAVOR, "block", "Lkotlin/Function0;", BuildConfig.FLAVOR, "measureTimeMillis", "kotlin-stdlib"}, k = 2, mv = {1, 1, 15})
/* loaded from: classes.dex */
public final class TimingKt {
    public static final long measureTimeMillis(Function0<Unit> block) {
        Intrinsics.checkParameterIsNotNull(block, "block");
        long start = System.currentTimeMillis();
        block.invoke();
        return System.currentTimeMillis() - start;
    }

    public static final long measureNanoTime(Function0<Unit> block) {
        Intrinsics.checkParameterIsNotNull(block, "block");
        long start = System.nanoTime();
        block.invoke();
        return System.nanoTime() - start;
    }
}