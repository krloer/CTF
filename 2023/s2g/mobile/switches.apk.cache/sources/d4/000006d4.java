package kotlin;

import kotlin.jvm.functions.Function0;
import s2g.project.game.BuildConfig;

/* compiled from: AssertionsJVM.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000\u0018\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\u001a\u0011\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u0003H\u0087\b\u001a\u001f\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u00032\f\u0010\u0004\u001a\b\u0012\u0004\u0012\u00020\u00060\u0005H\u0087\b¨\u0006\u0007"}, d2 = {"assert", BuildConfig.FLAVOR, "value", BuildConfig.FLAVOR, "lazyMessage", "Lkotlin/Function0;", BuildConfig.FLAVOR, "kotlin-stdlib"}, k = 5, mv = {1, 1, 15}, xi = 1, xs = "kotlin/PreconditionsKt")
/* loaded from: classes.dex */
class PreconditionsKt__AssertionsJVMKt {
    /* renamed from: assert  reason: not valid java name */
    private static final void m0assert(boolean value) {
        if (_Assertions.ENABLED && !value) {
            throw new AssertionError("Assertion failed");
        }
    }

    /* renamed from: assert  reason: not valid java name */
    private static final void m1assert(boolean value, Function0<? extends Object> function0) {
        if (_Assertions.ENABLED && !value) {
            Object message = function0.invoke();
            throw new AssertionError(message);
        }
    }
}