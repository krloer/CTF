package kotlin;

import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.InlineMarker;
import s2g.project.game.BuildConfig;

/* compiled from: Synchronized.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000\u0012\n\u0002\b\u0003\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\u001a7\u0010\u0000\u001a\u0002H\u0001\"\u0004\b\u0000\u0010\u00012\u0006\u0010\u0002\u001a\u00020\u00032\f\u0010\u0004\u001a\b\u0012\u0004\u0012\u0002H\u00010\u0005H\u0087\b\u0082\u0002\n\n\b\b\u0001\u0012\u0002\u0010\u0002 \u0001¢\u0006\u0002\u0010\u0006¨\u0006\u0007"}, d2 = {"synchronized", "R", "lock", BuildConfig.FLAVOR, "block", "Lkotlin/Function0;", "(Ljava/lang/Object;Lkotlin/jvm/functions/Function0;)Ljava/lang/Object;", "kotlin-stdlib"}, k = 5, mv = {1, 1, 15}, xi = 1, xs = "kotlin/StandardKt")
/* loaded from: classes.dex */
class StandardKt__SynchronizedKt extends StandardKt__StandardKt {
    /* renamed from: synchronized  reason: not valid java name */
    private static final <R> R m13synchronized(Object lock, Function0<? extends R> function0) {
        R invoke;
        synchronized (lock) {
            try {
                invoke = function0.invoke();
                InlineMarker.finallyStart(1);
            } catch (Throwable th) {
                InlineMarker.finallyStart(1);
                InlineMarker.finallyEnd(1);
                throw th;
            }
        }
        InlineMarker.finallyEnd(1);
        return invoke;
    }
}