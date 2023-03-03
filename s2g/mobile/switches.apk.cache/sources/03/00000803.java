package kotlin.coroutines.experimental.migration;

import kotlin.Metadata;
import kotlin.coroutines.ContinuationInterceptor;
import kotlin.coroutines.experimental.Continuation;
import kotlin.coroutines.experimental.CoroutineContext;
import kotlin.coroutines.experimental.EmptyCoroutineContext;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.functions.Function3;
import kotlin.jvm.internal.Intrinsics;
import s2g.project.game.BuildConfig;

/* compiled from: CoroutinesMigration.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000:\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u001a\u001e\u0010\u0000\u001a\b\u0012\u0004\u0012\u0002H\u00020\u0001\"\u0004\b\u0000\u0010\u0002*\b\u0012\u0004\u0012\u0002H\u00020\u0003H\u0007\u001a\f\u0010\u0004\u001a\u00020\u0005*\u00020\u0006H\u0007\u001a\f\u0010\u0007\u001a\u00020\b*\u00020\tH\u0007\u001a\u001e\u0010\n\u001a\b\u0012\u0004\u0012\u0002H\u00020\u0003\"\u0004\b\u0000\u0010\u0002*\b\u0012\u0004\u0012\u0002H\u00020\u0001H\u0007\u001a\f\u0010\u000b\u001a\u00020\u0006*\u00020\u0005H\u0007\u001a\f\u0010\f\u001a\u00020\t*\u00020\bH\u0007\u001a^\u0010\r\u001a\"\u0012\u0004\u0012\u0002H\u000f\u0012\u0004\u0012\u0002H\u0010\u0012\n\u0012\b\u0012\u0004\u0012\u0002H\u00110\u0003\u0012\u0006\u0012\u0004\u0018\u00010\u00120\u000e\"\u0004\b\u0000\u0010\u000f\"\u0004\b\u0001\u0010\u0010\"\u0004\b\u0002\u0010\u0011*\"\u0012\u0004\u0012\u0002H\u000f\u0012\u0004\u0012\u0002H\u0010\u0012\n\u0012\b\u0012\u0004\u0012\u0002H\u00110\u0001\u0012\u0006\u0012\u0004\u0018\u00010\u00120\u000eH\u0000\u001aL\u0010\r\u001a\u001c\u0012\u0004\u0012\u0002H\u000f\u0012\n\u0012\b\u0012\u0004\u0012\u0002H\u00110\u0003\u0012\u0006\u0012\u0004\u0018\u00010\u00120\u0013\"\u0004\b\u0000\u0010\u000f\"\u0004\b\u0001\u0010\u0011*\u001c\u0012\u0004\u0012\u0002H\u000f\u0012\n\u0012\b\u0012\u0004\u0012\u0002H\u00110\u0001\u0012\u0006\u0012\u0004\u0018\u00010\u00120\u0013H\u0000\u001a:\u0010\r\u001a\u0016\u0012\n\u0012\b\u0012\u0004\u0012\u0002H\u00110\u0003\u0012\u0006\u0012\u0004\u0018\u00010\u00120\u0014\"\u0004\b\u0000\u0010\u0011*\u0016\u0012\n\u0012\b\u0012\u0004\u0012\u0002H\u00110\u0001\u0012\u0006\u0012\u0004\u0018\u00010\u00120\u0014H\u0000¨\u0006\u0015"}, d2 = {"toContinuation", "Lkotlin/coroutines/Continuation;", "T", "Lkotlin/coroutines/experimental/Continuation;", "toContinuationInterceptor", "Lkotlin/coroutines/ContinuationInterceptor;", "Lkotlin/coroutines/experimental/ContinuationInterceptor;", "toCoroutineContext", "Lkotlin/coroutines/CoroutineContext;", "Lkotlin/coroutines/experimental/CoroutineContext;", "toExperimentalContinuation", "toExperimentalContinuationInterceptor", "toExperimentalCoroutineContext", "toExperimentalSuspendFunction", "Lkotlin/Function3;", "T1", "T2", "R", BuildConfig.FLAVOR, "Lkotlin/Function2;", "Lkotlin/Function1;", "kotlin-stdlib-coroutines"}, k = 2, mv = {1, 1, 15})
/* loaded from: classes.dex */
public final class CoroutinesMigrationKt {
    public static final <T> Continuation<T> toExperimentalContinuation(kotlin.coroutines.Continuation<? super T> toExperimentalContinuation) {
        Continuation<T> continuation;
        Intrinsics.checkParameterIsNotNull(toExperimentalContinuation, "$this$toExperimentalContinuation");
        ContinuationMigration continuationMigration = (ContinuationMigration) (!(toExperimentalContinuation instanceof ContinuationMigration) ? null : toExperimentalContinuation);
        return (continuationMigration == null || (continuation = continuationMigration.getContinuation()) == null) ? new ExperimentalContinuationMigration(toExperimentalContinuation) : continuation;
    }

    public static final <T> kotlin.coroutines.Continuation<T> toContinuation(Continuation<? super T> toContinuation) {
        kotlin.coroutines.Continuation<T> continuation;
        Intrinsics.checkParameterIsNotNull(toContinuation, "$this$toContinuation");
        ExperimentalContinuationMigration experimentalContinuationMigration = (ExperimentalContinuationMigration) (!(toContinuation instanceof ExperimentalContinuationMigration) ? null : toContinuation);
        return (experimentalContinuationMigration == null || (continuation = experimentalContinuationMigration.getContinuation()) == null) ? new ContinuationMigration(toContinuation) : continuation;
    }

    public static final CoroutineContext toExperimentalCoroutineContext(kotlin.coroutines.CoroutineContext toExperimentalCoroutineContext) {
        EmptyCoroutineContext original;
        Intrinsics.checkParameterIsNotNull(toExperimentalCoroutineContext, "$this$toExperimentalCoroutineContext");
        ContinuationInterceptor interceptor = (ContinuationInterceptor) toExperimentalCoroutineContext.get(ContinuationInterceptor.Key);
        ContextMigration migration = (ContextMigration) toExperimentalCoroutineContext.get(ContextMigration.Key);
        kotlin.coroutines.CoroutineContext remainder = toExperimentalCoroutineContext.minusKey(ContinuationInterceptor.Key).minusKey(ContextMigration.Key);
        if (migration == null || (original = migration.getContext()) == null) {
            original = EmptyCoroutineContext.INSTANCE;
        }
        CoroutineContext result = remainder == kotlin.coroutines.EmptyCoroutineContext.INSTANCE ? original : original.plus(new ExperimentalContextMigration(remainder));
        return interceptor == null ? result : result.plus(toExperimentalContinuationInterceptor(interceptor));
    }

    public static final kotlin.coroutines.CoroutineContext toCoroutineContext(CoroutineContext toCoroutineContext) {
        kotlin.coroutines.EmptyCoroutineContext original;
        Intrinsics.checkParameterIsNotNull(toCoroutineContext, "$this$toCoroutineContext");
        kotlin.coroutines.experimental.ContinuationInterceptor interceptor = (kotlin.coroutines.experimental.ContinuationInterceptor) toCoroutineContext.get(kotlin.coroutines.experimental.ContinuationInterceptor.Key);
        ExperimentalContextMigration migration = (ExperimentalContextMigration) toCoroutineContext.get(ExperimentalContextMigration.Key);
        CoroutineContext remainder = toCoroutineContext.minusKey(kotlin.coroutines.experimental.ContinuationInterceptor.Key).minusKey(ExperimentalContextMigration.Key);
        if (migration == null || (original = migration.getContext()) == null) {
            original = kotlin.coroutines.EmptyCoroutineContext.INSTANCE;
        }
        kotlin.coroutines.CoroutineContext result = remainder == EmptyCoroutineContext.INSTANCE ? original : original.plus(new ContextMigration(remainder));
        return interceptor == null ? result : result.plus(toContinuationInterceptor(interceptor));
    }

    public static final kotlin.coroutines.experimental.ContinuationInterceptor toExperimentalContinuationInterceptor(ContinuationInterceptor toExperimentalContinuationInterceptor) {
        kotlin.coroutines.experimental.ContinuationInterceptor interceptor;
        Intrinsics.checkParameterIsNotNull(toExperimentalContinuationInterceptor, "$this$toExperimentalContinuationInterceptor");
        ContinuationInterceptorMigration continuationInterceptorMigration = (ContinuationInterceptorMigration) (!(toExperimentalContinuationInterceptor instanceof ContinuationInterceptorMigration) ? null : toExperimentalContinuationInterceptor);
        return (continuationInterceptorMigration == null || (interceptor = continuationInterceptorMigration.getInterceptor()) == null) ? new ExperimentalContinuationInterceptorMigration(toExperimentalContinuationInterceptor) : interceptor;
    }

    public static final ContinuationInterceptor toContinuationInterceptor(kotlin.coroutines.experimental.ContinuationInterceptor toContinuationInterceptor) {
        ContinuationInterceptor interceptor;
        Intrinsics.checkParameterIsNotNull(toContinuationInterceptor, "$this$toContinuationInterceptor");
        ExperimentalContinuationInterceptorMigration experimentalContinuationInterceptorMigration = (ExperimentalContinuationInterceptorMigration) (!(toContinuationInterceptor instanceof ExperimentalContinuationInterceptorMigration) ? null : toContinuationInterceptor);
        return (experimentalContinuationInterceptorMigration == null || (interceptor = experimentalContinuationInterceptorMigration.getInterceptor()) == null) ? new ContinuationInterceptorMigration(toContinuationInterceptor) : interceptor;
    }

    public static final <R> Function1<Continuation<? super R>, Object> toExperimentalSuspendFunction(Function1<? super kotlin.coroutines.Continuation<? super R>, ? extends Object> toExperimentalSuspendFunction) {
        Intrinsics.checkParameterIsNotNull(toExperimentalSuspendFunction, "$this$toExperimentalSuspendFunction");
        return new ExperimentalSuspendFunction0Migration(toExperimentalSuspendFunction);
    }

    public static final <T1, R> Function2<T1, Continuation<? super R>, Object> toExperimentalSuspendFunction(Function2<? super T1, ? super kotlin.coroutines.Continuation<? super R>, ? extends Object> toExperimentalSuspendFunction) {
        Intrinsics.checkParameterIsNotNull(toExperimentalSuspendFunction, "$this$toExperimentalSuspendFunction");
        return new ExperimentalSuspendFunction1Migration(toExperimentalSuspendFunction);
    }

    public static final <T1, T2, R> Function3<T1, T2, Continuation<? super R>, Object> toExperimentalSuspendFunction(Function3<? super T1, ? super T2, ? super kotlin.coroutines.Continuation<? super R>, ? extends Object> toExperimentalSuspendFunction) {
        Intrinsics.checkParameterIsNotNull(toExperimentalSuspendFunction, "$this$toExperimentalSuspendFunction");
        return new ExperimentalSuspendFunction2Migration(toExperimentalSuspendFunction);
    }
}