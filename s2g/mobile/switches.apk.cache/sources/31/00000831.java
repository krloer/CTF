package kotlin.internal;

import java.lang.reflect.Method;
import java.util.regex.MatchResult;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.random.FallbackThreadLocalRandom;
import kotlin.random.Random;
import kotlin.text.MatchGroup;
import s2g.project.game.BuildConfig;

/* compiled from: PlatformImplementations.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u00004\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\u0003\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\b\u0010\u0018\u00002\u00020\u0001:\u0001\u0010B\u0005¢\u0006\u0002\u0010\u0002J\u0018\u0010\u0003\u001a\u00020\u00042\u0006\u0010\u0005\u001a\u00020\u00062\u0006\u0010\u0007\u001a\u00020\u0006H\u0016J\b\u0010\b\u001a\u00020\tH\u0016J\u001a\u0010\n\u001a\u0004\u0018\u00010\u000b2\u0006\u0010\f\u001a\u00020\r2\u0006\u0010\u000e\u001a\u00020\u000fH\u0016¨\u0006\u0011"}, d2 = {"Lkotlin/internal/PlatformImplementations;", BuildConfig.FLAVOR, "()V", "addSuppressed", BuildConfig.FLAVOR, "cause", BuildConfig.FLAVOR, "exception", "defaultPlatformRandom", "Lkotlin/random/Random;", "getMatchResultNamedGroup", "Lkotlin/text/MatchGroup;", "matchResult", "Ljava/util/regex/MatchResult;", "name", BuildConfig.FLAVOR, "ReflectAddSuppressedMethod", "kotlin-stdlib"}, k = 1, mv = {1, 1, 15})
/* loaded from: classes.dex */
public class PlatformImplementations {

    /* compiled from: PlatformImplementations.kt */
    @Metadata(bv = {1, 0, 3}, d1 = {"\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\bÂ\u0002\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002R\u0012\u0010\u0003\u001a\u0004\u0018\u00010\u00048\u0006X\u0087\u0004¢\u0006\u0002\n\u0000¨\u0006\u0005"}, d2 = {"Lkotlin/internal/PlatformImplementations$ReflectAddSuppressedMethod;", BuildConfig.FLAVOR, "()V", "method", "Ljava/lang/reflect/Method;", "kotlin-stdlib"}, k = 1, mv = {1, 1, 15})
    /* loaded from: classes.dex */
    private static final class ReflectAddSuppressedMethod {
        public static final ReflectAddSuppressedMethod INSTANCE = new ReflectAddSuppressedMethod();
        public static final Method method;

        /* JADX WARN: Removed duplicated region for block: B:12:0x0048 A[LOOP:0: B:3:0x0016->B:12:0x0048, LOOP_END] */
        /* JADX WARN: Removed duplicated region for block: B:16:0x004c A[EDGE_INSN: B:16:0x004c->B:14:0x004c ?: BREAK  , SYNTHETIC] */
        static {
            /*
                kotlin.internal.PlatformImplementations$ReflectAddSuppressedMethod r0 = new kotlin.internal.PlatformImplementations$ReflectAddSuppressedMethod
                r0.<init>()
                kotlin.internal.PlatformImplementations.ReflectAddSuppressedMethod.INSTANCE = r0
                java.lang.Class<java.lang.Throwable> r0 = java.lang.Throwable.class
                r1 = 0
                java.lang.reflect.Method[] r2 = r0.getMethods()
                java.lang.String r3 = "throwableClass.methods"
                kotlin.jvm.internal.Intrinsics.checkExpressionValueIsNotNull(r2, r3)
                int r3 = r2.length
                r4 = 0
                r5 = 0
            L16:
                if (r5 >= r3) goto L4b
                r6 = r2[r5]
                r7 = r6
                r8 = 0
                java.lang.String r9 = "it"
                kotlin.jvm.internal.Intrinsics.checkExpressionValueIsNotNull(r7, r9)
                java.lang.String r9 = r7.getName()
                java.lang.String r10 = "addSuppressed"
                boolean r9 = kotlin.jvm.internal.Intrinsics.areEqual(r9, r10)
                if (r9 == 0) goto L44
                java.lang.Class[] r9 = r7.getParameterTypes()
                java.lang.String r10 = "it.parameterTypes"
                kotlin.jvm.internal.Intrinsics.checkExpressionValueIsNotNull(r9, r10)
                java.lang.Object r9 = kotlin.collections.ArraysKt.singleOrNull(r9)
                java.lang.Class r9 = (java.lang.Class) r9
                boolean r9 = kotlin.jvm.internal.Intrinsics.areEqual(r9, r0)
                if (r9 == 0) goto L44
                r9 = 1
                goto L45
            L44:
                r9 = 0
            L45:
                if (r9 == 0) goto L48
                goto L4c
            L48:
                int r5 = r5 + 1
                goto L16
            L4b:
                r6 = 0
            L4c:
                kotlin.internal.PlatformImplementations.ReflectAddSuppressedMethod.method = r6
                return
            */
            throw new UnsupportedOperationException("Method not decompiled: kotlin.internal.PlatformImplementations.ReflectAddSuppressedMethod.<clinit>():void");
        }

        private ReflectAddSuppressedMethod() {
        }
    }

    public void addSuppressed(Throwable cause, Throwable exception) {
        Intrinsics.checkParameterIsNotNull(cause, "cause");
        Intrinsics.checkParameterIsNotNull(exception, "exception");
        Method method = ReflectAddSuppressedMethod.method;
        if (method != null) {
            method.invoke(cause, exception);
        }
    }

    public MatchGroup getMatchResultNamedGroup(MatchResult matchResult, String name) {
        Intrinsics.checkParameterIsNotNull(matchResult, "matchResult");
        Intrinsics.checkParameterIsNotNull(name, "name");
        throw new UnsupportedOperationException("Retrieving groups by name is not supported on this platform.");
    }

    public Random defaultPlatformRandom() {
        return new FallbackThreadLocalRandom();
    }
}