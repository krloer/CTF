package kotlin.random;

import kotlin.Metadata;
import kotlin.internal.PlatformImplementationsKt;
import kotlin.jvm.internal.Intrinsics;
import s2g.project.game.BuildConfig;

/* compiled from: PlatformRandom.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000\u001e\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0006\n\u0000\n\u0002\u0010\b\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0002\u001a\t\u0010\u0000\u001a\u00020\u0001H\u0081\b\u001a\u0018\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u0005H\u0000\u001a\u0010\u0010\u0007\u001a\u00020\u00052\u0006\u0010\b\u001a\u00020\u0005H\u0000\u001a\f\u0010\t\u001a\u00020\n*\u00020\u0001H\u0007\u001a\f\u0010\u000b\u001a\u00020\u0001*\u00020\nH\u0007¨\u0006\f"}, d2 = {"defaultPlatformRandom", "Lkotlin/random/Random;", "doubleFromParts", BuildConfig.FLAVOR, "hi26", BuildConfig.FLAVOR, "low27", "fastLog2", "value", "asJavaRandom", "Ljava/util/Random;", "asKotlinRandom", "kotlin-stdlib"}, k = 2, mv = {1, 1, 15})
/* loaded from: classes.dex */
public final class PlatformRandomKt {
    public static final java.util.Random asJavaRandom(Random asJavaRandom) {
        java.util.Random impl;
        Intrinsics.checkParameterIsNotNull(asJavaRandom, "$this$asJavaRandom");
        AbstractPlatformRandom abstractPlatformRandom = (AbstractPlatformRandom) (!(asJavaRandom instanceof AbstractPlatformRandom) ? null : asJavaRandom);
        return (abstractPlatformRandom == null || (impl = abstractPlatformRandom.getImpl()) == null) ? new KotlinRandom(asJavaRandom) : impl;
    }

    public static final Random asKotlinRandom(java.util.Random asKotlinRandom) {
        Random impl;
        Intrinsics.checkParameterIsNotNull(asKotlinRandom, "$this$asKotlinRandom");
        KotlinRandom kotlinRandom = (KotlinRandom) (!(asKotlinRandom instanceof KotlinRandom) ? null : asKotlinRandom);
        return (kotlinRandom == null || (impl = kotlinRandom.getImpl()) == null) ? new PlatformRandom(asKotlinRandom) : impl;
    }

    private static final Random defaultPlatformRandom() {
        return PlatformImplementationsKt.IMPLEMENTATIONS.defaultPlatformRandom();
    }

    public static final int fastLog2(int value) {
        return 31 - Integer.numberOfLeadingZeros(value);
    }

    public static final double doubleFromParts(int hi26, int low27) {
        double d = (hi26 << 27) + low27;
        double d2 = 9007199254740992L;
        Double.isNaN(d);
        Double.isNaN(d2);
        return d / d2;
    }
}