package kotlin;

import kotlin.jvm.internal.DoubleCompanionObject;
import kotlin.jvm.internal.FloatCompanionObject;
import s2g.project.game.BuildConfig;

/* compiled from: Numbers.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000&\n\u0000\n\u0002\u0010\u0006\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\t\n\u0002\u0010\u0007\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0005\u001a\u0015\u0010\u0000\u001a\u00020\u0001*\u00020\u00022\u0006\u0010\u0003\u001a\u00020\u0004H\u0087\b\u001a\u0015\u0010\u0000\u001a\u00020\u0005*\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u0007H\u0087\b\u001a\r\u0010\b\u001a\u00020\t*\u00020\u0001H\u0087\b\u001a\r\u0010\b\u001a\u00020\t*\u00020\u0005H\u0087\b\u001a\r\u0010\n\u001a\u00020\t*\u00020\u0001H\u0087\b\u001a\r\u0010\n\u001a\u00020\t*\u00020\u0005H\u0087\b\u001a\r\u0010\u000b\u001a\u00020\t*\u00020\u0001H\u0087\b\u001a\r\u0010\u000b\u001a\u00020\t*\u00020\u0005H\u0087\b\u001a\r\u0010\f\u001a\u00020\u0004*\u00020\u0001H\u0087\b\u001a\r\u0010\f\u001a\u00020\u0007*\u00020\u0005H\u0087\b\u001a\r\u0010\r\u001a\u00020\u0004*\u00020\u0001H\u0087\b\u001a\r\u0010\r\u001a\u00020\u0007*\u00020\u0005H\u0087\b¨\u0006\u000e"}, d2 = {"fromBits", BuildConfig.FLAVOR, "Lkotlin/Double$Companion;", "bits", BuildConfig.FLAVOR, BuildConfig.FLAVOR, "Lkotlin/Float$Companion;", BuildConfig.FLAVOR, "isFinite", BuildConfig.FLAVOR, "isInfinite", "isNaN", "toBits", "toRawBits", "kotlin-stdlib"}, k = 5, mv = {1, 1, 15}, xi = 1, xs = "kotlin/MathKt")
/* loaded from: classes.dex */
class MathKt__NumbersKt extends MathKt__BigIntegersKt {
    private static final boolean isNaN(double $this$isNaN) {
        return Double.isNaN($this$isNaN);
    }

    private static final boolean isNaN(float $this$isNaN) {
        return Float.isNaN($this$isNaN);
    }

    private static final boolean isInfinite(double $this$isInfinite) {
        return Double.isInfinite($this$isInfinite);
    }

    private static final boolean isInfinite(float $this$isInfinite) {
        return Float.isInfinite($this$isInfinite);
    }

    private static final boolean isFinite(double $this$isFinite) {
        return (Double.isInfinite($this$isFinite) || Double.isNaN($this$isFinite)) ? false : true;
    }

    private static final boolean isFinite(float $this$isFinite) {
        return (Float.isInfinite($this$isFinite) || Float.isNaN($this$isFinite)) ? false : true;
    }

    private static final long toBits(double $this$toBits) {
        return Double.doubleToLongBits($this$toBits);
    }

    private static final long toRawBits(double $this$toRawBits) {
        return Double.doubleToRawLongBits($this$toRawBits);
    }

    private static final double fromBits(DoubleCompanionObject $this$fromBits, long bits) {
        return Double.longBitsToDouble(bits);
    }

    private static final int toBits(float $this$toBits) {
        return Float.floatToIntBits($this$toBits);
    }

    private static final int toRawBits(float $this$toRawBits) {
        return Float.floatToRawIntBits($this$toRawBits);
    }

    private static final float fromBits(FloatCompanionObject $this$fromBits, int bits) {
        return Float.intBitsToFloat(bits);
    }
}